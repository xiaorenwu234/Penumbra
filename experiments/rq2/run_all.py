#!/usr/bin/env python3
"""
RQ2 Experiment Runner - Unified entry point for all five experiments.

Runs all experiments sequentially and produces a combined report suitable
for paper tables.

Usage:
    SHADOW_RUN_RQ2_EXPERIMENTS=1 python3 run_all.py [options]

Options:
    --repeats N       Repeats per test point for exp1-4 (default: 10)
    --trials N        Trials per fault for exp5 (default: 5000)
    --output-dir DIR  Output directory for reports (default: ./results)
    --exp N           Run only experiment N (1-5), or "all" (default: all)
    --skip-build      Skip probe compilation (assume already built)

Prerequisites:
    - Root privileges
    - Linux >= 5.15 with BPF LSM and cgroup v2
    - Running ShadowProc daemon (/tmp/shadow_proc.sock)
    - Running ShadowFS daemon (/tmp/shadowfs.sock)
    - Running ShadowObserve daemon (/tmp/shadow_observe.sock) [optional]
    - Compiled probe binaries (run 'make' in this directory)

Environment:
    SHADOW_RUN_RQ2_EXPERIMENTS=1    Required gate
    SHADOWPROC_SOCK                 ShadowProc socket path
    SHADOWFS_SOCK                   ShadowFS socket path
    SHADOWOBSERVE_SOCK              ShadowObserve socket path
    SHADOW_CGROUP_ROOT              Cgroup v2 root (default: /sys/fs/cgroup)
"""

import argparse
import json
import os
import subprocess
import sys
import time

EXPERIMENTS_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ2_EXPERIMENTS") == "1"


def check_prerequisites():
    """Verify all prerequisites are met."""
    errors = []

    if os.geteuid() != 0:
        errors.append("Must run as root (for BPF and cgroup operations)")

    if not RUN_EXPERIMENTS:
        errors.append("Set SHADOW_RUN_RQ2_EXPERIMENTS=1 to enable experiments")

    # Check sockets
    proc_sock = os.environ.get("SHADOWPROC_SOCK", "/tmp/shadow_proc.sock")
    if not os.path.exists(proc_sock):
        errors.append(f"ShadowProc socket not found: {proc_sock}")

    fs_sock = os.environ.get("SHADOWFS_SOCK", "/tmp/shadowfs.sock")
    if not os.path.exists(fs_sock):
        errors.append(f"ShadowFS socket not found: {fs_sock}")

    # Check cgroup v2
    cgroup_root = os.environ.get("SHADOW_CGROUP_ROOT", "/sys/fs/cgroup")
    if not os.path.isdir(cgroup_root):
        errors.append(f"Cgroup root not found: {cgroup_root}")
    elif not os.path.exists(os.path.join(cgroup_root, "cgroup.controllers")):
        errors.append(f"Not a cgroup v2 hierarchy: {cgroup_root}")

    # Check probes are built
    probes_bin = os.path.join(EXPERIMENTS_DIR, "probes", "bin")
    if not os.path.isdir(probes_bin):
        errors.append(f"Probe binaries not found: {probes_bin} (run 'make' first)")

    return errors


def build_probes():
    """Compile probe programs."""
    print("[build] Compiling probe programs ...")
    result = subprocess.run(
        ["make", "-C", os.path.join(EXPERIMENTS_DIR, "probes"), "-f",
         os.path.join(EXPERIMENTS_DIR, "Makefile"), "all"],
        capture_output=True, text=True, cwd=EXPERIMENTS_DIR)
    if result.returncode != 0:
        print(f"[build] WARNING: make returned {result.returncode}")
        if result.stderr:
            print(result.stderr[:500])
    else:
        print("[build] Done")
    return result.returncode == 0


def run_experiment(exp_num: int, repeats: int, trials: int,
                   output_dir: str) -> dict:
    """Run a single experiment and return its metrics dict."""
    print(f"\n{'#'*70}")
    print(f"  RUNNING EXPERIMENT {exp_num}")
    print(f"{'#'*70}\n")

    t0 = time.time()

    if exp_num == 1:
        from exp1_effect_coverage import Experiment1
        exp = Experiment1(repeats=repeats)
        metrics = exp.run()
    elif exp_num == 2:
        from exp2_audit_consistency import Experiment2
        exp = Experiment2(repeats=repeats)
        metrics = exp.run()
    elif exp_num == 3:
        from exp3_rollback_correctness import Experiment3
        exp = Experiment3(repeats=repeats)
        metrics = exp.run()
    elif exp_num == 4:
        from exp4_dependency_propagation import Experiment4
        exp = Experiment4(repeats=max(1, repeats // 2))
        metrics = exp.run()
    elif exp_num == 5:
        from exp5_failclosed_concurrency import Experiment5
        exp = Experiment5(trials=trials)
        metrics = exp.run()
    else:
        raise ValueError(f"Unknown experiment: {exp_num}")

    elapsed = time.time() - t0
    result = metrics.to_dict()
    result["wall_time_seconds"] = round(elapsed, 1)

    # Save individual report
    metrics.save_report(output_dir)
    return result


def print_combined_report(all_results: list, output_dir: str):
    """Print a combined summary suitable for paper inclusion."""
    print(f"\n\n{'='*70}")
    print(f"  RQ2 COMBINED RESULTS SUMMARY")
    print(f"{'='*70}\n")

    total_violations = 0
    total_trials = 0

    for result in all_results:
        exp_name = result.get("experiment", "unknown")
        duration = result.get("wall_time_seconds", 0)
        counters = result.get("counters", {})

        print(f"  {exp_name} ({duration}s):")
        for name, data in counters.items():
            count = data["count"]
            total = data["total"]
            ci = data.get("ci_95", [0, 0])
            total_violations += count
            total_trials += total
            status = "PASS" if count == 0 else "FAIL"
            print(f"    [{status}] {name}: {count}/{total} "
                  f"CI=[{ci[0]:.6f}, {ci[1]:.6f}]")
        print()

    print(f"  {'='*60}")
    print(f"  TOTAL: {total_violations} violations / {total_trials} trials")
    if total_violations == 0:
        print(f"  RESULT: ALL SAFETY PROPERTIES HELD ACROSS ALL EXPERIMENTS")
    else:
        print(f"  RESULT: VIOLATIONS DETECTED - SEE INDIVIDUAL REPORTS")
    print(f"  {'='*60}\n")

    # Save combined JSON (merge with existing results from prior --exp runs)
    combined_path = os.path.join(output_dir, "combined_results.json")
    # Canonical experiment names - only these 5 are valid
    CANONICAL_NAMES = {
        "exp1_effect_coverage",
        "exp2_audit_consistency",
        "exp3_rollback_correctness",
        "exp4_dependency_propagation",
        "exp5_failclosed_concurrency",
    }
    existing_experiments = {}
    if os.path.exists(combined_path):
        try:
            with open(combined_path, "r") as f:
                prev = json.load(f)
            for exp in prev.get("experiments", []):
                name = exp.get("experiment", "")
                # Only keep canonical names (discard stale/error entries)
                if name in CANONICAL_NAMES:
                    existing_experiments[name] = exp
        except (json.JSONDecodeError, KeyError):
            pass
    # Merge current results (overwrite same experiment name)
    for result in all_results:
        name = result.get("experiment", "")
        if name in CANONICAL_NAMES:
            existing_experiments[name] = result
    merged = list(existing_experiments.values())

    # Validate: experiments with no counters are errors, not passes
    has_error = False
    has_warning = False
    for r in merged:
        counters = r.get("counters", {})
        if not counters:
            print(f"  ERROR: {r.get('experiment')} has no counters (crashed?)")
            has_error = True
        # Warn on 0/0 counters (no effective observations)
        empty = r.get("empty_counters", [])
        if empty:
            print(f"  WARNING: {r.get('experiment')} has 0/0 counters: {empty}")
            has_warning = True
        skipped = r.get("skipped_trials", 0)
        if skipped > 0:
            print(f"  INFO: {r.get('experiment')} skipped {skipped} trials")

    # Recalculate totals (only from valid experiments with counters)
    total_v = sum(
        c["count"] for r in merged for c in r.get("counters", {}).values())
    total_t = sum(
        c["total"] for r in merged for c in r.get("counters", {}).values())

    with open(combined_path, "w") as f:
        json.dump({
            "experiments": merged,
            "total_violations": total_v,
            "total_trials": total_t,
            "has_error": has_error,
            "has_warning": has_warning,
            "experiments_present": sorted(existing_experiments.keys()),
            "experiments_missing": sorted(CANONICAL_NAMES - set(existing_experiments.keys())),
            "timestamp": time.time(),
        }, f, indent=2)
    print(f"  Combined results saved to: {combined_path}")
    if has_error:
        print(f"  ERROR: Some experiments have errors - results may be invalid")
    if has_warning:
        print(f"  WARNING: Some counters have 0 effective observations")


def main():
    parser = argparse.ArgumentParser(
        description="RQ2 Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument("--repeats", type=int, default=10,
                        help="Repeats per test point for exp1-4")
    parser.add_argument("--trials", type=int, default=5000,
                        help="Trials per fault for exp5")
    parser.add_argument("--output-dir", type=str, default="./results",
                        help="Output directory")
    parser.add_argument("--exp", type=str, default="all",
                        help="Run experiment N (1-5) or 'all'")
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip probe compilation")
    args = parser.parse_args()

    # Check prerequisites
    errors = check_prerequisites()
    if errors:
        print("PREREQUISITE FAILURES:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    # Build probes
    if not args.skip_build:
        build_probes()

    os.makedirs(args.output_dir, exist_ok=True)

    # Determine which experiments to run
    if args.exp == "all":
        exp_nums = [1, 2, 3, 4, 5]
    else:
        exp_nums = [int(args.exp)]

    # Run experiments
    all_results = []
    for num in exp_nums:
        try:
            result = run_experiment(num, args.repeats, args.trials,
                                    args.output_dir)
            all_results.append(result)
        except KeyboardInterrupt:
            print(f"\n[runner] Interrupted during experiment {num}")
            break
        except Exception as e:
            print(f"\n[runner] Experiment {num} failed: {e}")
            import traceback
            traceback.print_exc()
            all_results.append({
                "experiment": f"exp{num}",
                "error": str(e),
                "counters": {},
            })

    # Combined report
    if all_results:
        print_combined_report(all_results, args.output_dir)


if __name__ == "__main__":
    main()
