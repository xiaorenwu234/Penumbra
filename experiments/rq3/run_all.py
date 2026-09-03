#!/usr/bin/env python3
"""
RQ3 Experiment Runner — Performance overhead measurement for Penumbra.

Measures the overhead of speculative execution across 10 workload categories:
  W1:  No-op (fixed epoch management cost)
  W2:  CPU-only computation (process versioning overhead)
  W3:  Sequential file read (ShadowFS read path)
  W4:  New file creation (staging write, no copy-up)
  W5:  Modify existing file (copy-up cost)
  W6:  Repeated writes to same file (epoch-owned head reuse)
  W7:  Multi-file creation (finalization scaling)
  W8:  Rename operations (namespace versioning)
  W9:  Tool output (transcript management)
  W10: Session-resident memory (COW fork vs CRIU dump scaling)

(Numbering note: tool output was "W10" until the session-resident-memory
workload was added — it took the W10 slot and tool output moved to the
vacant W9. The new W10 is the retry of the old removed "W9 process-memory
COW" idea, fixed: that workload allocated its working set inside a
per-epoch child after begin_epoch, so the session process was never big;
the new one parks the payload in the session shell itself BEFORE
begin_epoch, on both engines.)

Usage:
    SHADOW_RUN_RQ3_EXPERIMENTS=1 python3 run_all.py [options]

Options:
    --output-dir DIR   Output directory (default: ./results)
    --workload W       Run only workload W (1-10) or "all" (default: all)
    --skip-build       Skip benchmark compilation
    --quick            Use reduced repeat counts for quick testing

The workload definitions live in workloads.py and are shared with the
overlayfs+CRIU baseline (run_baseline.py), which runs the SAME workloads
against a vanilla isolation mechanism for comparison.

Prerequisites:
    - Root privileges
    - Running orchestrator daemon (/tmp/shadow-orch.sock)
    - ShadowFS FUSE mounted at /tmp/shadow-rq2-test/mnt

Environment:
    SHADOW_RUN_RQ3_EXPERIMENTS=1  Required gate
    SHADOW_ORCH_SOCK              Orchestrator socket path
    SHADOWFS_MNT                  ShadowFS FUSE mount point
    SHADOWFS_ORIG                 ShadowFS backing store
"""

import argparse
import os
import subprocess
import sys
import time

# Add framework to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from framework import OrchClient, WorkloadHarness, compute_stats
from framework.harness import BENCHMARKS_BIN, SHADOWFS_MNT, SHADOWFS_ORIG
from workloads import (  # noqa: F401  (re-exported for tooling)
    build_workloads, ensure_work_dirs, cleanup_work_dir,
    DEFAULT_REPEATS, QUICK_REPEATS, WARMUP,
)

EXPERIMENTS_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ3_EXPERIMENTS") == "1"


def run_specs(harness: WorkloadHarness, specs: list, repeats_map: dict) -> list:
    """Run a list of WorkloadSpec (raw + speculative epochs), in order.

    Mirrors the per-workload error handling of the old run_wX() functions:
    KeyboardInterrupt aborts the remaining workloads, any other failure
    prints the traceback and moves on to the next workload.
    """
    all_results = []
    for spec in specs:
        repeats = repeats_map.get(spec.wl_num, 100)
        print(f"\n{'#'*70}")
        print(f"  WORKLOAD {spec.workload_id} [{spec.config}] "
              f"(repeats={repeats})")
        print(f"{'#'*70}")
        try:
            r = harness.run_workload(
                workload_id=spec.workload_id,
                config=spec.config,
                raw_cmd=spec.raw_cmd,
                spec_command=spec.spec_command,
                repeats=repeats,
                params=spec.params,
                finalize_modes=spec.finalize_modes,
                setup_fn=spec.setup_fn,
                teardown_fn=spec.teardown_fn,
                new_session_per_run=spec.new_session_per_run,
                verify_fn=spec.verify_fn,
                pin_once=spec.pin_once,
                session_mem_mb=spec.session_mem_mb,
            )
            all_results.append(r)
        except KeyboardInterrupt:
            print(f"\n[runner] Interrupted during {spec.workload_id}")
            break
        except Exception as e:
            print(f"\n[runner] {spec.workload_id} failed: {e}")
            import traceback
            traceback.print_exc()
    return all_results


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def check_prerequisites(skip_orch: bool = False):
    """Verify all prerequisites are met."""
    errors = []
    if os.geteuid() != 0:
        errors.append("Must run as root")
    if not RUN_EXPERIMENTS:
        errors.append("Set SHADOW_RUN_RQ3_EXPERIMENTS=1")
    if not skip_orch:
        orch_sock = os.environ.get("SHADOW_ORCH_SOCK", "/tmp/shadow-orch.sock")
        if not os.path.exists(orch_sock):
            errors.append(f"Orchestrator socket not found: {orch_sock}")
    if not os.path.isdir(BENCHMARKS_BIN):
        errors.append(f"Benchmark binaries not found: {BENCHMARKS_BIN}")
    return errors


def build_benchmarks():
    """Compile benchmark programs."""
    print("[build] Compiling benchmarks ...")
    result = subprocess.run(
        ["make", "-C", os.path.join(EXPERIMENTS_DIR, "benchmarks"), "all"],
        capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[build] FAILED:\n{result.stderr}")
        return False
    print("[build] Done")
    return True


def merge_save_results(new_results, output_dir: str, experiment_name: str = "rq3"):
    """Save results, merging with an existing JSON report instead of
    overwriting it wholesale.

    Runs can target a workload subset (e.g. only W10 to re-collect data
    after a fix); overwriting would silently drop the other workloads'
    measurements from the report. Entries are keyed by (workload_id,
    config): existing entries with the same key are replaced by the new
    measurements, all others are preserved.
    """
    import json as _json
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{experiment_name}.json")
    merged = [r.to_dict() for r in new_results]
    new_keys = {(r.workload_id, r.config) for r in new_results}
    if os.path.exists(path):
        try:
            with open(path) as f:
                old = _json.load(f)
            merged = ([w for w in old.get("workloads", [])
                       if (w.get("workload_id"), w.get("config"))
                       not in new_keys] + merged)
        except Exception:
            print(f"[save] existing {path} unreadable/corrupt -- overwriting")
    data = {
        "experiment": experiment_name,
        "timestamp": time.time(),
        "workloads": merged,
    }
    with open(path, "w") as f:
        _json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(
        description="RQ3 Performance Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", default="./results",
                        help="Output directory")
    parser.add_argument("--workload", default="all",
                        help="Workload number (1-10) or 'all'")
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip benchmark compilation")
    parser.add_argument("--quick", action="store_true",
                        help="Use reduced repeat counts")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print configuration without running")
    args = parser.parse_args()

    errors = check_prerequisites(skip_orch=args.dry_run)
    if errors:
        print("PREREQUISITE FAILURES:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    if not args.skip_build and not args.dry_run:
        if not build_benchmarks():
            sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    ensure_work_dirs(SHADOWFS_ORIG)

    # Determine workloads
    if args.workload == "all":
        wl_nums = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    else:
        # Comma-separated subset, e.g. "5,6,7,8,10"
        wl_nums = [int(x) for x in args.workload.split(",")]

    repeats_map = QUICK_REPEATS if args.quick else DEFAULT_REPEATS

    # Dry-run: just print what would be done
    if args.dry_run:
        print("\n[DRY RUN] Would execute:")
        for wl in wl_nums:
            repeats = repeats_map.get(wl, 100)
            print(f"  W{wl}: repeats={repeats}, warmup={WARMUP}")
        print(f"\n  Output: {args.output_dir}")
        print(f"  Benchmarks: {BENCHMARKS_BIN}")
        print(f"  FUSE mount: {SHADOWFS_MNT}")
        print(f"  Backing store: {SHADOWFS_ORIG}")
        sys.exit(0)

    harness = WorkloadHarness(warmup=WARMUP)

    # Build the shared workload specs against the ShadowFS directory pair —
    # the same definitions the overlayfs+CRIU baseline (run_baseline.py)
    # runs against its own (lowerdir, merged) pair.
    all_specs = build_workloads(SHADOWFS_ORIG, SHADOWFS_MNT)
    specs = [s for s in all_specs if s.wl_num in wl_nums]

    all_results = []
    try:
        all_results = run_specs(harness, specs, repeats_map)
    finally:
        harness.close()

    # Save and print results
    if all_results:
        merge_save_results(all_results, args.output_dir, "rq3")
        WorkloadHarness.print_summary(all_results)

    # Cleanup
    cleanup_work_dir(SHADOWFS_ORIG)
    print("\n[done] RQ3 experiments complete.")


if __name__ == "__main__":
    main()
