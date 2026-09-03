#!/usr/bin/env python3
"""RQ3 Baseline Experiment Runner — overlayfs + CRIU checkpoint/restore.

Runs the SAME workloads as run_all.py (shared definitions in workloads.py)
against a vanilla isolation stack, so Penumbra's speculative-execution
overhead can be compared against what a plain overlayfs + CRIU design
would cost:

  File-state isolation     overlayfs (upperdir = speculative scratch,
                            lowerdir = committed state)
  Process-state snapshot   CRIU dump at begin_epoch / restore at rollback

Epoch phase mapping (timed identically to the Penumbra harness):
  begin_epoch  → criu dump --leave-running
  session_run  → command (bash -c, taskset-pinned) in the merged view
  commit       → promote upperdir→lowerdir (whiteouts honored) + reset
  rollback     → criu restore + discard upperdir + reset

Usage:
    sudo SHADOW_RUN_RQ3_EXPERIMENTS=1 python3 run_baseline.py [options]

Options:
    --output-dir DIR   Output directory (default: ./results)
    --workload W       Run only workload W (1-10) or "all" (default: all)
    --root DIR         Engine root (default: /tmp/shadow-rq3-baseline)
    --skip-build       Skip benchmark compilation
    --quick            Use reduced repeat counts for quick testing

Prerequisites:
    - Root privileges (mount/umount/criu)
    - criu built via third_party/build_criu.sh (Ubuntu 24.04 noble has
      no criu apt package; the engine also honors $CRIU_BIN and $PATH)
    - NO Penumbra daemons needed — this baseline is fully standalone.
"""

import argparse
import os
import subprocess
import sys
import time

# Add framework to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from framework import WorkloadHarness
from framework.baseline_engine import (
    OverlayCriuEngine, BaselineEngineError, build_run_command,
    find_criu_binary,
)
from framework.harness import (
    WorkloadResult, BENCHMARKS_BIN, CPU_PIN,
)
from workloads import (
    build_workloads, ensure_work_dirs, cleanup_work_dir,
    DEFAULT_REPEATS, QUICK_REPEATS, WARMUP,
)

EXPERIMENTS_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ3_EXPERIMENTS") == "1"
DEFAULT_ENGINE_ROOT = "/tmp/shadow-rq3-baseline"


def check_prerequisites():
    """Verify all prerequisites are met."""
    errors = []
    if os.geteuid() != 0:
        errors.append("Must run as root (mount/umount/criu require it)")
    if not RUN_EXPERIMENTS:
        errors.append("Set SHADOW_RUN_RQ3_EXPERIMENTS=1")
    criu = find_criu_binary()
    if criu is None:
        errors.append(
            "criu not found (neither third_party/ build nor $PATH) — "
            "build it with: sudo bash "
            "experiments/rq3/third_party/build_criu.sh "
            "(Ubuntu 24.04 noble has no criu package in apt)")
    if not os.path.isdir(BENCHMARKS_BIN):
        errors.append(f"Benchmark binaries not found: {BENCHMARKS_BIN}")
    return errors


def build_benchmarks():
    """Compile benchmark programs (same targets as run_all.py)."""
    print("[build] Compiling benchmarks ...")
    result = subprocess.run(
        ["make", "-C", os.path.join(EXPERIMENTS_DIR, "benchmarks"), "all"],
        capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[build] FAILED:\n{result.stderr}")
        return False
    print("[build] Done")
    return True


class BaselineHarness:
    """Measurement harness over OverlayCriuEngine, producing the same
    WorkloadResult structure (raw / spec_begin / spec_run / spec_commit /
    spec_rollback / totals) as the Penumbra WorkloadHarness."""

    def __init__(self, engine: OverlayCriuEngine, warmup: int = 10,
                 verbose: bool = True):
        self.engine = engine
        self.warmup = warmup
        self.verbose = verbose
        # Reuse WorkloadHarness ONLY for its raw measurement loop: it is a
        # pure-subprocess timer with identical taskset/Timer/setup-teardown
        # semantics and never touches the orchestrator client unless
        # get_client() is called (we never call it).
        self._raw = WorkloadHarness(warmup=warmup, verbose=verbose)

    def log(self, msg: str):
        if self.verbose:
            print(f"  [baseline-harness] {msg}", flush=True)

    # ─── one epoch: begin → run → finalize ────────────────────────────────

    def _measure_epoch(self, spec, finalize: str):
        """Run one full epoch. Returns (success, begin_ns, run_ns, fin_ns,
        total_ns, error)."""
        engine = self.engine
        begin_ns = run_ns = fin_ns = 0
        try:
            begin_ns = engine.timed_begin_epoch()

            commands = (spec.spec_command
                        if isinstance(spec.spec_command, list)
                        else [spec.spec_command])
            if commands and isinstance(spec.spec_command, list) and spec.pin_once:
                # One epoch-level pin (single outer taskset), like the
                # Penumbra pin_once path.
                argv = build_run_command(None, CPU_PIN,
                                         commands=commands, pin_once=True)
                rc, out, ns = engine.timed_run(argv)
                run_ns += ns
                self._check_run(spec, rc, out)
            else:
                for cmd in commands:
                    argv = build_run_command(cmd, CPU_PIN)
                    rc, out, ns = engine.timed_run(argv)
                    run_ns += ns
                    self._check_run(spec, rc, out)

            if finalize == "commit":
                fin_ns = engine.timed_commit()
            else:
                fin_ns = engine.timed_rollback()
            return (True, begin_ns, run_ns, fin_ns,
                    begin_ns + run_ns + fin_ns, "")
        except Exception as e:
            # Recover: drop the speculative layer so the next epoch is clean.
            engine.recover_failed_epoch()
            return (False, begin_ns, run_ns, fin_ns, 0, str(e))

    def _check_run(self, spec, rc: int, out: str):
        if rc != 0:
            raise BaselineEngineError(
                f"command exited {rc}: {out[:200]!r}")
        if spec.verify_fn is not None:
            reason = spec.verify_fn(out)
            if reason:
                raise BaselineEngineError(reason)

    # ─── measurement loops ────────────────────────────────────────────────

    def _measure_spec(self, spec, repeats: int, finalize: str,
                      error_sink: list):
        """Epoch loop with warmup. Returns (samples_dict, excluded)."""
        engine = self.engine
        samples = {"begin": [], "run": [], "finalize": [], "total": []}
        excluded = 0
        fresh_session = spec.new_session_per_run

        # W10: carry the resident-memory payload in the checkpointed sleeper
        # itself (the session process CRIU dumps). The Penumbra side parks
        # the same payload in its session bash — same process, same RSS,
        # different snapshot mechanism. Setting this per workload keeps the
        # engine reusable across specs.
        engine.sleeper_mem_bytes = (spec.session_mem_mb or 0) * 1024 * 1024

        if not fresh_session:
            engine.session_open()
        try:
            for i in range(self.warmup + repeats):
                measured = i >= self.warmup
                if fresh_session:
                    engine.session_open()
                try:
                    if spec.setup_fn:
                        spec.setup_fn()
                        # setup writes the lowerdir directly; re-export it
                        # through the merged view (untimed).
                        engine.refresh()
                    ok, b, r, f, tot, err = self._measure_epoch(spec, finalize)
                    if spec.teardown_fn:
                        spec.teardown_fn()
                    if not ok:
                        if measured:
                            excluded += 1
                        error_sink.append(
                            f"[{'warmup' if not measured else 'run'}] {err}")
                        if self.verbose and err:
                            self.log(f"    [EXCLUDED] {err}")
                    elif measured:
                        samples["begin"].append(float(b))
                        samples["run"].append(float(r))
                        samples["finalize"].append(float(f))
                        samples["total"].append(float(tot))
                finally:
                    if fresh_session:
                        engine.session_close()
                if self.verbose and measured and \
                        (i - self.warmup + 1) % max(1, repeats // 5) == 0:
                    self.log(f"  spec({finalize}) progress: "
                             f"{i - self.warmup + 1}/{repeats}")
        finally:
            if not fresh_session:
                engine.session_close()
        return samples, excluded

    # ─── workload entry point ─────────────────────────────────────────────

    def run_workload(self, spec, repeats: int) -> WorkloadResult:
        result = WorkloadResult(
            workload_id=spec.workload_id,
            config=spec.config,
            params=dict(spec.params, engine="overlayfs+criu",
                        engine_root=self.engine.root),
            warmup_count=self.warmup,
            repeats=repeats,
        )

        t0 = time.time()
        self.log(f"Starting {spec.workload_id} [{spec.config}] "
                 f"repeats={repeats}")

        # Raw measurement (identical loop to the Penumbra harness)
        if spec.raw_cmd:
            self.log("  Measuring raw execution ...")
            raw_samples, raw_excl = self._raw.measure_raw(
                spec.raw_cmd, repeats, setup_fn=spec.setup_fn,
                teardown_fn=spec.teardown_fn)
            result.raw_samples_ns = raw_samples
            result.raw_excluded = raw_excl

        for mode in spec.finalize_modes:
            self.log(f"  Measuring spec ({mode}) ...")
            spec_samples, spec_excl = self._measure_spec(
                spec, repeats, mode, result.spec_errors)
            result.spec_excluded = max(result.spec_excluded, spec_excl)
            if mode == "commit":
                result.spec_begin_ns = spec_samples["begin"]
                result.spec_run_ns = spec_samples["run"]
                result.spec_commit_ns = spec_samples["finalize"]
                result.spec_total_commit_ns = spec_samples["total"]
            else:
                result.spec_rollback_ns = spec_samples["finalize"]
                result.spec_total_rollback_ns = spec_samples["total"]

        result.wall_time_s = time.time() - t0
        self.log(f"  Done in {result.wall_time_s:.1f}s")
        return result


def smoke_test(root: str) -> bool:
    """One full engine cycle with hard verifications — validates every
    mechanism (overlayfs mount, CRIU dump, run, commit promote, CRIU
    rollback restore) before any real measurement. Returns success."""
    from framework.baseline_engine import SLEEPER_ARGV0

    print("=" * 62)
    print("  BASELINE ENGINE SMOKE TEST (overlayfs + CRIU)")
    print("=" * 62)
    ok = True
    engine = OverlayCriuEngine(root, verbose=True)
    engine.setup()

    def check(name, cond, detail=""):
        nonlocal ok
        status = "PASS" if cond else "FAIL"
        if not cond:
            ok = False
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))

    try:
        # ── 1. overlayfs mount + sleeper ──
        engine.session_open()
        check("overlayfs mounted", os.path.ismount(engine.mnt))
        check("sleeper alive",
              engine._sleeper_pid is not None and engine._sleeper_alive(),
              f"pid={engine._sleeper_pid}")

        # ── 2. begin_epoch (criu dump) ──
        try:
            ns = engine.timed_begin_epoch()
            check("criu dump", True, f"{ns/1e6:.1f} ms")
        except Exception as e:
            check("criu dump", False, str(e)[:200])
            return ok

        # ── 3. run in merged view ──
        rc, out, ns = engine.timed_run(
            ["bash", "-c", "echo smoke-run-ok"])
        check("run in merged view", rc == 0 and "smoke-run-ok" in out,
              f"rc={rc} {ns/1e6:.1f} ms")

        # ── 4. commit: merged-view file must land in lowerdir ──
        marker = os.path.join(engine.mnt, "commit-marker.txt")
        with open(marker, "w") as f:
            f.write("committed")
        ns = engine.timed_commit()
        check("commit promote", os.path.isfile(
            os.path.join(engine.lower, "commit-marker.txt")),
              f"{ns/1e6:.1f} ms")

        # ── 5. rollback: sleeper must be restored, spec files dropped ──
        engine.timed_begin_epoch()
        with open(os.path.join(engine.mnt, "spec-only.txt"), "w") as f:
            f.write("should disappear")
        pid_before = engine._sleeper_pid
        try:
            ns = engine.timed_rollback()
            check("criu restore", engine._sleeper_alive(),
                  f"pid {pid_before}→{engine._sleeper_pid}, {ns/1e6:.1f} ms")
        except Exception as e:
            check("criu restore", False, str(e)[:200])
            return ok
        check("rollback drops spec files",
              not os.path.exists(os.path.join(engine.mnt, "spec-only.txt")))
        check("commit survives rollback",
              os.path.isfile(os.path.join(engine.mnt, "commit-marker.txt")))

        # ── 6. whiteout semantics: unlink in epoch + commit ──
        engine.timed_begin_epoch()
        os.unlink(os.path.join(engine.mnt, "commit-marker.txt"))
        engine.timed_commit()
        check("commit propagates unlink",
              not os.path.exists(os.path.join(engine.mnt, "commit-marker.txt"))
              and not os.path.exists(
                  os.path.join(engine.lower, "commit-marker.txt")))
    finally:
        engine.teardown()

    print("=" * 62)
    print(f"  SMOKE TEST {'PASSED' if ok else 'FAILED'}")
    print("=" * 62)
    return ok


def merge_save_baseline(new_results, output_dir: str):
    """Save baseline results, merging with an existing report (same merge
    semantics as run_all.merge_save_results)."""
    import json as _json
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "rq3_baseline.json")
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
        "experiment": "rq3_baseline",
        "engine": "overlayfs+criu",
        "timestamp": time.time(),
        "workloads": merged,
    }
    with open(path, "w") as f:
        _json.dump(data, f, indent=2, ensure_ascii=False)
    return path


def compare_with_penumbra(output_dir: str):
    """If a Penumbra rq3.json report exists next to the baseline report,
    print a side-by-side median comparison (spec totals)."""
    import json as _json
    rq3 = os.path.join(output_dir, "rq3.json")
    base = os.path.join(output_dir, "rq3_baseline.json")
    if not (os.path.exists(rq3) and os.path.exists(base)):
        return

    def load_index(path):
        with open(path) as f:
            data = _json.load(f)
        return {(w["workload_id"], w["config"]): w
                for w in data.get("workloads", [])}

    pen = load_index(rq3)
    bas = load_index(base)
    keys = [k for k in bas if k in pen]
    if not keys:
        return

    print(f"\n{'='*78}")
    print(f"  PENUMBRA vs OVERLAYFS+CRIU (median, ms)")
    print(f"{'='*78}\n")
    print(f"  {'Workload':<34} {'raw':>9} {'pen-commit':>11} "
          f"{'base-commit':>12} {'pen-roll':>10} {'base-roll':>11}")
    print(f"  {'-'*34} {'-'*9} {'-'*11} {'-'*12} {'-'*10} {'-'*11}")
    for key in keys:
        p, b = pen[key], bas[key]
        ps, bs = p.get("stats", {}), b.get("stats", {})

        def med(stats, name):
            v = stats.get(name, {}).get("median_ms")
            return f"{v:9.3f}" if v is not None else f"{'—':>9}"

        label = f"{key[0]}:{key[1]}"[:34]
        print(f"  {label:<34} {med(bs, 'raw_tool')} "
              f"{med(ps, 'spec_total_commit')} {med(bs, 'spec_total_commit')} "
              f"{med(ps, 'spec_total_rollback')} "
              f"{med(bs, 'spec_total_rollback')}")
    print(f"\n{'='*78}\n")


def main():
    parser = argparse.ArgumentParser(
        description="RQ3 Baseline (overlayfs + CRIU) Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", default="./results",
                        help="Output directory")
    parser.add_argument("--workload", default="all",
                        help="Workload number (1-8,10), comma list, or 'all'")
    parser.add_argument("--root", default=DEFAULT_ENGINE_ROOT,
                        help="Engine root directory")
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip benchmark compilation")
    parser.add_argument("--quick", action="store_true",
                        help="Use reduced repeat counts")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print configuration without running")
    parser.add_argument("--smoke", action="store_true",
                        help="Run a single end-to-end engine validation "
                             "(mount/dump/run/commit/rollback) and exit")
    args = parser.parse_args()

    if args.smoke:
        smoke_errors = []
        if os.geteuid() != 0:
            smoke_errors.append("Must run as root (mount/umount/criu)")
        if find_criu_binary() is None:
            smoke_errors.append("criu binary not found")
        if smoke_errors:
            print("PREREQUISITE FAILURES:")
            for e in smoke_errors:
                print(f"  - {e}")
            sys.exit(1)
        sys.exit(0 if smoke_test(args.root) else 1)

    errors = check_prerequisites()
    if errors and not args.dry_run:
        print("PREREQUISITE FAILURES:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    if not args.skip_build and not args.dry_run:
        if not build_benchmarks():
            sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    if args.workload == "all":
        wl_nums = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    else:
        wl_nums = [int(x) for x in args.workload.split(",")]

    repeats_map = QUICK_REPEATS if args.quick else DEFAULT_REPEATS

    if args.dry_run:
        print("\n[DRY RUN] Would execute (overlayfs + CRIU baseline):")
        for wl in wl_nums:
            repeats = repeats_map.get(wl, 100)
            print(f"  W{wl}: repeats={repeats}, warmup={WARMUP}")
        print(f"\n  Output: {args.output_dir}")
        print(f"  Benchmarks: {BENCHMARKS_BIN}")
        print(f"  Engine root: {args.root}")
        sys.exit(0)

    engine = OverlayCriuEngine(args.root, verbose=True)
    engine.setup()
    ensure_work_dirs(engine.lower)

    # Same workload definitions as run_all.py, against the baseline's
    # (lowerdir, merged-view) directory pair.
    all_specs = build_workloads(engine.lower, engine.mnt)
    specs = [s for s in all_specs if s.wl_num in wl_nums]

    harness = BaselineHarness(engine, warmup=WARMUP)

    all_results = []
    try:
        for spec in specs:
            repeats = repeats_map.get(spec.wl_num, 100)
            print(f"\n{'#'*70}")
            print(f"  BASELINE WORKLOAD {spec.workload_id} [{spec.config}] "
                  f"(repeats={repeats})")
            print(f"{'#'*70}")
            try:
                r = harness.run_workload(spec, repeats)
                all_results.append(r)
            except KeyboardInterrupt:
                print(f"\n[runner] Interrupted during {spec.workload_id}")
                break
            except Exception as e:
                print(f"\n[runner] {spec.workload_id} failed: {e}")
                import traceback
                traceback.print_exc()
    finally:
        engine.teardown()

    if all_results:
        path = merge_save_baseline(all_results, args.output_dir)
        print(f"\n  Results saved to: {path}")
        WorkloadHarness.print_summary(all_results)
        compare_with_penumbra(args.output_dir)

    print("\n[done] RQ3 baseline (overlayfs + CRIU) experiments complete.")


if __name__ == "__main__":
    main()
