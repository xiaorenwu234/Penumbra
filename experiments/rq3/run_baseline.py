#!/usr/bin/env python3
"""RQ3 Baseline Experiment Runner — selectable isolation engine.

Runs the SAME workloads as run_all.py (shared definitions in workloads.py)
against a vanilla isolation stack, so Penumbra's speculative-execution
overhead can be compared against what a plain single-mechanism design
would cost. Three engines are available:

  --engine try   (default, primary baseline)
      OSDI'26 `try`: run the epoch's command in a per-epoch overlay sandbox
      (per top-level dir, inside a user namespace); commit applies the
      sandbox upperdir onto the live tree, rollback just drops the sandbox.
      File-state isolation  overlay sandbox (try's native flow)
      Process-state         none (try's scope is file effects only)

  --engine hs    (speculative shell-execution system baseline)
      binpash/hs (dynamic-parallelizer): the epoch's command runs through
      hs's executor path — fd_util + a try sandbox (hs's vendored try
      branch) + strace tracing — and commits via hs's own commit entry
      point (try -i /run/mount commit, copy semantics).
      File-state isolation  try sandbox (hs's vendored branch, -i/-L)
      Process-state         none (hs is file-effect speculation only)

  --engine criu  (fallback baseline, kept as a safety net)
      overlayfs + CRIU: upperdir scratch + CRIU dump at begin_epoch /
      restore at rollback.
      File-state isolation  overlayfs (single lower/upper pair)
      Process-state         CRIU checkpoint/restore of the session process

Epoch phase mapping (timed identically to the Penumbra harness):
  begin_epoch  -> try: fresh sandbox dir | hs: epoch dirs + env snapshot |
                  criu: criu dump --leave-running
  session_run  -> command (bash -c, taskset-pinned) in the isolated view
  commit       -> try: `try commit <sandbox>` | hs: hs commit_workspace |
                  criu: promote upper->lower
  rollback     -> try: drop the sandbox | hs: delete sandbox upperdirs |
                  criu: criu restore + discard

Results are written to engine-specific files so the baselines never
clobber each other: results/rq3_baseline_try.json,
results/rq3_baseline_hs.json and results/rq3_baseline_criu.json.

Usage:
    sudo SHADOW_RUN_RQ3_EXPERIMENTS=1 python3 run_baseline.py [options]

Options:
    --engine E         try (default), hs, or criu / overlayfs+criu
    --output-dir DIR   Output directory (default: ./results)
    --workload W       Run only workload W (1-10) or "all" (default: all)
    --root DIR         Engine root (default: /tmp/shadow-rq3-try for try,
                       /tmp/shadow-rq3-hs for hs,
                       /tmp/shadow-rq3-baseline for criu)
    --skip-build       Skip benchmark compilation
    --quick            Use reduced repeat counts for quick testing

Prerequisites:
    - Root privileges for the full runs (mount/umount; criu mode needs it
      unconditionally). Set RQ3_ALLOW_NONROOT=1 to bypass for functional
      testing — the try/hs engines themselves work unprivileged (user
      namespaces).
    - try mode: `try` built via third_party/build_try.sh (a plain script;
      C tools compiled with gcc). Honors $TRY_BIN / $TRY_SRC.
    - hs mode: the hs tree (default <RQ2>/hs, override $HS_ROOT) with its
      deps/try submodule initialized and fd_util/try-utils compiled —
      set it up with third_party/build_hs.sh.
    - criu mode: criu built via third_party/build_criu.sh (Ubuntu 24.04
      noble has no criu apt package; the engine also honors $CRIU_BIN)
    - NO Penumbra daemons needed — these baselines are fully standalone.
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
from framework.try_engine import (
    TryEngine, find_try_binary, find_try_utils_dir, smoke_test as try_smoke_test,
)
from framework.hs_engine import (
    HsEngine, find_hs_root, smoke_test as hs_smoke_test,
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
# Functional-testing escape hatch: the try engine runs fine unprivileged
# (user namespaces); the CRIU engine genuinely needs root (mount/criu).
ALLOW_NONROOT = os.environ.get("RQ3_ALLOW_NONROOT") == "1"
DEFAULT_ENGINE = "try"
ENGINE_ALIASES = {"overlayfs+criu": "criu", "overlayfs": "criu"}
ENGINE_DISPLAY = {"try": "try", "criu": "overlayfs+criu", "hs": "hs"}
DEFAULT_ROOTS = {"try": "/tmp/shadow-rq3-try",
                 "criu": "/tmp/shadow-rq3-baseline",
                 "hs": "/tmp/shadow-rq3-hs"}
# Engine-specific result files — never clobber another baseline's data.
RESULT_FILES = {"try": "rq3_baseline_try.json",
                "criu": "rq3_baseline_criu.json",
                "hs": "rq3_baseline_hs.json"}


def normalize_engine(name: str) -> str:
    """Map CLI spellings onto canonical engine names (try/hs/criu)."""
    return ENGINE_ALIASES.get(name.lower(), name.lower())


def engine_for(engine_name: str, root: str = None, verbose: bool = True):
    """Construct the selected baseline engine."""
    if engine_name == "try":
        return TryEngine(root or DEFAULT_ROOTS["try"], verbose=verbose)
    if engine_name == "hs":
        return HsEngine(root or DEFAULT_ROOTS["hs"], verbose=verbose)
    return OverlayCriuEngine(root or DEFAULT_ROOTS["criu"], verbose=verbose)


def check_prerequisites(engine_name: str):
    """Verify all prerequisites for the selected engine."""
    errors = []
    if os.geteuid() != 0 and not ALLOW_NONROOT:
        errors.append("Must run as root (mount/umount/criu require it); "
                      "set RQ3_ALLOW_NONROOT=1 to bypass for testing")
    if not RUN_EXPERIMENTS:
        errors.append("Set SHADOW_RUN_RQ3_EXPERIMENTS=1")
    if engine_name == "try":
        try_bin = find_try_binary()
        if try_bin is None:
            errors.append(
                "try not found (neither $TRY_BIN, <RQ2>/try-osdi26-ae, "
                "third_party/try-osdi26-ae nor $PATH) — build it with: "
                "bash experiments/rq3/third_party/build_try.sh")
        elif find_try_utils_dir(try_bin) is None:
            errors.append(
                f"try-commit/try-summary not found next to {try_bin} — "
                "try would use its slow shell commit path; rebuild with: "
                "bash experiments/rq3/third_party/build_try.sh")
    elif engine_name == "hs":
        hs_root = find_hs_root()
        if hs_root is None:
            errors.append(
                "hs not found (neither $HS_ROOT, <RQ2>/hs nor "
                "third_party/hs) — set it up with: "
                "bash experiments/rq3/third_party/build_hs.sh")
        else:
            for rel, hint in (
                    (("executor", "run_command.sh"),
                     "hs source tree incomplete"),
                    (("executor", "fd_util"),
                     f"build it: make -C {hs_root}/executor"),
                    (("jit_runtime", "pash_declare_vars.sh"),
                     "hs source tree incomplete"),
                    (("deps", "try", "try"),
                     "init the submodule: git -c http.sslVerify=false "
                     "submodule update --init deps/try"),
                    (("deps", "try", "utils", "try-commit"),
                     f"build it: make -C {hs_root}/deps/try/utils"),
            ):
                path = os.path.join(hs_root, *rel)
                if not os.path.isfile(path):
                    errors.append(f"{path} missing ({hint})")
    else:
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
            # Multi-command epochs: merge into ONE engine call when either
            # the workload asks for an epoch-level pin (pin_once) or the
            # engine declares per-call provisioning costs that must not be
            # multiplied per command (TryEngine.merge_epoch_commands — each
            # `try` call re-establishes its sandbox). One outer taskset
            # pins the whole merged script, matching the raw baseline's
            # single-wrapper pin.
            merge_call = (isinstance(spec.spec_command, list)
                          and (spec.pin_once
                               or getattr(engine, "merge_epoch_commands",
                                          False)))
            if commands and merge_call:
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
            params=dict(spec.params,
                        engine=getattr(self.engine, "engine_name",
                                       "overlayfs+criu"),
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
    CRIU-path mechanism (overlayfs mount, CRIU dump, run, commit promote,
    CRIU rollback restore) before any real measurement. Returns success.

    (CRIU-specific; the try engine ships its own smoke test in
    framework/try_engine.py.)"""
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


def merge_save_baseline(new_results, output_dir: str, engine_name: str):
    """Save baseline results, merging with an existing report of the SAME
    engine (same merge semantics as run_all.merge_save_results).

    Each engine writes its own file (rq3_baseline_try.json /
    rq3_baseline_criu.json) so the two baselines never clobber each
    other's data.
    """
    import json as _json
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, RESULT_FILES[engine_name])
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
        "experiment": f"rq3_baseline_{engine_name}",
        "engine": ENGINE_DISPLAY[engine_name],
        "timestamp": time.time(),
        "workloads": merged,
    }
    with open(path, "w") as f:
        _json.dump(data, f, indent=2, ensure_ascii=False)
    return path


def compare_with_penumbra(output_dir: str, engine_name: str):
    """If a Penumbra rq3.json report exists next to this engine's baseline
    report, print a side-by-side median comparison (spec totals)."""
    import json as _json
    rq3 = os.path.join(output_dir, "rq3.json")
    base = os.path.join(output_dir, RESULT_FILES[engine_name])
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
    print(f"  PENUMBRA vs {ENGINE_DISPLAY[engine_name].upper()} (median, ms)")
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
        description="RQ3 Baseline Experiment Runner "
                    "(engine: try [default] / hs / overlayfs+criu)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engine", default=DEFAULT_ENGINE,
                        help="Baseline engine: try (default, OSDI'26), "
                             "hs (binpash/hs executor path) or "
                             "criu / overlayfs+criu (fallback)")
    parser.add_argument("--output-dir", default="./results",
                        help="Output directory")
    parser.add_argument("--workload", default="all",
                        help="Workload number (1-10), comma list, or 'all'")
    parser.add_argument("--root", default=None,
                        help="Engine root directory (default: per-engine "
                             "under /tmp)")
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip benchmark compilation")
    parser.add_argument("--quick", action="store_true",
                        help="Use reduced repeat counts")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print configuration without running")
    parser.add_argument("--smoke", action="store_true",
                        help="Run a single end-to-end engine validation "
                             "(run/isolate/commit/rollback) and exit")
    args = parser.parse_args()

    engine_name = normalize_engine(args.engine)
    if engine_name not in RESULT_FILES:
        parser.error(f"unknown engine {args.engine!r} "
                     f"(expected: try, criu, overlayfs+criu)")
    root = args.root or DEFAULT_ROOTS[engine_name]

    if args.smoke:
        smoke_errors = []
        if engine_name == "try":
            # try runs unprivileged (user namespaces); the C tools are
            # required for a faithful commit path.
            try_bin = find_try_binary()
            if try_bin is None:
                smoke_errors.append("try binary not found")
            elif find_try_utils_dir(try_bin) is None:
                smoke_errors.append("try-commit/try-summary not found")
        elif engine_name == "hs":
            # hs runs unprivileged too; the executor path needs fd_util
            # compiled and the vendored try utils built.
            hs_root = find_hs_root()
            if hs_root is None:
                smoke_errors.append(
                    "hs not found (set HS_ROOT or place it at <RQ2>/hs)")
            else:
                for rel, hint in (
                        (("executor", "fd_util"),
                         "build it: make -C <hs>/executor"),
                        (("deps", "try", "utils", "try-commit"),
                         "build it: make -C <hs>/deps/try/utils"),
                ):
                    if not os.path.isfile(os.path.join(hs_root, *rel)):
                        smoke_errors.append(
                            f"missing {os.path.join(hs_root, *rel)} "
                            f"({hint})")
        else:
            if os.geteuid() != 0 and not ALLOW_NONROOT:
                smoke_errors.append("Must run as root (mount/umount/criu)")
            if find_criu_binary() is None:
                smoke_errors.append("criu binary not found")
        if smoke_errors:
            print("PREREQUISITE FAILURES:")
            for e in smoke_errors:
                print(f"  - {e}")
            sys.exit(1)
        if engine_name == "try":
            sys.exit(0 if try_smoke_test(root) else 1)
        if engine_name == "hs":
            sys.exit(0 if hs_smoke_test(root) else 1)
        sys.exit(0 if smoke_test(root) else 1)

    errors = check_prerequisites(engine_name)
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
        print(f"\n[DRY RUN] Would execute ({ENGINE_DISPLAY[engine_name]} "
              f"baseline):")
        for wl in wl_nums:
            repeats = repeats_map.get(wl, 100)
            print(f"  W{wl}: repeats={repeats}, warmup={WARMUP}")
        print(f"\n  Output: {args.output_dir} "
              f"({RESULT_FILES[engine_name]})")
        print(f"  Benchmarks: {BENCHMARKS_BIN}")
        print(f"  Engine root: {root}")
        sys.exit(0)

    engine = engine_for(engine_name, root, verbose=True)
    engine.setup()
    ensure_work_dirs(engine.lower)

    # Same workload definitions as run_all.py, against the engine's
    # (backing store, isolated-view) directory pair.
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
        path = merge_save_baseline(all_results, args.output_dir, engine_name)
        print(f"\n  Results saved to: {path}")
        WorkloadHarness.print_summary(all_results)
        compare_with_penumbra(args.output_dir, engine_name)

    print(f"\n[done] RQ3 baseline ({ENGINE_DISPLAY[engine_name]}) "
          f"experiments complete.")


if __name__ == "__main__":
    main()
