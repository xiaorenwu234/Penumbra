#!/usr/bin/env python3
"""Common experiment harness logic for RQ3 workloads.

Provides the WorkloadHarness class that handles:
  - Warm-up runs (excluded from results)
  - Raw (direct subprocess) measurement loops
  - Speculative (session epoch) measurement loops
  - Result collection and cleanup
  - JSON/text report generation
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .orch_client import OrchClient
from .stats import StatsResult, compute_stats
from .timing import Timer


# Default paths
BENCHMARKS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "benchmarks")
BENCHMARKS_BIN = os.path.join(BENCHMARKS_DIR, "bin")

# ShadowFS paths (same as RQ2)
SHADOWFS_MNT = os.environ.get("SHADOWFS_MNT", "/tmp/shadow-rq2-test/mnt")
SHADOWFS_ORIG = os.environ.get("SHADOWFS_ORIG", "/tmp/shadow-rq2-test/orig")

# CPU affinity: pin benchmark processes to a fixed CPU for reproducibility.
# Set to None to disable pinning.
CPU_PIN = int(os.environ.get("RQ3_CPU_PIN", "2")) if os.environ.get(
    "RQ3_CPU_PIN", "2") != "off" else None


class SpecCommandError(RuntimeError):
    """A speculative command failed: non-zero exit or output verification.

    Raised mid-epoch so the measurement is excluded (and the epoch rolled
    back) instead of being silently counted as a fast success.
    """


@dataclass
class EpochMeasurement:
    """One complete epoch measurement (begin + run + finalize)."""
    begin_ns: int = 0
    run_ns: int = 0
    finalize_ns: int = 0  # commit or rollback
    total_ns: int = 0
    success: bool = True
    error: str = ""
    finalize_mode: str = "commit"  # "commit" or "rollback"


@dataclass
class RawMeasurement:
    """One raw (direct subprocess) measurement."""
    elapsed_ns: int = 0
    success: bool = True
    error: str = ""
    returncode: int = 0


@dataclass
class WorkloadResult:
    """Complete result for one workload configuration."""
    workload_id: str
    config: str  # human-readable config description
    params: Dict[str, Any] = field(default_factory=dict)

    # Raw measurements
    raw_samples_ns: List[float] = field(default_factory=list)
    raw_excluded: int = 0

    # Spec measurements (broken down)
    spec_begin_ns: List[float] = field(default_factory=list)
    spec_run_ns: List[float] = field(default_factory=list)
    spec_commit_ns: List[float] = field(default_factory=list)
    spec_rollback_ns: List[float] = field(default_factory=list)
    spec_total_commit_ns: List[float] = field(default_factory=list)
    spec_total_rollback_ns: List[float] = field(default_factory=list)
    spec_excluded: int = 0
    # Why samples were excluded (SpecCommandError details), capped in to_dict
    spec_errors: List[str] = field(default_factory=list)

    # Metadata
    warmup_count: int = 0
    repeats: int = 0
    wall_time_s: float = 0.0

    def compute_all_stats(self) -> Dict[str, StatsResult]:
        """Compute statistics for all measurement categories."""
        stats = {}
        if self.raw_samples_ns:
            stats["raw_tool"] = compute_stats(
                "raw_tool", self.raw_samples_ns, self.raw_excluded)
        if self.spec_begin_ns:
            stats["spec_begin"] = compute_stats(
                "spec_begin", self.spec_begin_ns, self.spec_excluded)
        if self.spec_run_ns:
            stats["spec_run"] = compute_stats(
                "spec_run", self.spec_run_ns, self.spec_excluded)
        if self.spec_commit_ns:
            stats["spec_commit"] = compute_stats(
                "spec_commit", self.spec_commit_ns, self.spec_excluded)
        if self.spec_rollback_ns:
            stats["spec_rollback"] = compute_stats(
                "spec_rollback", self.spec_rollback_ns, self.spec_excluded)
        if self.spec_total_commit_ns:
            stats["spec_total_commit"] = compute_stats(
                "spec_total_commit", self.spec_total_commit_ns,
                self.spec_excluded)
        if self.spec_total_rollback_ns:
            stats["spec_total_rollback"] = compute_stats(
                "spec_total_rollback", self.spec_total_rollback_ns,
                self.spec_excluded)
        return stats

    def to_dict(self) -> dict:
        stats = self.compute_all_stats()
        return {
            "workload_id": self.workload_id,
            "config": self.config,
            "params": self.params,
            "warmup_count": self.warmup_count,
            "repeats": self.repeats,
            "wall_time_s": round(self.wall_time_s, 2),
            "raw_excluded": self.raw_excluded,
            "spec_excluded": self.spec_excluded,
            # Cap error details (they can be long); the first few are enough
            # to diagnose why samples were excluded.
            "spec_errors": [e[:300] for e in self.spec_errors[:10]],
            "stats": {k: v.to_dict() for k, v in stats.items()},
        }


class WorkloadHarness:
    """Common harness for running RQ3 workload measurements.

    Handles the measurement loop:
      1. Warm-up (N runs, discarded)
      2. Raw measurement (direct subprocess)
      3. Spec measurement (session epoch: begin → run → commit/rollback)
    """

    def __init__(self, orch_sock: str = None, warmup: int = 10,
                 verbose: bool = True):
        self.orch_sock = orch_sock
        self.warmup = warmup
        self.verbose = verbose
        self._client: Optional[OrchClient] = None

    def get_client(self) -> OrchClient:
        """Get or create the orchestrator client."""
        if self._client is None:
            self._client = OrchClient(self.orch_sock)
            self._client.connect()
        return self._client

    def close(self):
        """Close the orchestrator client."""
        if self._client:
            self._client.close()
            self._client = None

    def log(self, msg: str):
        if self.verbose:
            print(f"  [harness] {msg}", flush=True)

    # ─── Raw measurement ──────────────────────────────────────────────────

    def run_raw(self, cmd: List[str], timeout: float = 60.0,
                cwd: str = None) -> RawMeasurement:
        """Run a command directly (no speculative overhead) and time it."""
        try:
            # Build command with optional CPU pinning
            full_cmd = cmd
            if CPU_PIN is not None:
                full_cmd = ["taskset", "-c", str(CPU_PIN)] + cmd

            with Timer() as t:
                proc = subprocess.run(
                    full_cmd, capture_output=True, text=True,
                    timeout=timeout, cwd=cwd)
            return RawMeasurement(
                elapsed_ns=t.elapsed_ns,
                success=(proc.returncode == 0),
                returncode=proc.returncode,
                error=proc.stderr[:200] if proc.returncode != 0 else "",
            )
        except subprocess.TimeoutExpired:
            return RawMeasurement(success=False, error="timeout")
        except Exception as e:
            return RawMeasurement(success=False, error=str(e))

    def measure_raw(self, cmd: List[str], repeats: int,
                    timeout: float = 60.0, cwd: str = None,
                    setup_fn: Callable = None,
                    teardown_fn: Callable = None
                    ) -> Tuple[List[float], int]:
        """Run raw measurement loop. Returns (samples_ns, excluded_count).

        setup_fn/teardown_fn run around EACH invocation (warmup and measured)
        exactly as in the speculative loop, so the raw baseline exercises the
        same fresh-file state transitions instead of repeatedly re-using
        leftover state (e.g. O_TRUNC on an existing file vs. true creation).
        """
        samples = []
        excluded = 0
        # Warm-up
        for i in range(self.warmup):
            if setup_fn:
                setup_fn()
            m = self.run_raw(cmd, timeout, cwd)
            if teardown_fn:
                teardown_fn()
            if not m.success:
                excluded += 1
        # Measurement
        for i in range(repeats):
            if setup_fn:
                setup_fn()
            m = self.run_raw(cmd, timeout, cwd)
            if teardown_fn:
                teardown_fn()
            if m.success:
                samples.append(float(m.elapsed_ns))
            else:
                excluded += 1
            if self.verbose and (i + 1) % max(1, repeats // 5) == 0:
                self.log(f"  raw progress: {i+1}/{repeats}")
        return samples, excluded

    # ─── Speculative measurement ──────────────────────────────────────────

    def measure_spec_epoch(self, session_id: str, command: str,
                           finalize: str = "commit",
                           agent_id: str = "rq3-bench",
                           verify_fn: Callable = None,
                           pin_once: bool = False
                           ) -> EpochMeasurement:
        """Run one full epoch: begin → run → commit/rollback. Timed.

        `command` may be a single shell command or a LIST of commands run
        sequentially INSIDE the same epoch (one transcript entry each, e.g.
        W10-b's N tool invocations); run_ns is the sum of all commands.

        The run phase FAILS the measurement (and rolls back) when a command
        exits non-zero or `verify_fn` rejects its output — a failed run must
        never be silently counted as a fast success. verify_fn receives the
        command output and returns None on success or a reason string.
        """
        client = self.get_client()
        m = EpochMeasurement(finalize_mode=finalize)
        commands = [command] if isinstance(command, str) else list(command)
        try:
            # Begin epoch
            _, begin_ns = client.timed_begin_epoch(session_id, agent_id)
            m.begin_ns = begin_ns

            # Pin the candidate shell once for the whole epoch (multi-run
            # workloads, e.g. W10-b): affinity is inherited by every command
            # the shell spawns, so N runs pay one taskset-equivalent instead
            # of N× the ~1.3 ms taskset startup. The raw baseline pins once
            # via its single wrapper — this restores symmetry.
            if CPU_PIN is not None and pin_once:
                client.timed_pin_epoch_cpu(session_id, CPU_PIN)

            # Run command(s)
            total_run = 0
            for cmd in commands:
                # Pin the speculative command to the same CPU as raw runs so
                # the two baselines are comparable.
                if CPU_PIN is not None and not pin_once:
                    cmd = f"taskset -c {CPU_PIN} {cmd}"
                run_resp, run_ns = client.timed_run(session_id, cmd)
                total_run += run_ns
                rc = run_resp.get("exit_code", 0)
                if rc != 0:
                    raise SpecCommandError(
                        f"command exited {rc}: "
                        f"{run_resp.get('output', '')[:200]!r}")
                if verify_fn is not None:
                    reason = verify_fn(run_resp.get("output", ""))
                    if reason:
                        raise SpecCommandError(reason)
            m.run_ns = total_run

            # Finalize
            if finalize == "commit":
                _, fin_ns = client.timed_commit(session_id, agent_id)
            else:
                _, fin_ns = client.timed_rollback(session_id, agent_id)
            m.finalize_ns = fin_ns
            m.total_ns = begin_ns + total_run + fin_ns
            m.success = True
        except Exception as e:
            m.success = False
            m.error = str(e)
            # Try to recover: rollback if possible
            try:
                client.session_rollback_epoch(session_id, agent_id)
            except Exception:
                pass
        return m

    def measure_spec(self, command: str, repeats: int,
                     finalize: str = "commit",
                     agent_id: str = "rq3-bench",
                     setup_fn: Callable = None,
                     teardown_fn: Callable = None,
                     new_session_per_run: bool = False,
                     verify_fn: Callable = None,
                     error_sink: List[str] = None,
                     pin_once: bool = False
                     ) -> Tuple[Dict[str, List[float]], int]:
        """Run speculative measurement loop.

        Args:
            command: Shell command to run in the session.
            repeats: Number of measured iterations.
            finalize: "commit" or "rollback".
            setup_fn: Called before each epoch (e.g., create input files).
            teardown_fn: Called after each epoch (e.g., cleanup).
            new_session_per_run: If True, open/close session each iteration.
            error_sink: If given, excluded samples' reasons are appended
                (diagnostics: exit code, verify mismatch, commit failure).

        Returns:
            (dict of sample lists keyed by phase, excluded_count)
        """
        client = self.get_client()
        samples = {
            "begin": [], "run": [], "finalize": [], "total": [],
        }
        excluded = 0
        if error_sink is None:
            error_sink = []

        # Open session
        if not new_session_per_run:
            resp = client.session_open(agent_id)
            session_id = resp["session_id"]

        try:
            # Warm-up
            for i in range(self.warmup):
                if new_session_per_run:
                    resp = client.session_open(agent_id)
                    sid = resp["session_id"]
                else:
                    sid = session_id
                if setup_fn:
                    setup_fn()
                m = self.measure_spec_epoch(sid, command, finalize, agent_id,
                                             verify_fn, pin_once)
                if not m.success:
                    # Warm-up failures also matter for diagnostics: they
                    # reveal whether the failure is systematic or starts
                    # later (e.g. only once the session has been reused).
                    error_sink.append(f"[warmup] {m.error}")
                if teardown_fn:
                    teardown_fn()
                if new_session_per_run:
                    try:
                        client.session_close(sid)
                    except Exception:
                        pass

            # Measurement
            for i in range(repeats):
                if new_session_per_run:
                    resp = client.session_open(agent_id)
                    sid = resp["session_id"]
                else:
                    sid = session_id
                if setup_fn:
                    setup_fn()
                m = self.measure_spec_epoch(sid, command, finalize, agent_id,
                                             verify_fn, pin_once)
                if teardown_fn:
                    teardown_fn()
                if new_session_per_run:
                    try:
                        client.session_close(sid)
                    except Exception:
                        pass

                if m.success:
                    samples["begin"].append(float(m.begin_ns))
                    samples["run"].append(float(m.run_ns))
                    samples["finalize"].append(float(m.finalize_ns))
                    samples["total"].append(float(m.total_ns))
                else:
                    excluded += 1
                    error_sink.append(m.error)
                    if self.verbose and m.error:
                        self.log(f"    [EXCLUDED] {m.error}")

                if self.verbose and (i + 1) % max(1, repeats // 5) == 0:
                    self.log(f"  spec({finalize}) progress: {i+1}/{repeats}")
        finally:
            if not new_session_per_run:
                try:
                    client.session_close(session_id)
                except Exception:
                    pass

        return samples, excluded

    # ─── Combined measurement ─────────────────────────────────────────────

    def run_workload(self, workload_id: str, config: str,
                     raw_cmd: Optional[List[str]], spec_command: str,
                     repeats: int, params: Dict = None,
                     finalize_modes: List[str] = None,
                     setup_fn: Callable = None,
                     teardown_fn: Callable = None,
                     raw_timeout: float = 60.0,
                     new_session_per_run: bool = False,
                     verify_fn: Callable = None,
                     pin_once: bool = False
                     ) -> WorkloadResult:
        """Run a complete workload measurement (raw + spec commit + rollback).

        This is the main entry point for workload scripts.

        verify_fn, if given, rejects speculative samples whose command output
        does not match the expected benchmark report (e.g. "created=N"), so
        silently-failed runs never pollute the samples.
        """
        if finalize_modes is None:
            finalize_modes = ["commit", "rollback"]

        result = WorkloadResult(
            workload_id=workload_id,
            config=config,
            params=params or {},
            warmup_count=self.warmup,
            repeats=repeats,
        )

        t0 = time.time()
        self.log(f"Starting {workload_id} [{config}] repeats={repeats}")

        # Raw measurement
        if raw_cmd:
            self.log(f"  Measuring raw execution ...")
            raw_samples, raw_excl = self.measure_raw(
                raw_cmd, repeats, raw_timeout, setup_fn=setup_fn,
                teardown_fn=teardown_fn)
            result.raw_samples_ns = raw_samples
            result.raw_excluded = raw_excl

        # Spec measurements
        for mode in finalize_modes:
            self.log(f"  Measuring spec ({mode}) ...")
            spec_samples, spec_excl = self.measure_spec(
                spec_command, repeats, finalize=mode,
                setup_fn=setup_fn, teardown_fn=teardown_fn,
                new_session_per_run=new_session_per_run,
                verify_fn=verify_fn,
                error_sink=result.spec_errors,
                pin_once=pin_once)
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

    # ─── Reporting ────────────────────────────────────────────────────────

    @staticmethod
    def save_results(results: List[WorkloadResult], output_dir: str,
                     experiment_name: str = "rq3"):
        """Save all results to JSON and print summary."""
        os.makedirs(output_dir, exist_ok=True)

        # JSON report
        data = {
            "experiment": experiment_name,
            "timestamp": time.time(),
            "workloads": [r.to_dict() for r in results],
        }
        json_path = os.path.join(output_dir, f"{experiment_name}.json")
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Text summary
        txt_path = os.path.join(output_dir, f"{experiment_name}.txt")
        with open(txt_path, "w") as f:
            f.write(f"{'='*78}\n")
            f.write(f"  RQ3 PERFORMANCE RESULTS\n")
            f.write(f"{'='*78}\n\n")
            for r in results:
                f.write(f"  {r.workload_id} [{r.config}]\n")
                f.write(f"  {'-'*60}\n")
                stats = r.compute_all_stats()
                for name, s in stats.items():
                    f.write(f"    {s.summary_line()}\n")
                f.write(f"\n")
            f.write(f"{'='*78}\n")

        print(f"\n  Results saved to: {json_path}")
        print(f"  Summary saved to: {txt_path}")
        return json_path, txt_path

    @staticmethod
    def print_summary(results: List[WorkloadResult]):
        """Print a concise summary table to stdout."""
        print(f"\n{'='*78}")
        print(f"  RQ3 PERFORMANCE SUMMARY")
        print(f"{'='*78}\n")
        print(f"  {'Workload':<30} {'Metric':<20} {'Median(ms)':>12} "
              f"{'P95(ms)':>10} {'P99(ms)':>10}")
        print(f"  {'-'*30} {'-'*20} {'-'*12} {'-'*10} {'-'*10}")
        for r in results:
            stats = r.compute_all_stats()
            for name, s in stats.items():
                label = f"{r.workload_id}:{r.config}"
                print(f"  {label:<30} {name:<20} {s.median_ms:>12.3f} "
                      f"{s.p95_ms:>10.3f} {s.p99_ms:>10.3f}")
        print(f"\n{'='*78}\n")
