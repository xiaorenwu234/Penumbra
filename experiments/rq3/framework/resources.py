#!/usr/bin/env python3
"""Daemon CPU / RSS sampling for RQ3 scalability experiments.

The scaling questions ("does the orchestrator become the bottleneck?", "how
much memory does the dependency graph cost?") cannot be answered from client
latency alone: a system can look fast per invocation while burning a whole core
in its coordination daemon. This module measures the three daemons
(ShadowFS, ShadowProc, orchestrator) from /proc so an experiment can bracket a
phase and attribute CPU-seconds and resident memory to it.

What is measured
----------------
CPU   cumulative utime+stime of the daemon process, differenced across the
      phase and divided by the phase's wall time -> cpu_pct. A value above 100
      means the daemon used more than one core (Go/Rust threads), which is
      exactly the "coordination is not scaling" signal.
RSS   VmRSS at phase start, at phase end, and the maximum seen by a background
      poller. The poller matters: finalization allocates in bursts, so
      end-minus-start can read as zero growth for a phase that actually peaked
      hundreds of megabytes higher.

Honest limitation
-----------------
utime+stime is USERSPACE cpu of the daemon process plus its own syscalls. It
does NOT include:
  * eBPF/LSM program time, which the kernel charges to the process whose syscall
    triggered the hook (the workload), not to ShadowProc;
  * FUSE request servicing done in kernel context on behalf of the workload.
So a flat ShadowProc cpu_pct under rising contention is not evidence that the
process layer is free -- it is evidence that its userspace control path is.
The Go heap figures from `graph_stats` are the right complement for ShadowFS
metadata memory, and are reported alongside these numbers.

PID discovery order: SHADOW_{FS,PROC,ORCH}_PID env vars (set by
start_and_run.sh), then the pidfiles it writes, then a /proc cmdline scan.
"""

import os
import time
import threading
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

try:
    CLK_TCK = os.sysconf("SC_CLK_TCK")
except (ValueError, OSError, AttributeError):  # pragma: no cover - non-POSIX
    CLK_TCK = 100

# Daemon roles, in the order experiments report them.
ROLES = ("shadowfs", "shadowproc", "orchestrator")

_PIDFILE = {
    "shadowfs": "/var/tmp/shadowfs-rq3.pid",
    "shadowproc": "/var/tmp/shadowproc-rq3.pid",
    "orchestrator": "/var/tmp/orch-rq3.pid",
}
_PIDENV = {
    "shadowfs": "SHADOW_FS_PID",
    "shadowproc": "SHADOW_PROC_PID",
    "orchestrator": "SHADOW_ORCH_PID",
}
# Substrings that identify each daemon in /proc/<pid>/cmdline. Ordered from
# most to least specific so the orchestrator (a python script) is not confused
# with an experiment that merely mentions the daemon in its arguments.
_CMDLINE_MATCH = {
    "shadowfs": ("shadowfs", "-staging"),
    "shadowproc": ("shadow-proc",),
    "orchestrator": ("shadow_orchestrator.py", "--listen"),
}


@dataclass
class ProcSample:
    """One reading of one daemon."""
    role: str
    pid: int = 0
    found: bool = False
    cpu_seconds: float = 0.0   # cumulative utime+stime since process start
    rss_bytes: int = 0
    threads: int = 0
    wall: float = 0.0          # time.monotonic() when read
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProcDelta:
    """A phase's resource cost for one daemon."""
    role: str
    pid: int = 0
    found: bool = False
    wall_seconds: float = 0.0
    cpu_seconds: float = 0.0
    cpu_pct: float = 0.0       # cpu_seconds / wall_seconds * 100 (can exceed 100)
    rss_start_bytes: int = 0
    rss_end_bytes: int = 0
    rss_peak_bytes: int = 0
    rss_delta_bytes: int = 0
    samples: int = 0
    error: str = ""

    @property
    def rss_peak_mb(self) -> float:
        return self.rss_peak_bytes / (1024.0 * 1024.0)

    @property
    def rss_delta_mb(self) -> float:
        return self.rss_delta_bytes / (1024.0 * 1024.0)

    def to_dict(self) -> dict:
        return asdict(self)


def _read_stat(pid: int) -> Tuple[float, int]:
    """Return (cpu_seconds, threads) for pid.

    /proc/<pid>/stat field 2 is comm, which may contain spaces and parentheses,
    so parsing splits on the LAST ')' rather than on whitespace. Field numbers
    are 1-based over the whole line: 14=utime 15=stime 20=num_threads, which
    become indices 11, 12 and 17 after dropping pid and comm.
    """
    with open(f"/proc/{pid}/stat", "rb") as fh:
        data = fh.read().decode("utf-8", "replace")
    rparen = data.rfind(")")
    if rparen < 0:
        raise ValueError(f"malformed /proc/{pid}/stat")
    fields = data[rparen + 2:].split()
    utime = int(fields[11])
    stime = int(fields[12])
    threads = int(fields[17])
    return (utime + stime) / float(CLK_TCK), threads


def _read_rss(pid: int) -> int:
    """Return VmRSS in bytes (0 if the kernel does not report it)."""
    with open(f"/proc/{pid}/status", "rb") as fh:
        for raw in fh:
            line = raw.decode("utf-8", "replace")
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1]) * 1024
                return 0
    return 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True   # exists, owned by someone else
    except OSError:
        return False
    return True


def _scan_proc(all_substrings: Tuple[str, ...]) -> int:
    """Find a pid whose cmdline contains every substring. 0 if none."""
    try:
        entries = os.listdir("/proc")
    except OSError:
        return 0
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read().decode("utf-8", "replace")
        except OSError:
            continue
        if not cmd:
            continue
        # cmdline is NUL-separated; keep the NULs out of the match text but
        # require every substring so "python3 exp.py --shadowfs-sock" does not
        # get mistaken for the daemon itself.
        text = cmd.replace("\x00", " ")
        if all(s in text for s in all_substrings):
            return pid
    return 0


class DaemonResources:
    """Discovers the daemons and measures their CPU/RSS across a phase.

    Usage:
        res = DaemonResources()
        with res.window() as w:
            run_phase()
        report = w.result          # {role: ProcDelta}
        cpu = report["shadowfs"].cpu_pct

    A window that cannot find a daemon still yields a ProcDelta with
    found=False and an explanatory error, so a missing pidfile degrades a
    column of the results table instead of aborting the experiment.
    """

    def __init__(self, roles: Tuple[str, ...] = ROLES,
                 poll_interval: float = 0.2):
        self.roles = tuple(roles)
        self.poll_interval = poll_interval
        self.pids: Dict[str, int] = {}
        # Set once discovery has run, so a caller that pins pids by hand (the
        # unit tests, or an experiment measuring a specific process) is not
        # second-guessed by window().
        self._discovered = False

    # ── discovery ────────────────────────────────────────────────────────

    def discover(self) -> Dict[str, int]:
        """Resolve each role to a pid: env var, then pidfile, then /proc scan."""
        found: Dict[str, int] = {}
        for role in self.roles:
            pid = 0
            env = os.environ.get(_PIDENV.get(role, ""), "")
            if env.strip().isdigit():
                candidate = int(env.strip())
                if _pid_alive(candidate):
                    pid = candidate
            if not pid:
                path = _PIDFILE.get(role, "")
                if path and os.path.exists(path):
                    try:
                        with open(path) as fh:
                            candidate = int(fh.read().strip())
                        if _pid_alive(candidate):
                            pid = candidate
                    except (OSError, ValueError):
                        pid = 0
            if not pid:
                pid = _scan_proc(_CMDLINE_MATCH[role])
            if pid:
                found[role] = pid
        self.pids = found
        self._discovered = True
        return found

    def missing(self) -> List[str]:
        """Roles that discovery could not resolve."""
        return [r for r in self.roles if r not in self.pids]

    # ── sampling ─────────────────────────────────────────────────────────

    def sample(self) -> Dict[str, ProcSample]:
        """One synchronous reading of every discovered daemon."""
        out: Dict[str, ProcSample] = {}
        now = time.monotonic()
        for role in self.roles:
            pid = self.pids.get(role, 0)
            if not pid:
                out[role] = ProcSample(role=role, wall=now,
                                       error="pid not discovered")
                continue
            s = ProcSample(role=role, pid=pid, wall=now)
            try:
                s.cpu_seconds, s.threads = _read_stat(pid)
                s.rss_bytes = _read_rss(pid)
                s.found = True
            except (OSError, ValueError, IndexError) as e:
                s.error = f"{type(e).__name__}: {e}"
            out[role] = s
        return out

    @contextmanager
    def window(self, poll: bool = True):
        """Bracket a phase, polling RSS in the background for a true peak.

        The poller is a daemon thread so an exception inside the phase cannot
        leave it running; it is joined before the window closes either way.
        """
        if not self._discovered:
            self.discover()
        win = _ResourceWindow(self, poll=poll)
        win.__enter__()
        try:
            yield win
        finally:
            win.__exit__()


class _ResourceWindow:
    """Body of DaemonResources.window(); holds the phase's measurements."""

    def __init__(self, res: DaemonResources, poll: bool = True):
        self._res = res
        self._poll = poll and res.poll_interval > 0
        self._start: Dict[str, ProcSample] = {}
        self._end: Dict[str, ProcSample] = {}
        self._peak: Dict[str, int] = {}
        self._samples: Dict[str, int] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._t0 = 0.0
        self._t1 = 0.0
        self.result: Dict[str, ProcDelta] = {}

    def __enter__(self) -> "_ResourceWindow":
        self._start = self._res.sample()
        for role, s in self._start.items():
            self._peak[role] = s.rss_bytes
            self._samples[role] = 1 if s.found else 0
        self._t0 = time.monotonic()
        if self._poll:
            self._thread = threading.Thread(target=self._poll_loop,
                                            name="res-poll", daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._res.poll_interval * 4 + 1.0)
            self._thread = None
        self._t1 = time.monotonic()
        self._end = self._res.sample()
        wall = max(self._t1 - self._t0, 1e-9)
        out: Dict[str, ProcDelta] = {}
        for role in self._res.roles:
            a = self._start.get(role, ProcSample(role=role))
            b = self._end.get(role, ProcSample(role=role))
            d = ProcDelta(role=role, pid=a.pid or b.pid,
                          found=bool(a.found and b.found),
                          wall_seconds=round(wall, 6))
            if not d.found:
                d.error = a.error or b.error or "daemon disappeared mid-phase"
                d.rss_peak_bytes = max(self._peak.get(role, 0), b.rss_bytes)
                out[role] = d
                continue
            d.cpu_seconds = round(b.cpu_seconds - a.cpu_seconds, 6)
            d.cpu_pct = round(d.cpu_seconds / wall * 100.0, 3)
            d.rss_start_bytes = a.rss_bytes
            d.rss_end_bytes = b.rss_bytes
            d.rss_peak_bytes = max(self._peak.get(role, 0),
                                   a.rss_bytes, b.rss_bytes)
            d.rss_delta_bytes = b.rss_bytes - a.rss_bytes
            d.samples = self._samples.get(role, 0)
            out[role] = d
        self.result = out

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self._res.poll_interval)
            if self._stop.is_set():
                return
            for role, s in self._res.sample().items():
                if not s.found:
                    continue
                self._samples[role] = self._samples.get(role, 0) + 1
                if s.rss_bytes > self._peak.get(role, 0):
                    self._peak[role] = s.rss_bytes


def summarize(deltas: Dict[str, ProcDelta]) -> dict:
    """Flatten a window result into the shape the results JSON stores.

    Keyed "<role>_<metric>" so a scaling table can select columns without
    walking nested dicts, plus an aggregate `daemons_cpu_pct` because the
    reviewer-facing question is the total coordination tax, not its split.
    """
    out: Dict[str, object] = {}
    total_cpu = 0.0
    total_peak = 0
    wall = 0.0
    for role in ROLES:
        d = deltas.get(role)
        if d is None:
            continue
        out[f"{role}_found"] = d.found
        out[f"{role}_pid"] = d.pid
        out[f"{role}_cpu_seconds"] = d.cpu_seconds
        out[f"{role}_cpu_pct"] = d.cpu_pct
        out[f"{role}_rss_start_mb"] = round(d.rss_start_bytes / 1048576.0, 3)
        out[f"{role}_rss_peak_mb"] = round(d.rss_peak_bytes / 1048576.0, 3)
        out[f"{role}_rss_delta_mb"] = round(d.rss_delta_bytes / 1048576.0, 3)
        out[f"{role}_rss_samples"] = d.samples
        if d.error:
            out[f"{role}_error"] = d.error
        if d.found:
            total_cpu += d.cpu_pct
            total_peak += d.rss_peak_bytes
            wall = max(wall, d.wall_seconds)
    # Kept so aggregate_resources() can recompute percentages from cpu-seconds
    # over wall time instead of averaging percentages of unequal windows.
    out["wall_seconds"] = round(wall, 6)
    out["windows"] = 1
    out["daemons_cpu_pct"] = round(total_cpu, 3)
    out["daemons_rss_peak_mb"] = round(total_peak / 1048576.0, 3)
    return out


def aggregate_resources(windows: List[dict]) -> dict:
    """Fold several summarize() windows into one figure for a whole dimension.

    Percentages are RECOMPUTED from summed cpu-seconds over summed wall time.
    Averaging the per-window percentages would weight a 0.5 s window as heavily
    as a 30 s one, which quietly distorts exactly the large-N points whose cost
    the experiment exists to measure. Peaks take the max: memory overhead is a
    high-water mark, not a mean.
    """
    if not windows:
        return {}
    out: Dict[str, object] = {}
    total_cpu_s = 0.0
    total_peak_mb = 0.0
    for role in ROLES:
        found = [w for w in windows if w.get(f"{role}_found")]
        if not found:
            out[f"{role}_found"] = False
            for w in windows:
                if w.get(f"{role}_error"):
                    out[f"{role}_error"] = w[f"{role}_error"]
                    break
            continue
        cpu_s = sum(float(w.get(f"{role}_cpu_seconds") or 0.0) for w in found)
        wall = sum(float(w.get(f"{role}_wall_seconds") or 0.0) for w in found)
        peak_mb = max(float(w.get(f"{role}_rss_peak_mb") or 0.0) for w in found)
        start_mb = float(found[0].get(f"{role}_rss_start_mb") or 0.0)
        # Growth across the whole dimension is the sum of per-window growths:
        # each window starts where the previous one ended.
        delta_mb = sum(float(w.get(f"{role}_rss_delta_mb") or 0.0) for w in found)
        out[f"{role}_found"] = True
        out[f"{role}_pid"] = found[-1].get(f"{role}_pid")
        out[f"{role}_cpu_seconds"] = round(cpu_s, 6)
        out[f"{role}_cpu_pct"] = round(cpu_s / wall * 100.0, 3) if wall else 0.0
        out[f"{role}_rss_start_mb"] = round(start_mb, 3)
        out[f"{role}_rss_peak_mb"] = round(peak_mb, 3)
        out[f"{role}_rss_delta_mb"] = round(delta_mb, 3)
        out[f"{role}_rss_samples"] = sum(int(w.get(f"{role}_rss_samples") or 0)
                                         for w in found)
        total_cpu_s += cpu_s
        total_peak_mb += peak_mb
    total_wall = sum(float(w.get("wall_seconds") or 0.0) for w in windows)
    out["wall_seconds"] = round(total_wall, 6)
    out["windows"] = len(windows)
    out["daemons_cpu_pct"] = (round(total_cpu_s / total_wall * 100.0, 3)
                              if total_wall else 0.0)
    out["daemons_rss_peak_mb"] = round(total_peak_mb, 3)
    return out


if __name__ == "__main__":
    # Manual check: prints one 2-second window over whatever daemons are up.
    r = DaemonResources()
    pids = r.discover()
    print(f"discovered: {pids}  missing: {r.missing()}")
    with r.window() as w:
        time.sleep(2.0)
    for role, d in w.result.items():
        print(f"  {role:13s} found={d.found} cpu={d.cpu_pct:6.2f}% "
              f"rss_peak={d.rss_peak_mb:8.2f}MB delta={d.rss_delta_mb:+.2f}MB "
              f"samples={d.samples} {d.error}")
    print(summarize(w.result))
    print(aggregate_resources([summarize(w.result)]))
