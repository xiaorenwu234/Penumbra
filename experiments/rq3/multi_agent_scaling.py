#!/usr/bin/env python3
"""
RQ3 Experiment A: Multi-Agent Scaling.

Measures what happens to Penumbra's coordination machinery when the NUMBER OF
AGENTS sharing one workspace grows, under three dependency regimes:

  independent       every agent touches only its own files. No cross-epoch
                    dependency can form, so this is the scaling upper bound:
                    anything sub-linear here is coordination overhead, not
                    dependency tracking.
  partially_shared  agents are paired: producer k writes x_k, consumer k reads
                    x_k and writes y_k; an odd trailing agent stays independent.
                    Exercises dependency tracking ALONGSIDE independent branch
                    preservation -- the unpaired agent must never pay for, or be
                    rolled back with, a pair it does not belong to.
  contended         every agent reads the whole shared file set and writes into
                    it. Worst case: read-from and write-write edges appear
                    between most agents, so the graph lock, SCC resolution and
                    the graph_generation TOCTOU fence are all hot.

Agent counts: 1 / 2 / 4 / 8 / 16 / 32 by default. 32 is the largest sane point
on this host: ShadowProc's BPF slot table caps CONCURRENT live cgroups at 64
(`add_cgroup: Maximum 64 concurrent cgroups supported`), and every agent holds
one cgroup for the whole configuration, so the ceiling is a hard system limit
rather than a measurement choice.

Metrics collected per (workload, agent count)
---------------------------------------------
  throughput                 invocations/s over the whole concurrent phase
  session_open latency       cost of ADMITTING one more agent
  epoch begin latency        + orchestrator breakdown (agent barrier, graph
                             sequence lock wait, ShadowFS begin_epoch, ShadowProc
                             fork)
  dependency insertion       client-visible: the same `cat` of the same file,
                             once while the producer's epoch is LIVE (creates a
                             read-from edge, WAL append + fsync) and once after
                             the producer finalized (creates nothing). The
                             difference is the price of exact read provenance.
                             daemon-side: edge_insert_ns / edge_insertions.
  authz -> finalization      orchestrator `authz_to_finalized_ms`, plus its own
                             breakdown (prepare_resolution, freeze, begin_finalize,
                             wait_finalized, lock wait/held)
  commit latency             client-experienced, including any retry after an
                             `authorized_pending` response
  rollback latency           + cascade size (affected_epochs) per rollback
  orchestrator/ShadowFS/     DaemonResources window over the measured phase
  ShadowProc CPU + RSS
  dependency graph size      graph_stats delta: epochs, edges, versions, SCC
                             counts, Go heap
  edges per invocation       edge_insertions / measured invocations -- the
                             number that says whether the graph grows with
                             work or with the square of the agent count

Honest limitations
------------------
  * `partially_shared` and `contended` form an edge only when the producer's
    epoch is still live and unfinalized at the moment of the read (ShadowFS's
    readDepInternal skips versions whose owner is Finalized or gone). Agents
    run concurrently but not in lockstep, so edges per invocation is a
    MEASURED fraction, not a constructed constant. The structure phase below
    is where the exact topology is asserted, by holding every epoch open.
  * Agent CPU is deliberately NOT pinned. WorkloadHarness pins to one core to
    make single-agent latency comparable to `taskset` baselines; pinning here
    would serialize the very parallelism being measured.
  * DaemonResources reports USERSPACE cpu of each daemon. eBPF/LSM time is
    charged by the kernel to the workload process that triggered the hook, so
    a flat shadowproc cpu_pct is evidence about its control path only.

Usage:
    SHADOW_RUN_RQ3_EXPERIMENTS=1 python3 multi_agent_scaling.py [options]

Options:
    --output-dir DIR      output directory (default: ./results)
    --workloads LIST      comma-separated subset (default: all three)
    --agents LIST         comma-separated agent counts (default: 1,2,4,8,16,32)
    --repeats N           repeats of the throughput phase (default: 3)
    --invocations N       measured invocations per agent (default: 20)
    --phases LIST         structure,throughput,rollback,insertion (default: all)
    --quick               small configuration for a smoke run
    --dry-run             print the configuration and exit

Prerequisites:
    - Root privileges
    - Running orchestrator daemon (/tmp/shadow-orch.sock)
    - ShadowFS FUSE mounted at /tmp/shadow-rq2-test/mnt
"""

import argparse
import json
import os
import statistics
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from framework import OrchClient, compute_stats, graph_delta, summarize
from framework.timing import Timer
from framework.harness import SHADOWFS_MNT, SHADOWFS_ORIG
from framework.resources import DaemonResources

EXPERIMENTS_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ3_EXPERIMENTS") == "1"

# Work directory under the FUSE mount. Kept separate from dep_graph's rq3-dep
# so the two experiments cannot observe each other's epochs in graph_stats.
MULTI_WORK_FUSE = os.path.join(SHADOWFS_MNT, "rq3-multi")
MULTI_WORK_ORIG = os.path.join(SHADOWFS_ORIG, "rq3-multi")

ALLOW_ALL_OPS = [{"event_type": "*", "action": "allow", "path_pattern": "/"}]

WORKLOADS = ("independent", "partially_shared", "contended")
PHASES = ("structure", "throughput", "rollback", "insertion")

# Shared file set size for `contended`. 4 files over up to 32 agents means up
# to 8 concurrent writers per file: enough write-write contention to make the
# graph lock and the TOCTOU fence visible without degenerating into a single
# global serialization point that would measure nothing but a queue.
SHARED_FILES = 4

FULL_AGENTS = [1, 2, 4, 8, 16, 32]
QUICK_AGENTS = [1, 4, 16]
FULL_REPEATS = 3
QUICK_REPEATS = 1
FULL_INVOCATIONS = 20
QUICK_INVOCATIONS = 5
FULL_ROLLBACK_INVOCATIONS = 5
QUICK_ROLLBACK_INVOCATIONS = 2
FULL_PROBE_REPEATS = 5
QUICK_PROBE_REPEATS = 2

# A commit that finds its SCC siblings not yet authorized returns
# `authorized_pending` and parks the group; the orchestrator's background retry
# loop finishes it. The client therefore retries instead of failing: this is
# the documented recovery path, and the number of retries is itself a result.
PENDING_RETRY_LIMIT = 60
PENDING_RETRY_SLEEP_S = 0.02
# The attempt cap alone is not a bound. Each attempt blocks in the
# orchestrator's own finalize poll for up to 30s before it can answer
# `authorized_pending` again, so 60 attempts is half an hour of silence on ONE
# commit -- indistinguishable from a hang, and paid once per probe. The wall
# clock is what bounds it; the attempt cap is only a backstop for a server that
# answers pending instantly.
PENDING_RETRY_BUDGET_S = 90.0

# ─── default agent-count ceiling ─────────────────────────────────────────────
# ShadowProc supports at most 64 concurrent live cgroups. Each agent holds one
# for the whole configuration, so exceeding this fails session_open rather than
# degrading a measurement.
MAX_AGENTS = 64


# ═══════════════════════════════════════════════════════════════════════════
# Result structures
# ═══════════════════════════════════════════════════════════════════════════

def _ns_stats(name: str, samples: List[float]) -> Optional[Dict[str, Any]]:
    """Stats over nanosecond samples (None when the phase produced nothing)."""
    if not samples:
        return None
    return compute_stats(name, samples).to_dict()


def _ms_stats(name: str, samples: List[float]) -> Optional[Dict[str, Any]]:
    """Stats over millisecond samples, reported through the same schema.

    Scaled to ns so compute_stats' percentile/CI code is reused unchanged and
    the JSON keys (*_ms / *_ns) mean the same thing everywhere in the results.
    """
    if not samples:
        return None
    return compute_stats(name, [s * 1e6 for s in samples]).to_dict()


def _merge_timings(dst: Dict[str, List[float]], src: Optional[Dict[str, Any]]):
    """Accumulate every numeric field the orchestrator stamped.

    Keys are discovered, not hardcoded: when the orchestrator gains a new
    phase stamp the results file picks it up instead of silently dropping the
    one number a reviewer asked about.
    """
    for key, val in (src or {}).items():
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            continue
        dst.setdefault(key, []).append(float(val))


@dataclass
class ScalingResult:
    """Everything measured for one (workload, agent-count) configuration."""
    workload: str
    agents: int
    repeats: int = 0
    invocations_per_agent: int = 0
    rollback_invocations_per_agent: int = 0

    # ── throughput phase ──
    wall_s: List[float] = field(default_factory=list)
    throughput: List[float] = field(default_factory=list)   # invocations/s
    invocations_ok: List[int] = field(default_factory=list)
    open_ns: List[float] = field(default_factory=list)
    begin_ns: List[float] = field(default_factory=list)
    run_ns: List[float] = field(default_factory=list)
    commit_ns: List[float] = field(default_factory=list)
    invocation_ns: List[float] = field(default_factory=list)
    begin_timings: Dict[str, List[float]] = field(default_factory=dict)
    commit_timings: Dict[str, List[float]] = field(default_factory=dict)
    commit_attempts: List[int] = field(default_factory=list)
    pending_commits: int = 0        # commits that returned authorized_pending
    finalization_wait_ns: List[float] = field(default_factory=list)

    # ── rollback phase ──
    rollback_ns: List[float] = field(default_factory=list)
    rollback_timings: Dict[str, List[float]] = field(default_factory=dict)
    rollback_affected: List[int] = field(default_factory=list)
    rollback_failed: int = 0
    # Expected fail-closed EIO/EBADF from a concurrent cascade undoing this
    # agent's epoch/version mid-setup -- counted apart from genuine failures
    # (see _is_cascade_collision). Non-zero only for a shared workload.
    rollback_collisions: int = 0
    rollback_collision_samples: List[str] = field(default_factory=list)

    # ── dependency-insertion probe ──
    edge_run_ns: List[float] = field(default_factory=list)
    noedge_run_ns: List[float] = field(default_factory=list)
    probe_edges: int = 0            # edges the probe phase actually created
    probe_probes: int = 0
    control_edges: int = 0          # edges the control phase created (want 0)
    control_probes: int = 0
    probe_edge_insert_ns: int = 0   # ShadowFS-side cumulative addDependency time

    # ── graph + daemon resources over the measured phase ──
    graph: Dict[str, Any] = field(default_factory=dict)
    resources: Dict[str, Any] = field(default_factory=dict)

    # ── structure verification ──
    structure_ok: Optional[bool] = None
    structure_edges: int = 0
    structure_errors: List[str] = field(default_factory=list)
    # graph_stats sampled with EVERY epoch open: the dependency-graph size and
    # the metadata-memory figure at full population, a state the throughput
    # phase never pauses in.
    structure_graph: Dict[str, Any] = field(default_factory=dict)
    structure_detail: Dict[str, Any] = field(default_factory=dict)
    branch_preservation_ok: Optional[bool] = None
    branch_errors: List[str] = field(default_factory=list)

    errors: List[str] = field(default_factory=list)
    wall_time_s: float = 0.0

    # ── derived ──

    @property
    def total_invocations(self) -> int:
        return sum(self.invocations_ok)

    @property
    def edges_per_invocation(self) -> Optional[float]:
        """Graph edges created per measured invocation.

        The reviewer-facing question behind the whole experiment: if this grows
        with the agent count, the dependency graph is quadratic in the number of
        agents and the design does not scale; if it stays flat, edges track
        actual data flow.
        """
        n = self.total_invocations
        if not n:
            return None
        return self.graph.get("edge_insertions", 0) / float(n)

    @property
    def insertion_latency_ns(self) -> Optional[float]:
        """Client-visible price of one read-from edge (median difference)."""
        if not self.edge_run_ns or not self.noedge_run_ns:
            return None
        return (statistics.median(self.edge_run_ns)
                - statistics.median(self.noedge_run_ns))

    @property
    def daemon_edge_insert_ns(self) -> Optional[float]:
        """ShadowFS-side mean cost of one addDependency call."""
        n = self.graph.get("edge_insertions", 0)
        if not n:
            return None
        return self.graph.get("edge_insert_ns", 0) / float(n)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "workload": self.workload,
            "agents": self.agents,
            "repeats": self.repeats,
            "invocations_per_agent": self.invocations_per_agent,
            "rollback_invocations_per_agent": self.rollback_invocations_per_agent,
            "total_invocations": self.total_invocations,
            "wall_time_s": self.wall_time_s,
            "errors": self.errors[:20],
            "error_count": len(self.errors),
        }
        if self.throughput:
            d["throughput_inv_per_s"] = {
                "median": statistics.median(self.throughput),
                "mean": statistics.fmean(self.throughput),
                "min": min(self.throughput),
                "max": max(self.throughput),
                "n": len(self.throughput),
            }
        if self.wall_s:
            d["wall_s_median"] = statistics.median(self.wall_s)

        stats: Dict[str, Any] = {}
        for name, samples in (("session_open_ns", self.open_ns),
                              ("epoch_begin_ns", self.begin_ns),
                              ("run_ns", self.run_ns),
                              ("commit_ns", self.commit_ns),
                              ("invocation_ns", self.invocation_ns),
                              ("rollback_ns", self.rollback_ns),
                              ("finalization_wait_ns", self.finalization_wait_ns),
                              ("insertion_edge_run_ns", self.edge_run_ns),
                              ("insertion_noedge_run_ns", self.noedge_run_ns)):
            s = _ns_stats(name, samples)
            if s is not None:
                stats[name] = s
        for name, samples in (("begin", self.begin_timings),
                              ("commit", self.commit_timings),
                              ("rollback", self.rollback_timings)):
            for key, vals in sorted(samples.items()):
                s = _ms_stats(f"{name}.{key}", vals)
                if s is not None:
                    stats[f"{name}_timings_ms.{key}"] = s
        d["stats"] = stats

        d["pending_commits"] = self.pending_commits
        d["commit_attempts_mean"] = (
            statistics.fmean(self.commit_attempts) if self.commit_attempts else None)
        d["rollback_failed"] = self.rollback_failed
        d["rollback_collisions"] = self.rollback_collisions
        d["rollback_collision_samples"] = self.rollback_collision_samples[:20]
        d["rollback_affected_mean"] = (
            statistics.fmean(self.rollback_affected) if self.rollback_affected else None)
        d["rollback_affected_max"] = (
            max(self.rollback_affected) if self.rollback_affected else None)

        d["graph"] = self.graph
        d["resources"] = self.resources

        epi = self.edges_per_invocation
        d["edges_per_invocation"] = epi
        d["insertion_latency_ns_client"] = self.insertion_latency_ns
        d["insertion_latency_ns_daemon"] = self.daemon_edge_insert_ns
        if epi is not None and self.daemon_edge_insert_ns is not None:
            # What the measured edge rate costs inside ShadowFS per invocation.
            d["modelled_graph_overhead_us_per_invocation"] = (
                epi * self.daemon_edge_insert_ns / 1000.0)

        d["insertion_probe"] = {
            "probes": self.probe_probes,
            "edges_created": self.probe_edges,
            "control_probes": self.control_probes,
            "control_edges_created": self.control_edges,
            "edge_insert_ns_total": self.probe_edge_insert_ns,
            # The probe is only a valid measurement of ONE edge's cost if it
            # really created exactly one edge per probe and the control created
            # none. Recorded rather than asserted so a failed probe degrades a
            # column instead of invalidating an hour of throughput data.
            "verified": (self.probe_probes > 0
                         and self.probe_edges == self.probe_probes
                         and self.control_probes > 0
                         and self.control_edges == 0),
        }
        d["structure"] = {
            "ok": self.structure_ok,
            "edges": self.structure_edges,
            "errors": self.structure_errors[:20],
            "detail": self.structure_detail,
        }
        # Metadata memory is reported from the full-population snapshot, with
        # the end-of-phase heap alongside: the difference between them is what
        # finalization released.
        if self.structure_graph:
            d["structure_graph"] = {
                k: self.structure_graph.get(k)
                for k in ("epochs", "edges", "versions", "objects",
                          "scc_count", "cyclic_scc_count", "max_scc_size",
                          "heap_alloc_bytes", "heap_inuse_bytes", "sys_bytes")
            }
        d["branch_preservation_ok"] = self.branch_preservation_ok
        d["branch_errors"] = self.branch_errors[:20]
        return d


# ═══════════════════════════════════════════════════════════════════════════
# Workspace helpers
# ═══════════════════════════════════════════════════════════════════════════

def ensure_multi_dirs():
    """Create the work directory in the backing store."""
    os.makedirs(MULTI_WORK_ORIG, exist_ok=True)


def cleanup_multi_dir():
    """Remove the work directory contents (backing-store side).

    Only the backing store is touched: the merged view is a FUSE projection of
    it, and removing files through the mount would create whiteout versions
    owned by whatever epoch is live in the calling process.
    """
    import shutil
    if os.path.isdir(MULTI_WORK_ORIG):
        shutil.rmtree(MULTI_WORK_ORIG, ignore_errors=True)
    os.makedirs(MULTI_WORK_ORIG, exist_ok=True)


def multi_fuse_path(rel: str) -> str:
    return os.path.join(MULTI_WORK_FUSE, rel)


def create_seed_file(rel_path: str, content: str = "seed"):
    """Pre-create a file in the backing store.

    Files MUST exist in orig before an epoch reads them: otherwise the FUSE
    Lookup fails with ENOENT before reaching Open, where Resolve() records the
    read-from edge, and the dependency the experiment intends to measure never
    forms.
    """
    full = os.path.join(MULTI_WORK_ORIG, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)


# ═══════════════════════════════════════════════════════════════════════════
# Workload definitions
# ═══════════════════════════════════════════════════════════════════════════

def agent_files(workload: str, idx: int, n_agents: int) -> Tuple[List[str], List[str]]:
    """(files this agent READS, files this agent WRITES), relative names.

    The whole workload taxonomy is this one function: three file-layout rules
    produce three dependency regimes, and every command below is derived from
    it, so the commands cannot drift from the layout the verification expects.
    """
    if workload == "independent":
        # Disjoint files: no foreign version can ever be observed.
        return [f"ind_{idx}.dat"], [f"ind_{idx}.dat"]

    if workload == "partially_shared":
        # Odd trailing agent stays independent (the user's "E independent"):
        # it is the branch that must be preserved while a pair couples.
        if n_agents % 2 == 1 and idx == n_agents - 1:
            return ["solo.dat"], ["solo.dat"]
        pair = idx // 2
        if idx % 2 == 0:
            # Producer: writes x, reads back its own (promoted) x.
            return [f"x_{pair}.dat"], [f"x_{pair}.dat"]
        # Consumer: reads the producer's x, writes its own y.
        return [f"x_{pair}.dat"], [f"y_{pair}.dat"]

    if workload == "contended":
        shared = min(SHARED_FILES, n_agents)
        return ([f"sh_{j}.dat" for j in range(shared)],
                [f"sh_{idx % shared}.dat"])

    raise ValueError(f"unknown workload {workload!r}")


def agent_role(workload: str, idx: int, n_agents: int) -> str:
    """Human-readable role, recorded so a result row explains itself."""
    if workload == "partially_shared":
        if n_agents % 2 == 1 and idx == n_agents - 1:
            return "independent"
        return "producer" if idx % 2 == 0 else "consumer"
    return workload


def seed_files(workload: str, n_agents: int) -> List[str]:
    """Every file any agent of this configuration touches."""
    out: Set[str] = set()
    for i in range(n_agents):
        reads, writes = agent_files(workload, i, n_agents)
        out.update(reads)
        out.update(writes)
    return sorted(out)


def seed_workspace(workload: str, n_agents: int):
    """Reset the workspace and pre-create this configuration's files."""
    cleanup_multi_dir()
    for rel in seed_files(workload, n_agents):
        create_seed_file(rel, "base")
    # The insertion probe uses its own file so its edges are attributable.
    create_seed_file("dep_probe.dat", "probe-base")


def read_commands(workload: str, idx: int, n_agents: int) -> List[str]:
    reads, _ = agent_files(workload, idx, n_agents)
    return [f"cat {multi_fuse_path(r)} > /dev/null" for r in reads]


def write_commands(workload: str, idx: int, n_agents: int, inv: int) -> List[str]:
    _, writes = agent_files(workload, idx, n_agents)
    return [f"echo '{workload[:4]}{idx}-{inv}' > {multi_fuse_path(w)}"
            for w in writes]


def invocation_commands(workload: str, idx: int, n_agents: int,
                        inv: int) -> List[str]:
    """One agent invocation: read its inputs, then write its outputs."""
    return (read_commands(workload, idx, n_agents)
            + write_commands(workload, idx, n_agents, inv))


# ═══════════════════════════════════════════════════════════════════════════
# Agent handles
# ═══════════════════════════════════════════════════════════════════════════

def open_agent(idx: int, run_tag: str) -> Dict[str, Any]:
    """Open one agent's session on its OWN socket connection.

    One connection per agent is not a convenience: the orchestrator protocol is
    line-oriented per connection, so two threads sharing a socket would
    interleave requests and each read the other's response.
    """
    agent_id = f"mas-{run_tag}-a{idx}"
    client = OrchClient()
    for attempt in range(5):
        try:
            client.connect()
            break
        except (BlockingIOError, ConnectionRefusedError, OSError):
            if attempt == 4:
                return {"idx": idx, "agent_id": agent_id, "client": None,
                        "session_id": None, "cgroup_id": None,
                        "error": "connect failed", "open_ns": 0}
            time.sleep(0.05 * (attempt + 1))
    try:
        resp, open_ns = client.timed_open(agent_id)
        return {"idx": idx, "agent_id": agent_id, "client": client,
                "session_id": resp["session_id"],
                "cgroup_id": resp.get("cgroup_id", ""),
                "epoch_id": "", "error": None, "open_ns": open_ns}
    except Exception as e:  # noqa: BLE001
        client.close()
        return {"idx": idx, "agent_id": agent_id, "client": None,
                "session_id": None, "cgroup_id": None,
                "error": f"session_open: {e}", "open_ns": 0}


def open_agents(n_agents: int, run_tag: str) -> List[Dict[str, Any]]:
    """Open n_agents sessions concurrently, in agent-index order."""
    with ThreadPoolExecutor(max_workers=min(n_agents, MAX_AGENTS)) as pool:
        futures = [pool.submit(open_agent, i, run_tag) for i in range(n_agents)]
        handles = [f.result() for f in futures]
    handles.sort(key=lambda h: h["idx"])
    return handles


def close_agents(handles: List[Dict[str, Any]]):
    """Best-effort teardown. Sessions MUST be closed between configurations:
    each holds a cgroup, and ShadowProc caps concurrent cgroups at 64."""
    for h in handles:
        client = h.get("client")
        if client is None:
            continue
        try:
            if h.get("session_id"):
                client.session_close(h["session_id"])
        except Exception:  # noqa: BLE001
            pass
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        h["client"] = None


def live_agents(handles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [h for h in handles if not h.get("error") and h.get("session_id")]


def begin_agent_epoch(h: Dict[str, Any]) -> Tuple[bool, int, Dict[str, Any], str]:
    """Begin an epoch for one agent. Returns (ok, begin_ns, timings, epoch_id)."""
    resp, begin_ns = h["client"].timed_begin_epoch(h["session_id"],
                                                   h["agent_id"])
    h["epoch_id"] = resp.get("epoch_id", "")
    return True, begin_ns, resp.get("timings") or {}, h["epoch_id"]


def run_agent_commands(h: Dict[str, Any], cmds: List[str]) -> int:
    """Run commands inside the agent's live epoch; returns summed run_ns.

    A non-zero exit code raises: a command that failed must never be recorded
    as a fast successful invocation.
    """
    total = 0
    for cmd in cmds:
        resp, ns = h["client"].timed_run(h["session_id"], cmd)
        total += ns
        rc = resp.get("exit_code", 0)
        if rc != 0:
            out = str(resp.get("output", ""))[:160]
            raise RuntimeError(f"command exited {rc}: {cmd!r} -> {out!r}")
    return total


def commit_agent_epoch(h: Dict[str, Any]) -> Tuple[Dict[str, Any], int, int]:
    """Commit one agent's epoch, retrying the parked-group case.

    Returns (final_response, total_ns, attempts). `authorized_pending` is not a
    failure: it means this agent authorized before its SCC siblings did, the
    group was parked, and the orchestrator's background retry loop (or a client
    retry, which finds the group already finalized) completes it. Treating the
    first response as final would report contention as breakage.
    """
    client = h["client"]
    req = {"action": "session_commit_epoch", "session_id": h["session_id"],
           "agent_id": h["agent_id"], "allowed_ops": ALLOW_ALL_OPS}
    attempts = 0
    total = 0
    deadline = time.monotonic() + PENDING_RETRY_BUDGET_S
    with Timer() as t:
        while True:
            attempts += 1
            resp = client.request(req)
            if resp.get("status") == "ok":
                break
            if (resp.get("decision") != "authorized_pending"
                    or attempts >= PENDING_RETRY_LIMIT
                    or time.monotonic() >= deadline):
                break
            time.sleep(PENDING_RETRY_SLEEP_S)
        total = t.elapsed_ns
    return resp, total, attempts


def _extend_timings(dst: Dict[str, List[float]], src: Dict[str, List[float]]):
    """Merge one agent's accumulated timing samples into the configuration's."""
    for key, vals in (src or {}).items():
        dst.setdefault(key, []).extend(vals)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1: structure verification (exact topology + branch preservation)
# ═══════════════════════════════════════════════════════════════════════════

def build_open_graph(obs: OrchClient, workload: str, n_agents: int,
                     handles: List[Dict[str, Any]]) -> List[str]:
    """Give every agent a live epoch and wire the workload's real dependencies.

    Order is what makes the topology deterministic: ALL epochs are opened and
    ALL writes issued first, so when the reads run in the second pass every
    foreign version they observe belongs to an epoch that is still open and
    unfinalized -- the only condition under which ShadowFS records a read-from
    edge. The concurrent phases measure a realistic interleaving; this one
    measures a known graph.
    """
    errors: List[str] = []
    for h in handles:
        try:
            begin_agent_epoch(h)
        except Exception as e:  # noqa: BLE001
            errors.append(f"begin_epoch(agent{h['idx']}): {e}")
            return errors
    for h in handles:
        try:
            run_agent_commands(h, write_commands(workload, h["idx"], n_agents, 0))
        except Exception as e:  # noqa: BLE001
            errors.append(f"write(agent{h['idx']}): {e}")
    for h in handles:
        try:
            run_agent_commands(h, read_commands(workload, h["idx"], n_agents))
        except Exception as e:  # noqa: BLE001
            errors.append(f"read(agent{h['idx']}): {e}")
    return errors


def expected_affected(workload: str, idx: int, n_agents: int,
                      handles: List[Dict[str, Any]]) -> Optional[Set[str]]:
    """Exact affected-cgroup set for agent idx, or None when not predictable.

    `contended` returns None on purpose: which agent owns a file's head version
    there depends on the write order across the shared set, so only the weaker
    coupling properties below are asserted. Asserting an exact set for a graph
    the experiment did not construct would be a check that passes by luck.
    """
    cg = {h["idx"]: h["cgroup_id"] for h in handles}
    if workload == "independent":
        return {cg[idx]}
    if workload == "partially_shared":
        if n_agents % 2 == 1 and idx == n_agents - 1:
            return {cg[idx]}                     # the unpaired agent
        if idx % 2 == 0:
            exp = {cg[idx]}
            if idx + 1 < n_agents:
                exp.add(cg[idx + 1])             # producer carries its consumer
            return exp
        return {cg[idx]}                         # consumer is downstream: alone
    return None


def verify_affected_sets(obs: OrchClient, workload: str, n_agents: int,
                         handles: List[Dict[str, Any]]) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Check every agent's cascade set; return (ok, errors, detail)."""
    errors: List[str] = []
    sizes: Dict[int, int] = {}
    all_cg = {h["cgroup_id"] for h in handles}
    union: Set[str] = set()
    for h in handles:
        try:
            resp = obs.get_affected(h["cgroup_id"])
        except Exception as e:  # noqa: BLE001
            errors.append(f"get_affected(agent{h['idx']}): {e}")
            continue
        aff = set(resp.get("affected", []))
        sizes[h["idx"]] = len(aff)
        union |= aff
        if h["cgroup_id"] not in aff:
            errors.append(f"agent{h['idx']}: own cgroup missing from its "
                          f"affected set ({len(aff)} entries)")
        exp = expected_affected(workload, h["idx"], n_agents, handles)
        if exp is not None and aff != exp:
            errors.append(
                f"agent{h['idx']} ({agent_role(workload, h['idx'], n_agents)}): "
                f"affected={len(aff)} expected={len(exp)} "
                f"missing={len(exp - aff)} extra={len(aff - exp)}")
    max_size = max(sizes.values()) if sizes else 0
    detail = {"affected_sizes": sizes, "max_affected": max_size,
              "union_covers_all": union == all_cg}
    if workload == "contended":
        # The worst case must actually be coupled: one agent's rollback has to
        # reach others, and together the sets have to cover the workspace.
        if union != all_cg:
            errors.append(f"contended: affected union covers {len(union)}/"
                          f"{len(all_cg)} cgroups")
        if n_agents > 1 and max_size < 2:
            errors.append(f"contended: max affected set is {max_size}, so no "
                          f"agent is coupled to any other")
    return not errors, errors, detail


def verify_branch_preservation(obs: OrchClient, workload: str, n_agents: int,
                               handles: List[Dict[str, Any]],
                               res: ScalingResult):
    """Roll one agent back; every unrelated branch must survive and still commit.

    This is the property no latency number can show. Cascading rollback has to
    follow the dependency edges and ONLY those: a consumer rolled back must not
    disturb the producer it read from, and an agent outside the pair must not
    notice at all. If this fails, `partially_shared` is one global transaction
    wearing a dependency graph's clothes.
    """
    if workload == "contended":
        res.branch_preservation_ok = None
        res.branch_errors.append(
            "n/a: contended couples every agent by construction")
        return
    if n_agents < 2:
        res.branch_preservation_ok = None
        res.branch_errors.append("n/a: one agent has no unrelated branch")
        return

    errors: List[str] = []
    # partially_shared: the consumer of pair 0 (idx 1). independent: agent 0.
    victim_idx = 1 if workload == "partially_shared" else 0
    victim = handles[victim_idx]
    others = [h for i, h in enumerate(handles) if i != victim_idx]
    before = {h["epoch_id"] for h in handles}

    try:
        rb = victim["client"].request({
            "action": "session_rollback_epoch",
            "session_id": victim["session_id"],
            "agent_id": victim["agent_id"]})
    except Exception as e:  # noqa: BLE001
        res.branch_preservation_ok = False
        res.branch_errors.append(f"victim rollback raised: {e}")
        return
    if rb.get("status") != "ok":
        errors.append(f"victim rollback: {rb.get('message')}")
    cascaded = rb.get("affected_epochs", []) or []
    if len(cascaded) != 1:
        errors.append(f"victim rollback cascaded to {len(cascaded)} epochs, "
                      f"want 1 (the victim alone)")

    # The victim left the graph; nobody else did.
    alive = {e["epoch_id"] for e in obs.epoch_states()}
    if victim["epoch_id"] in alive:
        errors.append("victim epoch still in the graph after its rollback")
    for h in others:
        if h["epoch_id"] and h["epoch_id"] not in alive:
            errors.append(f"agent{h['idx']} ({agent_role(workload, h['idx'], n_agents)}) "
                          f"was removed by an unrelated rollback")
    gone = before - alive - {victim["epoch_id"]}
    if gone:
        errors.append(f"{len(gone)} unexpected epoch(es) left the graph")

    if workload == "partially_shared":
        # The producer keeps its own version but loses the edge to the consumer
        # that no longer exists: exact provenance, not a conservative superset.
        producer = handles[0]
        try:
            aff = set(obs.get_affected(producer["cgroup_id"]).get("affected", []))
            if aff != {producer["cgroup_id"]}:
                errors.append(f"producer affected set is {len(aff)} entries "
                              f"after its consumer was rolled back, want 1")
        except Exception as e:  # noqa: BLE001
            errors.append(f"get_affected(producer): {e}")

    # Every surviving branch must still be able to publish.
    for h in others:
        try:
            cresp, _, _ = commit_agent_epoch(h)
        except Exception as e:  # noqa: BLE001
            errors.append(f"agent{h['idx']} commit raised: {e}")
            continue
        if cresp.get("status") != "ok":
            errors.append(f"agent{h['idx']} commit after unrelated rollback: "
                          f"{cresp.get('message')}")

    res.branch_preservation_ok = not errors
    res.branch_errors.extend(errors)


def phase_structure(obs: OrchClient, workload: str, n_agents: int,
                    run_tag: str, res: ScalingResult):
    """Assert the exact dependency topology this workload is supposed to build."""
    handles = open_agents(n_agents, f"{run_tag}-st")
    live = live_agents(handles)
    try:
        if len(live) != n_agents:
            failed = [h["error"] for h in handles if h.get("error")]
            res.structure_ok = False
            res.structure_errors.append(
                f"opened {len(live)}/{n_agents} sessions: {failed[:3]}")
            return
        res.structure_errors.extend(
            build_open_graph(obs, workload, n_agents, live))
        # Sampled with every epoch open: this is the dependency-graph size and
        # the metadata-memory figure at full population, which is the state the
        # throughput phase never pauses in.
        res.structure_graph = obs.graph_stats()
        res.structure_edges = res.structure_graph.get("edges", 0)
        ok, errors, detail = verify_affected_sets(obs, workload, n_agents, live)
        res.structure_detail = detail
        res.structure_errors.extend(errors)
        if workload in ("independent", "partially_shared") and n_agents > 1:
            # Exact sets are only a correctness claim if edges really formed:
            # an empty graph satisfies affected(x)=={x} for every workload.
            want_edges = (n_agents // 2) if workload == "partially_shared" else 0
            if res.structure_edges != want_edges:
                ok = False
                res.structure_errors.append(
                    f"graph has {res.structure_edges} edges, want {want_edges}")
        verify_branch_preservation(obs, workload, n_agents, live, res)
        res.structure_ok = ok and not res.structure_errors
    finally:
        for h in live:
            try:
                h["client"].request({
                    "action": "session_rollback_epoch",
                    "session_id": h["session_id"],
                    "agent_id": h["agent_id"]})
            except Exception:  # noqa: BLE001
                pass   # already committed or already rolled back
        close_agents(handles)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2: throughput under concurrent agents
# ═══════════════════════════════════════════════════════════════════════════

def _agent_commit_loop(h: Dict[str, Any], workload: str, n_agents: int,
                       warmup: int, invocations: int) -> Dict[str, Any]:
    """One agent's invocation loop: begin → run → commit, `invocations` times.

    Warm-up iterations exercise the same path but are discarded: the first
    epoch of a session pays one-off costs (candidate shell warm-up, first
    staging directory creation) that are not part of steady-state scaling.
    """
    out: Dict[str, Any] = {
        "ok": 0, "begin_ns": [], "run_ns": [], "commit_ns": [],
        "invocation_ns": [], "begin_timings": {}, "commit_timings": {},
        "commit_attempts": [], "pending": 0, "errors": [], "unresolved": [],
        "aborted": False,
    }
    client = h["client"]
    for k in range(warmup + invocations):
        measuring = k >= warmup
        inv_t0 = time.perf_counter_ns()
        try:
            _, begin_ns, begin_tm, epoch_id = begin_agent_epoch(h)
            run_ns = run_agent_commands(
                h, invocation_commands(workload, h["idx"], n_agents, k))
            cresp, commit_ns, attempts = commit_agent_epoch(h)
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"agent{h['idx']} inv{k}: {e}")
            try:
                client.request({"action": "session_rollback_epoch",
                                "session_id": h["session_id"],
                                "agent_id": h["agent_id"]})
            except Exception:  # noqa: BLE001
                pass
            # Stop this agent: an epoch that neither committed nor rolled back
            # may be parked mid-finalization, and every later invocation would
            # then queue on the per-agent barrier and record its timeout as a
            # latency sample.
            out["aborted"] = True
            if epoch_id := h.get("epoch_id"):
                out["unresolved"].append(epoch_id)
            break
        if cresp.get("status") != "ok":
            out["errors"].append(f"agent{h['idx']} inv{k}: commit refused: "
                                 f"{cresp.get('message')}")
            out["unresolved"].append(h.get("epoch_id") or "")
            out["aborted"] = True
            break
        if attempts > 1:
            out["pending"] += 1
        if not measuring:
            continue
        out["ok"] += 1
        out["begin_ns"].append(float(begin_ns))
        out["run_ns"].append(float(run_ns))
        out["commit_ns"].append(float(commit_ns))
        out["invocation_ns"].append(float(time.perf_counter_ns() - inv_t0))
        out["commit_attempts"].append(attempts)
        _merge_timings(out["begin_timings"], begin_tm)
        _merge_timings(out["commit_timings"], cresp.get("timings"))
    out["unresolved"] = [e for e in out["unresolved"] if e]
    return out


def phase_throughput(obs: OrchClient, workload: str, n_agents: int,
                     run_tag: str, res: ScalingResult, cfg: Dict[str, Any],
                     daemon_res: DaemonResources):
    """The scaling measurement: N agents issuing invocations concurrently.

    The graph_stats brackets and the daemon-resource window cover the WHOLE
    phase (all repeats), so edges-per-invocation and cpu-per-invocation are
    ratios over the same denominator rather than a per-repeat average of
    ratios.
    """
    repeats = cfg["repeats"]
    invocations = cfg["invocations"]
    warmup = min(2, invocations)
    graph_before = obs.graph_stats()

    with daemon_res.window() as win:
        for rep in range(repeats):
            seed_workspace(workload, n_agents)
            handles = open_agents(n_agents, f"{run_tag}-t{rep}")
            live = live_agents(handles)
            res.open_ns.extend(float(h["open_ns"]) for h in live)
            if len(live) != n_agents:
                failed = [h["error"] for h in handles if h.get("error")]
                res.errors.append(f"throughput rep{rep}: opened "
                                  f"{len(live)}/{n_agents}: {failed[:3]}")
            try:
                if not live:
                    continue
                t0 = time.perf_counter()
                with ThreadPoolExecutor(max_workers=len(live)) as pool:
                    futures = [pool.submit(_agent_commit_loop, h, workload,
                                           n_agents, warmup, invocations)
                               for h in live]
                    outs = [f.result() for f in futures]
                wall = time.perf_counter() - t0

                # Epochs whose commit never returned ok: how long the parked
                # group took to leave the graph IS the finalization wait, since
                # no member of an SCC may publish before all of them authorized.
                unresolved = [e for o in outs for e in o["unresolved"]]
                if unresolved:
                    gone, wait_ns, states = obs.wait_epochs_gone(
                        unresolved, timeout=30.0)
                    res.finalization_wait_ns.append(float(wait_ns))
                    if not gone:
                        res.errors.append(
                            f"rep{rep}: {len(unresolved)} epoch(es) never left "
                            f"the graph (last states {states[:4]})")

                completed = sum(o["ok"] for o in outs)
                res.wall_s.append(wall)
                res.invocations_ok.append(completed)
                res.throughput.append(completed / wall if wall > 0 else 0.0)
                res.pending_commits += sum(o["pending"] for o in outs)
                for o in outs:
                    res.begin_ns.extend(o["begin_ns"])
                    res.run_ns.extend(o["run_ns"])
                    res.commit_ns.extend(o["commit_ns"])
                    res.invocation_ns.extend(o["invocation_ns"])
                    res.commit_attempts.extend(o["commit_attempts"])
                    _extend_timings(res.begin_timings, o["begin_timings"])
                    _extend_timings(res.commit_timings, o["commit_timings"])
                    res.errors.extend(o["errors"][:3])
                print(f"    [{workload}/n={n_agents}] rep {rep+1}/{repeats}: "
                      f"{completed}/{n_agents*invocations} invocations in "
                      f"{wall:.2f}s -> {res.throughput[-1]:.1f} inv/s",
                      flush=True)
            finally:
                close_agents(handles)

    res.graph = graph_delta(graph_before, obs.graph_stats())
    res.resources = summarize(win.result)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3: rollback latency at scale
# ═══════════════════════════════════════════════════════════════════════════

# Under a SHARED workload the rollback phase runs every agent's
# begin -> run -> undo loop concurrently over the same files, so one agent's
# cascading rollback routinely undoes an epoch (or a resolved version) that
# another agent is mid-`cat`/`echo` on. ShadowFS then FAILS CLOSED on that
# in-flight operation instead of serving a version that no longer exists:
#   * epochForCtx -> EIO    (the cgroup lost its active epoch; logged as
#                            "epoch attribution failed")
#   * Open/Resolve -> EIO   ("resolved version N disappeared while recording
#                            read dependency")
#   * trackedHandle.dead() -> EBADF (the open handle's version was force-closed)
# So an EIO/EBADF on a shared-workload setup command is the workload's DESIGNED
# worst case surfacing as a correctly-refused I/O -- not a malfunction. Lumping
# it into the same count as a genuine failure (a refused rollback, a dropped
# socket, a timeout) made the contended rows read as broken when the system was
# behaving exactly as specified. The two are therefore tallied apart.
#
# Two guards keep the split honest:
#   1. `independent` is EXCLUDED -- its agents touch disjoint files, so no
#      foreign cascade can reach them; an EIO there is a real bug and must stay
#      a genuine error, never be excused as a collision.
#   2. Text without an EIO/EBADF signature defaults to GENUINE, so an
#      unrecognised failure is always surfaced. The split can under-count
#      collisions; it can never mask a real error.
# The markers span the C and zh_CN locales because strerror() text is the only
# channel the shell's non-zero exit gives us. The zh_CN strings below are
# glibc's ACTUAL strerror() output, verified against a live run -- in particular
# EBADF is "错误的文件描述符", NOT a literal "坏文件描述符" translation
# (guessing that once mis-filed a real EBADF collision as a genuine error).
_CASCADE_COLLISION_MARKERS = (
    "Input/output error",   # EIO   (C/en)
    "输入/输出错误",          # EIO   (zh_CN)
    "Bad file descriptor",  # EBADF (C/en)
    "错误的文件描述符",           # EBADF (zh_CN)
)


def _is_cascade_collision(workload: str, message: str) -> bool:
    """True iff `message` is the EXPECTED fail-closed EIO/EBADF of a concurrent
    cascade undoing this agent's epoch/version under a shared workload.

    See _CASCADE_COLLISION_MARKERS for why this is expected, and why
    `independent` and unrecognised text are deliberately NOT excused.
    """
    if workload == "independent":
        return False
    return any(m in message for m in _CASCADE_COLLISION_MARKERS)


def _agent_rollback_loop(h: Dict[str, Any], workload: str, n_agents: int,
                         invocations: int,
                         first_epoch_open: bool = True) -> Dict[str, Any]:
    """One agent's rollback loop: undo the open graph, then begin → run → undo.

    Rollback cannot be measured in the commit phase -- an epoch is either
    accepted or undone, never both -- so it gets its own phase over the same
    deterministic graph. A failed setup is counted, not fatal, and is split two
    ways: under contention a cascade from another agent routinely undoes this
    epoch mid-`cat`, which ShadowFS answers with a fail-closed EIO/EBADF -- the
    workload's designed worst case, tallied as an expected `collision` -- while
    anything else (a refused rollback, a dropped socket) stays a genuine `error`.
    See _is_cascade_collision.

    `first_epoch_open` is correctness, not a shortcut. `build_open_graph`
    leaves every agent's epoch open on purpose -- ShadowFS records a read-from
    edge only against a version that is still live and unfinalized -- and the
    orchestrator releases an agent's barrier slot only on a commit or a
    rollback. So beginning a fresh epoch before undoing the open one queues
    behind itself for the full 30s barrier timeout, on every iteration, and the
    phase returns zero samples while looking merely slow. Undoing the epoch
    that is already open is also the measurement this phase exists for: it is
    the one that cascades through the graph that was just built.
    """
    out: Dict[str, Any] = {"rollback_ns": [], "rollback_timings": {},
                           "affected": [], "failed": 0, "errors": [],
                           "collisions": 0, "collision_samples": []}
    for k in range(invocations):
        began = False
        if k > 0 or not first_epoch_open:
            try:
                begin_agent_epoch(h)
                began = True
                run_agent_commands(
                    h, invocation_commands(workload, h["idx"], n_agents,
                                           1000 + k))
            except Exception as e:  # noqa: BLE001
                msg = f"agent{h['idx']} rb{k} setup: {e}"
                # A concurrent cascade undoing this epoch surfaces as a
                # fail-closed EIO/EBADF on the setup `cat`/`echo`; under a
                # shared workload that is the designed worst case, not a
                # malfunction, so tally it apart from genuine failures.
                if _is_cascade_collision(workload, msg):
                    out["collisions"] += 1
                    out["collision_samples"].append(msg)
                else:
                    out["failed"] += 1
                    out["errors"].append(msg)
                # begin_epoch CLAIMED this agent's orchestrator barrier slot,
                # and the orchestrator frees it only on a commit or a rollback
                # of that epoch. A command can fail AFTER the epoch is open --
                # under contention the usual cause is a `cat` returning EIO
                # because another agent's cascade rollback already undid this
                # epoch -- and `continue`ing straight past the rollback below
                # would leave the slot claimed forever. Every later call from
                # this agent then blocks on the barrier until its 30s timeout,
                # so a single failed `cat` wedges the whole phase (observed as
                # AGENT_BARRIER "still in flight" repeating for the same epoch,
                # with ShadowFS idle and healthy the entire time). Always undo
                # the epoch we opened; rolling back one a foreign cascade
                # already removed is a safe no-op that still frees the slot.
                # This iteration yields no measurement either way.
                if began:
                    try:
                        h["client"].request({
                            "action": "session_rollback_epoch",
                            "session_id": h["session_id"],
                            "agent_id": h["agent_id"]})
                    except Exception:  # noqa: BLE001
                        pass
                continue
        with Timer() as t:
            resp = h["client"].request({
                "action": "session_rollback_epoch",
                "session_id": h["session_id"],
                "agent_id": h["agent_id"]})
        if resp.get("status") != "ok":
            # NOT a cascade collision: ShadowFS answers an already-undone epoch
            # with status "ok" (a no-op), so a non-ok here is a genuine refusal
            # (e.g. promotion already started) and stays in `errors`.
            out["failed"] += 1
            out["errors"].append(f"agent{h['idx']} rb{k}: "
                                 f"{resp.get('message')}")
            continue
        out["rollback_ns"].append(float(t.elapsed_ns))
        out["affected"].append(len(resp.get("affected_epochs", []) or []))
        _merge_timings(out["rollback_timings"], resp.get("timings"))
    return out


def phase_rollback(obs: OrchClient, workload: str, n_agents: int,
                   run_tag: str, res: ScalingResult, cfg: Dict[str, Any]):
    """Concurrent cascading rollback over a real dependency graph."""
    invocations = cfg["rollback_invocations"]
    seed_workspace(workload, n_agents)
    handles = open_agents(n_agents, f"{run_tag}-rb")
    live = live_agents(handles)
    try:
        if not live:
            res.errors.append("rollback phase: no sessions opened")
            return
        # Same deterministic construction as the structure phase, so the
        # rollback has the edges to cascade through that this workload implies.
        res.errors.extend(build_open_graph(obs, workload, n_agents, live))
        with ThreadPoolExecutor(max_workers=len(live)) as pool:
            futures = [pool.submit(_agent_rollback_loop, h, workload,
                                   n_agents, invocations) for h in live]
            outs = [f.result() for f in futures]
        for o in outs:
            res.rollback_ns.extend(o["rollback_ns"])
            res.rollback_affected.extend(o["affected"])
            _extend_timings(res.rollback_timings, o["rollback_timings"])
            res.rollback_failed += o["failed"]
            res.errors.extend(o["errors"][:3])
            res.rollback_collisions += o["collisions"]
            res.rollback_collision_samples.extend(o["collision_samples"][:3])
    finally:
        # The same teardown the structure phase does, for the same reason: an
        # epoch that is neither committed nor rolled back stays in the graph,
        # and the release path then refuses to let the session go -- polling it
        # every two seconds for the rest of the run. The loop above normally
        # undoes all of them; this covers the run where it did not.
        for h in live:
            try:
                h["client"].request({
                    "action": "session_rollback_epoch",
                    "session_id": h["session_id"],
                    "agent_id": h["agent_id"]})
            except Exception:  # noqa: BLE001
                pass   # already undone by the loop, or by another agent's cascade
        close_agents(handles)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4: dependency-insertion latency (with control)
# ═══════════════════════════════════════════════════════════════════════════

PROBE_REL = "dep_probe.dat"


def _probe_read(obs: OrchClient, tag: str, idx: int) -> Tuple[Optional[float], Optional[str]]:
    """One throwaway agent that reads the probe file once, then undoes itself.

    Returns (run_ns, error). The whole session exists only to make that read
    happen from a FRESH epoch, because an edge is per (producer, consumer)
    epoch pair: re-reading inside one epoch would be deduplicated and measure
    nothing.

    The consumer is ROLLED BACK rather than committed, and that is forced, not
    a preference. The producer's epoch is still open -- which is exactly what
    makes this read observe a live foreign version and record an edge -- and
    dependency-safe publication will not finalize a reader ahead of the writer
    it read from. A commit here is therefore a group that can never resolve:
    the server parks it, answers `authorized_pending` after every 30s poll, and
    the client spends its whole retry budget on one `cat`. Undoing the consumer
    cascades to nothing, because nothing depends on it.
    """
    h = open_agent(idx, tag)
    if h.get("error"):
        return None, h["error"]
    try:
        begin_agent_epoch(h)
        _, run_ns = h["client"].timed_run(
            h["session_id"], f"cat {multi_fuse_path(PROBE_REL)} > /dev/null")
        return float(run_ns), None
    except Exception as e:  # noqa: BLE001
        return None, f"probe: {e}"
    finally:
        try:
            h["client"].request({
                "action": "session_rollback_epoch",
                "session_id": h["session_id"],
                "agent_id": h["agent_id"]})
        except Exception:  # noqa: BLE001
            pass   # never begun, or already undone by a cascade
        close_agents([h])


def phase_insertion(obs: OrchClient, run_tag: str, res: ScalingResult,
                    probes: int):
    """Client-visible cost of ONE read-from edge, against a control that forms none.

    A producer epoch is held OPEN while `probes` fresh agents each read its
    file once: every one of those reads observes a live foreign version and
    must create exactly one edge (WAL append + fsync + addDependency). The
    producer then finalizes, and the same read by the same number of fresh
    agents creates nothing at all. The difference of the two medians is the
    price of exact read provenance, and both edge counts are checked against
    graph_stats -- a probe that silently failed to form an edge is reported
    instead of being averaged into a latency.
    """
    create_seed_file(PROBE_REL, "probe-base")

    producer = open_agent(9000, f"{run_tag}-ip")
    if producer.get("error"):
        res.errors.append(f"insertion probe: producer open failed: "
                          f"{producer['error']}")
        return
    try:
        begin_agent_epoch(producer)
        run_agent_commands(producer, [
            f"echo 'probe-live' > {multi_fuse_path(PROBE_REL)}"])

        g0 = obs.graph_stats()
        for i in range(probes):
            ns, err = _probe_read(obs, f"{run_tag}-ie", 9100 + i)
            if err:
                res.errors.append(f"edge probe {i}: {err}")
            else:
                res.edge_run_ns.append(ns)
        g1 = obs.graph_stats()
        res.probe_probes = probes
        res.probe_edges = g1.get("edge_insertions", 0) - g0.get("edge_insertions", 0)
        res.probe_edge_insert_ns = (g1.get("edge_insert_ns", 0)
                                    - g0.get("edge_insert_ns", 0))
    finally:
        # Finalize the producer so its version is promoted and its node leaves
        # the graph: that is what turns the control read into a no-edge read.
        try:
            cresp, _, _ = commit_agent_epoch(producer)
            if cresp.get("status") != "ok":
                res.errors.append(
                    f"insertion probe: producer commit "
                    f"{cresp.get('decision') or cresp.get('message')}")
        except Exception as e:  # noqa: BLE001
            res.errors.append(f"insertion probe: producer commit: {e}")
        try:
            producer["client"].request({
                "action": "session_rollback_epoch",
                "session_id": producer["session_id"],
                "agent_id": producer["agent_id"]})
        except Exception:  # noqa: BLE001
            pass   # committed above, so there is nothing left to undo
        close_agents([producer])

    g2 = obs.graph_stats()
    for i in range(probes):
        ns, err = _probe_read(obs, f"{run_tag}-ic", 9300 + i)
        if err:
            res.errors.append(f"control probe {i}: {err}")
        else:
            res.noedge_run_ns.append(ns)
    g3 = obs.graph_stats()
    res.control_probes = probes
    res.control_edges = g3.get("edge_insertions", 0) - g2.get("edge_insertions", 0)


# ═══════════════════════════════════════════════════════════════════════════
# Configuration runner
# ═══════════════════════════════════════════════════════════════════════════

def run_configuration(workload: str, n_agents: int, cfg: Dict[str, Any],
                      daemon_res: DaemonResources) -> ScalingResult:
    """Run every requested phase for one (workload, agent-count) point."""
    res = ScalingResult(
        workload=workload, agents=n_agents, repeats=cfg["repeats"],
        invocations_per_agent=cfg["invocations"],
        rollback_invocations_per_agent=cfg["rollback_invocations"])
    t0 = time.time()
    run_tag = f"{workload[:4]}-n{n_agents}"
    print(f"\n[{workload}] agents={n_agents} phases={','.join(cfg['phases'])}")

    obs = OrchClient()
    try:
        obs.connect()
    except Exception as e:  # noqa: BLE001
        res.errors.append(f"observation client could not connect: {e}")
        res.wall_time_s = time.time() - t0
        return res
    try:
        if "structure" in cfg["phases"]:
            phase_structure(obs, workload, n_agents, run_tag, res)
            print(f"    structure: {_verdict(res.structure_ok)} "
                  f"edges={res.structure_edges} "
                  f"branch_preservation={_verdict(res.branch_preservation_ok)}",
                  flush=True)
        if "throughput" in cfg["phases"]:
            phase_throughput(obs, workload, n_agents, run_tag, res, cfg,
                             daemon_res)
        if "rollback" in cfg["phases"]:
            phase_rollback(obs, workload, n_agents, run_tag, res, cfg)
            if res.rollback_ns:
                print(f"    rollback: median="
                      f"{statistics.median(res.rollback_ns)/1e6:.2f}ms "
                      f"max_cascade={max(res.rollback_affected) if res.rollback_affected else 0} "
                      f"failed={res.rollback_failed} "
                      f"collisions={res.rollback_collisions}", flush=True)
        if "insertion" in cfg["phases"]:
            phase_insertion(obs, run_tag, res, cfg["probe_repeats"])
            lat = res.insertion_latency_ns
            tail = f"delta={lat/1e3:.1f}us" if lat is not None else "delta=n/a"
            print(f"    insertion: edges {res.probe_edges}/{res.probe_probes} "
                  f"control {res.control_edges}/{res.control_probes} {tail}",
                  flush=True)
    except KeyboardInterrupt:
        raise
    except Exception as e:  # noqa: BLE001
        res.errors.append(f"configuration failed: {e}")
        traceback.print_exc()
    finally:
        cleanup_multi_dir()
        obs.close()
    res.wall_time_s = time.time() - t0
    if res.errors:
        print(f"    errors: {len(res.errors)} (first: {res.errors[0][:120]})",
              flush=True)
    if res.rollback_collisions:
        print(f"    cascade collisions (expected fail-closed EIO/EBADF): "
              f"{res.rollback_collisions}", flush=True)
    return res


# ═══════════════════════════════════════════════════════════════════════════
# Prerequisites, output, main
# ═══════════════════════════════════════════════════════════════════════════

def _is_fuse_mounted(mount_point: str) -> bool:
    """Check /proc/mounts, not os.path.isdir(): calls on a FUSE mount point can
    hang or lie while the daemon is not yet responsive."""
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == mount_point:
                    return True
    except OSError:
        pass
    return False


def check_prerequisites() -> List[str]:
    errors = []
    if not RUN_EXPERIMENTS:
        errors.append("Set SHADOW_RUN_RQ3_EXPERIMENTS=1 to run experiments")
    orch_sock = os.environ.get("SHADOW_ORCH_SOCK", "/tmp/shadow-orch.sock")
    if not os.path.exists(orch_sock):
        errors.append(f"Orchestrator socket not found: {orch_sock}")
    if not _is_fuse_mounted(SHADOWFS_MNT):
        errors.append(f"ShadowFS FUSE not mounted at: {SHADOWFS_MNT}")
    return errors


def save_results(results: List[ScalingResult], output_dir: str,
                 cfg: Dict[str, Any]) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "multi_agent_scaling.json")
    data = {
        "experiment": "rq3_multi_agent_scaling",
        "timestamp": time.time(),
        "config": {k: v for k, v in cfg.items() if k != "phases"} | {
            "phases": list(cfg["phases"])},
        "host": {
            "cpus": os.cpu_count(),
            "max_concurrent_cgroups": MAX_AGENTS,
        },
        "configurations": [r.to_dict() for r in results],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n[save] Results written to {path}")
    return path


def _median_or_none(samples: List[float]) -> Optional[float]:
    return statistics.median(samples) if samples else None


def _verdict(ok: Optional[bool]) -> str:
    return {True: "OK", False: "FAIL", None: "-"}[ok]


def _fmt(val: Optional[float], spec: str = ".2f") -> str:
    return format(val, spec) if val is not None else "-"


def print_summary(results: List[ScalingResult]):
    """One row per configuration, with speedup against that workload's smallest
    agent count -- the near-linear-scaling claim needs a baseline, not a slope."""
    baselines: Dict[str, float] = {}
    for r in sorted(results, key=lambda x: (x.workload, x.agents)):
        thpt = _median_or_none(r.throughput)
        if thpt is not None and r.workload not in baselines:
            baselines[r.workload] = thpt

    print("\n" + "\u2550" * 138)
    print("  SUMMARY \u2014 Experiment A: Multi-Agent Scaling")
    print("\u2550" * 138)
    print(f"{'Workload':<17}{'N':>4}{'inv/s':>9}{'spd':>7}{'eff%':>7}"
          f"{'begin':>9}{'commit':>9}{'authz-fin':>11}{'rollback':>10}"
          f"{'edg/inv':>9}{'FScpu%':>8}{'ORcpu%':>8}{'heapMB':>8}"
          f"{'str':>5}{'br':>5}{'coll':>6}{'err':>5}")
    print("\u2500" * 138)
    for r in results:
        thpt = _median_or_none(r.throughput)
        base = baselines.get(r.workload)
        speedup = (thpt / base) if (thpt and base) else None
        eff = (100.0 * speedup / r.agents) if speedup else None
        begin = _median_or_none(r.begin_ns)
        commit = _median_or_none(r.commit_ns)
        authz = _median_or_none(r.commit_timings.get("authz_to_finalized_ms", []))
        rb = _median_or_none(r.rollback_ns)
        epi = r.edges_per_invocation
        heap = (r.structure_graph.get("heap_alloc_bytes")
                or r.graph.get("mem_heap_alloc_bytes") or 0)
        fs_cpu = r.resources.get("shadowfs_cpu_pct") if r.resources else None
        or_cpu = r.resources.get("orchestrator_cpu_pct") if r.resources else None
        # Latencies are ns in the client samples but ms in the orchestrator's
        # own breakdown; both are printed in ms.
        print(f"{r.workload:<17}{r.agents:>4}"
              f"{_fmt(thpt, '.1f'):>9}{_fmt(speedup):>7}"
              f"{_fmt(eff, '.0f'):>7}"
              f"{_fmt(begin / 1e6 if begin else None):>9}"
              f"{_fmt(commit / 1e6 if commit else None):>9}"
              f"{_fmt(authz):>11}"
              f"{_fmt(rb / 1e6 if rb else None):>10}"
              f"{_fmt(epi):>9}"
              f"{_fmt(fs_cpu, '.0f'):>8}{_fmt(or_cpu, '.0f'):>8}"
              f"{heap / 1048576.0:>8.1f}"
              f"{_verdict(r.structure_ok):>5}"
              f"{_verdict(r.branch_preservation_ok):>5}"
              f"{r.rollback_collisions:>6}"
              f"{len(r.errors):>5}")
    print("\u2500" * 138)
    print("  latency columns are medians in ms; authz-fin is the orchestrator's")
    print("  authz_to_finalized_ms (authorization complete -> group published);")
    print("  edg/inv = edge_insertions / measured invocations; heapMB = ShadowFS")
    print("  Go heap with every epoch of the structure phase open.")
    print("  coll = expected fail-closed EIO/EBADF: a concurrent cascade undid")
    print("  this agent's epoch/version mid-setup (shared workloads, by design);")
    print("  err = genuine failures only (refused rollback, dropped socket, ...).")


def main():
    parser = argparse.ArgumentParser(
        description="RQ3 Experiment A: Multi-Agent Scaling")
    parser.add_argument("--output-dir", default="./results")
    parser.add_argument("--workloads", default="all",
                        help=f"comma-separated subset of {','.join(WORKLOADS)}")
    parser.add_argument("--agents", default="",
                        help="comma-separated agent counts "
                             "(default: 1,2,4,8,16,32)")
    parser.add_argument("--repeats", type=int, default=None)
    parser.add_argument("--invocations", type=int, default=None,
                        help="measured invocations per agent per repeat")
    parser.add_argument("--rollback-invocations", type=int, default=None)
    parser.add_argument("--probe-repeats", type=int, default=None,
                        help="reads per side of the insertion probe")
    parser.add_argument("--phases", default="all",
                        help=f"comma-separated subset of {','.join(PHASES)}")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.workloads == "all":
        workloads = list(WORKLOADS)
    else:
        workloads = [w.strip() for w in args.workloads.split(",") if w.strip()]
        unknown = [w for w in workloads if w not in WORKLOADS]
        if unknown:
            parser.error(f"unknown workload(s): {unknown}")

    if args.agents:
        agents = [int(x) for x in args.agents.split(",") if x.strip()]
    else:
        agents = list(QUICK_AGENTS if args.quick else FULL_AGENTS)
    if any(a < 1 for a in agents):
        parser.error("agent counts must be >= 1")
    over = [a for a in agents if a > MAX_AGENTS]
    if over:
        parser.error(f"agent counts {over} exceed the {MAX_AGENTS} concurrent "
                     f"cgroup limit of ShadowProc")

    if args.phases == "all":
        phases = list(PHASES)
    else:
        phases = [p.strip() for p in args.phases.split(",") if p.strip()]
        unknown = [p for p in phases if p not in PHASES]
        if unknown:
            parser.error(f"unknown phase(s): {unknown}")

    quick = args.quick
    cfg: Dict[str, Any] = {
        "workloads": workloads,
        "agents": agents,
        "phases": phases,
        "repeats": args.repeats if args.repeats is not None else (
            QUICK_REPEATS if quick else FULL_REPEATS),
        "invocations": args.invocations if args.invocations is not None else (
            QUICK_INVOCATIONS if quick else FULL_INVOCATIONS),
        "rollback_invocations": (args.rollback_invocations
                                 if args.rollback_invocations is not None else (
                                     QUICK_ROLLBACK_INVOCATIONS if quick
                                     else FULL_ROLLBACK_INVOCATIONS)),
        "probe_repeats": args.probe_repeats if args.probe_repeats is not None else (
            QUICK_PROBE_REPEATS if quick else FULL_PROBE_REPEATS),
    }

    if args.dry_run:
        print("\n[DRY RUN] Would execute:")
        for w in workloads:
            for n in agents:
                per_cfg = (n * cfg["invocations"] * cfg["repeats"]
                           if "throughput" in phases else 0)
                print(f"  {w:<17} agents={n:<3} phases={phases} "
                      f"measured_invocations={per_cfg} "
                      f"rollback_invocations="
                      f"{n * cfg['rollback_invocations'] if 'rollback' in phases else 0} "
                      f"insertion_probes="
                      f"{2 * cfg['probe_repeats'] if 'insertion' in phases else 0}")
        print(f"  repeats={cfg['repeats']} invocations/agent={cfg['invocations']}")
        sys.exit(0)

    errors = check_prerequisites()
    if errors:
        print("PREREQUISITE FAILURES:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    print("═" * 78)
    print("  RQ3 Experiment A — Multi-Agent Scaling")
    print(f"  workloads={workloads} agents={agents}")
    print(f"  repeats={cfg['repeats']} invocations/agent={cfg['invocations']} "
          f"phases={phases}")
    print("═" * 78)

    daemon_res = DaemonResources()
    pids = daemon_res.discover()
    print(f"[daemons] {pids}")
    missing = daemon_res.missing()
    if missing:
        print(f"[daemons] WARNING: not found -> {missing}; their CPU/RSS "
              f"columns will be empty (pidfiles are written by start_and_run.sh)")

    ensure_multi_dirs()
    results: List[ScalingResult] = []
    try:
        for workload in workloads:
            for n in agents:
                results.append(
                    run_configuration(workload, n, cfg, daemon_res))
    except KeyboardInterrupt:
        print("\n[interrupted]")

    if results:
        save_results(results, args.output_dir, cfg)
        print_summary(results)
    cleanup_multi_dir()
    print("\n[done] Multi-agent scaling experiment complete.")


if __name__ == "__main__":
    main()
