#!/usr/bin/env python3
"""
RQ3 Experiment B: Dependency Graph Shape Scaling.

Measures what the causal DAG COSTS as its SHAPE grows. Every graph node is one
session (one cgroup, one epoch), so the x-axis of every curve below is the
number of DEPENDENCY NODES -- the number of concurrent agents is held fixed by
construction and is varied separately in multi_agent_scaling.py (Experiment A).

  D1: Chain — A → B → … → N, 2/4/8/16/32/64 nodes. Node[i] writes file[i] and
      node[i+1] reads it, so every link is a real cross-epoch read-from edge.
      Measured TWICE per size:
        decision=allow      whole-chain publication (group finalization)
        decision=root-deny  CASCADING ROLLBACK of all N nodes from the root
      Those two rows are the finalization-latency and rollback-latency curves
      against node count.
  D2: Fan-out / Fan-in — one producer feeding N consumers, and N producers
      converging on one consumer.
  D3: SCC — a cycle of N epochs (2/4/8/16/32), measured on the UNDO path:
      denying one member atomically rolls the whole component back.
  D4: Concurrent agents — N agents each depending on a shared root epoch, all
      committing at once. Publication contention rather than graph shape.
  D5: Authorization decisions — allow / root-deny / middle-deny at a fixed chain
      length: the cost of a decision as a function of its POSITION in the graph.
  D6: Diamond — root → {W middles} → sink. The generalized diamond (W=2 is the
      A/B/C/D case the correctness suite already covers): fan-out and fan-in in
      one graph, so a root rollback must cascade down both arms and back up.
  D7: SCC publication — the same cycles as D3, measured on the PUBLISH path:
      all N members authorize concurrently and none of them may appear until all
      of them have. Reports SCC detection cost, the finalization wait each
      member experiences, and the graph-revalidation rate.

Every configuration additionally reports, from ShadowFS `graph_stats` and from
the orchestrator's per-phase `timings`:
  graph shape at full population  epochs / edges / versions / SCC counts,
                                  sampled with EVERY node's epoch still open
  metadata memory                 ShadowFS Go heap at that same instant. The
                                  heap is whole-process, so its intercept
                                  includes unrelated allocations; the SLOPE
                                  across sizes is the marginal cost of one
                                  dependency node, which is what a reviewer
                                  needs and what the summarizer plots.
  edges per invocation            edge_insertions / measured session_run calls
  SCC detection                   scc_computations, scc_compute_ns, max_scc_size
  graph revalidation              ShadowFS finalize_rejected_toctou plus the
                                  orchestrator's graph_revalidations stamp
  daemon CPU / RSS                shadowfs, shadowproc, orchestrator

Ceiling on the node count
-------------------------
ShadowProc's BPF slot table caps CONCURRENT live cgroups at 64
(`add_cgroup: Maximum 64 concurrent cgroups supported`), and one graph node
holds one cgroup for the whole repeat. A 64-node chain therefore sits exactly
at a hard system limit; larger graphs cannot be reached end-to-end on this host
and are not attempted. Sizes above MAX_NODES are rejected at argument parsing.

Usage:
    SHADOW_RUN_RQ3_EXPERIMENTS=1 python3 dep_graph_scalability.py [options]

Options:
    --output-dir DIR    Output directory (default: ./results)
    --dimension D       Run only dimension D (1-7) or "all" (default: all)
    --repeats N         Repeats per configuration (default: 10)
    --quick             Use reduced sizes for quick testing
    --dry-run           Print configuration without running

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
import threading
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

# Work directory under the FUSE mount (dependency files live here)
DEP_WORK_FUSE = os.path.join(SHADOWFS_MNT, "rq3-dep")
DEP_WORK_ORIG = os.path.join(SHADOWFS_ORIG, "rq3-dep")

# Default policy: allow all (for benchmarks that commit)
ALLOW_ALL_OPS = [{"event_type": "*", "action": "allow", "path_pattern": "/"}]

# One graph node = one session = one cgroup held for the whole repeat, and
# ShadowProc caps concurrent live cgroups at 64. Beyond this, session_open
# fails outright rather than degrading a measurement, so the ceiling is checked
# at argument parsing instead of being discovered mid-run.
MAX_NODES = 64

# An SCC member that authorizes before its siblings gets `authorized_pending`:
# the component may not publish until all of them have. The client retries,
# because the orchestrator's own background retry loop ticks every 2 s and
# would make every wait measurement a reading of that interval rather than of
# the graph. The retry count is itself a result (see commit_attempts).
PENDING_RETRY_LIMIT = 150
PENDING_RETRY_SLEEP_S = 0.02
# The attempt cap is not a time bound. Each attempt blocks in the orchestrator's
# own finalize poll for up to 30s before it can answer `authorized_pending`
# again, so 150 attempts is seventy-five minutes of silence on ONE commit --
# longer than a whole dimension sweep, and indistinguishable from a hang.
# Parking is normal for an SCC member that authorized before its siblings and
# resolves within a poll or two; the budget only fires on a component that will
# never publish, which is a result to report rather than one to wait out.
PENDING_RETRY_BUDGET_S = 120.0

# Poll granularity/timeout for wait_epochs_gone. The interval quantizes the
# drain measurement from below by at most one poll.
GONE_POLL_INTERVAL_S = 0.005
GONE_TIMEOUT_S = 120.0


# ═══════════════════════════════════════════════════════════════════════════
# Result structures
# ═══════════════════════════════════════════════════════════════════════════

def _ns_stats(name: str, samples: List[float]) -> Optional[Dict[str, Any]]:
    """Stats over nanosecond samples; None when a phase produced nothing."""
    if not samples:
        return None
    return compute_stats(name, samples).to_dict()


def _ms_stats(name: str, samples: List[float]) -> Optional[Dict[str, Any]]:
    """Stats over millisecond samples, reported through the same schema.

    Scaled to ns so compute_stats' percentile/CI code is reused unchanged and
    the *_ms / *_ns key suffixes mean the same thing across both experiments.
    """
    if not samples:
        return None
    return compute_stats(name, [s * 1e6 for s in samples]).to_dict()


# Timing keys that are COUNTS, not durations. The orchestrator stamps them into
# the same dict as its phase timings, so they travel together, but reporting
# them under a *_ms key would turn "revalidated twice" into "took 2 ms".
TIMING_COUNT_KEYS = frozenset({"graph_revalidations", "finalize_polls"})


def _merge_timings(dst: Dict[str, List[float]], src: Optional[Dict[str, Any]]):
    """Accumulate every numeric field the orchestrator stamped.

    Keys are discovered, not hardcoded, so a phase the orchestrator starts
    stamping later lands in the results file instead of being dropped.
    """
    for key, val in (src or {}).items():
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            continue
        dst.setdefault(key, []).append(float(val))


def _extend_timings(dst: Dict[str, List[float]],
                    src: Dict[str, List[float]]):
    """Merge one repeat's accumulated timing samples into the configuration's."""
    for key, vals in (src or {}).items():
        dst.setdefault(key, []).extend(vals)


@dataclass
class DepGraphResult:
    """Result for one dependency graph experiment configuration."""
    dimension: str          # D1-D7
    topology: str           # chain, fan-out, fan-in, scc, diamond, concurrent
    size: int              # number of graph nodes (epochs)
    decision: str = "allow"  # allow, root-deny, middle-deny, rollback-cascade,
                             # publish

    # What the timed interval measured. `finalize_ns` has always been "the
    # measured resolution operation" (D3 put a cascade rollback in it), so it
    # stays that way; this field says which operation, letting a summarizer
    # draw the publication and the rollback curve from one field without
    # guessing from the decision string.
    resolution_op: str = "commit"   # commit | cascade-rollback | decision

    # Measurements (nanoseconds)
    setup_ns: List[float] = field(default_factory=list)
    finalize_ns: List[float] = field(default_factory=list)
    total_ns: List[float] = field(default_factory=list)
    per_epoch_finalize_ns: List[float] = field(default_factory=list)
    # For a rollback resolution these hold the SAME samples as finalize_ns,
    # under the single name a cross-dimension rollback curve needs.
    rollback_ns: List[float] = field(default_factory=list)

    # Per-node client latencies (nanoseconds)
    open_ns: List[float] = field(default_factory=list)
    begin_ns: List[float] = field(default_factory=list)
    run_ns: List[float] = field(default_factory=list)
    commit_ns: List[float] = field(default_factory=list)

    # Orchestrator per-phase breakdowns (milliseconds), keyed as stamped.
    begin_timings: Dict[str, List[float]] = field(default_factory=dict)
    commit_timings: Dict[str, List[float]] = field(default_factory=dict)
    rollback_timings: Dict[str, List[float]] = field(default_factory=dict)

    # Atomic publication of a component: how many attempts had to park, and how
    # long each member waited from its first authorization to publication.
    pending_commits: int = 0
    commit_attempts: List[int] = field(default_factory=list)
    finalization_wait_ns: List[float] = field(default_factory=list)
    drain_ns: List[float] = field(default_factory=list)

    # Dependency verification
    affected_epochs: int = 0  # affected cgroup count from get_affected
    affected_samples: List[int] = field(default_factory=list)
    # Cascade sizes reported BY a rollback that actually happened, kept apart
    # from affected_samples (a dry-run get_affected during verification): one
    # is what the graph said would be undone, the other is what was undone.
    rollback_affected: List[int] = field(default_factory=list)
    topo_checks: List[bool] = field(default_factory=list)  # per-repeat check

    # Graph observation. `graph` is the counter delta over the WHOLE
    # configuration (all repeats), so anything per-repeat must be divided by
    # `repeats`; `graph_peak` is the shape sampled with every node's epoch
    # still open, which is the only instant the graph is fully populated.
    invocations: int = 0
    graph: Dict[str, Any] = field(default_factory=dict)
    graph_peak: Dict[str, Any] = field(default_factory=dict)
    resources: Dict[str, Any] = field(default_factory=dict)

    @property
    def topo_verified(self) -> bool:
        """True iff ALL repeats passed the precise set-equality check."""
        return (len(self.topo_checks) == self.repeats
                and all(self.topo_checks))

    @property
    def node_count(self) -> int:
        """Number of graph nodes this configuration actually built.

        `size` is the SHAPE PARAMETER (chain length, fan width, SCC size), which
        for fan-out/fan-in/diamond is not the node count: those add a root
        and/or a sink. The node-count axis of the scaling plot has to use this,
        and it is cross-checked against graph_peak['epochs'] as sampled from
        ShadowFS itself.
        """
        if self.topology in ("fan-out", "fan-in", "concurrent"):
            return self.size + 1
        if self.topology == "diamond":
            return self.size + 2
        return self.size

    @property
    def edges_per_invocation(self) -> Optional[float]:
        """Graph edges created per measured invocation.

        Says whether the graph grows with the work issued or with the square of
        the node count -- the difference between a DAG that tracks real data
        flow and one that invents edges.
        """
        if not self.invocations:
            return None
        return self.graph.get("edge_insertions", 0) / float(self.invocations)

    @property
    def heap_alloc_bytes(self) -> int:
        return int(self.graph_peak.get("heap_alloc_bytes") or 0)

    @property
    def metadata_bytes_per_node(self) -> Optional[float]:
        """ShadowFS heap at full population, per dependency node.

        A ratio, not a marginal cost: the heap carries unrelated allocations,
        so the per-node figure is an upper bound whose usefulness is in how it
        moves across sizes (see the module docstring).
        """
        if not self.size or not self.heap_alloc_bytes:
            return None
        return self.heap_alloc_bytes / float(self.size)

    @property
    def graph_revalidations(self) -> int:
        """Orchestrator-visible re-preparations (begin_finalize generation
        mismatch). The ShadowFS-side complement is
        graph['finalize_rejected_toctou']."""
        vals = self.commit_timings.get("graph_revalidations") or []
        return int(sum(vals))

    # Metadata
    repeats: int = 0
    errors: List[str] = field(default_factory=list)
    wall_time_s: float = 0.0

    # Guards the fields that are read-modify-write rather than append. D4 and
    # D7 authorize up to 64 members concurrently, and a lost increment there
    # would understate the parked-commit count -- the headline number for
    # atomic SCC publication. list.append is already atomic under the GIL, so
    # only these two need it.
    _ctr_lock: Any = field(default_factory=threading.Lock,
                           repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        stats = {}
        for key in ["setup_ns", "finalize_ns", "total_ns",
                    "per_epoch_finalize_ns", "rollback_ns", "open_ns",
                    "begin_ns", "run_ns", "commit_ns",
                    "finalization_wait_ns", "drain_ns"]:
            s = _ns_stats(key, getattr(self, key))
            if s is not None:
                stats[key] = s
        for name, series in (("begin", self.begin_timings),
                             ("commit", self.commit_timings),
                             ("rollback", self.rollback_timings)):
            for key, vals in sorted(series.items()):
                if key in TIMING_COUNT_KEYS:
                    stats[f"{name}_counts.{key}"] = {
                        "mean": statistics.fmean(vals),
                        "max": max(vals),
                        "total": sum(vals),
                        "n": len(vals),
                    }
                    continue
                s = _ms_stats(f"{name}.{key}", vals)
                if s is not None:
                    stats[f"{name}_timings_ms.{key}"] = s

        d = {
            "dimension": self.dimension,
            "topology": self.topology,
            "size": self.size,
            "nodes": self.node_count,
            "decision": self.decision,
            "resolution_op": self.resolution_op,
            "repeats": self.repeats,
            "affected_epochs": self.affected_epochs,
            "topo_verified": self.topo_verified,
            "errors": self.errors[:10],
            "error_count": len(self.errors),
            "wall_time_s": self.wall_time_s,
            "stats": stats,
            "raw_finalize_ns": self.finalize_ns,
        }
        d["affected_mean"] = (
            statistics.fmean(self.affected_samples)
            if self.affected_samples else None)
        d["affected_max"] = (max(self.affected_samples)
                             if self.affected_samples else None)
        d["rollback_affected_mean"] = (
            statistics.fmean(self.rollback_affected)
            if self.rollback_affected else None)
        d["rollback_affected_max"] = (max(self.rollback_affected)
                                      if self.rollback_affected else None)
        d["pending_commits"] = self.pending_commits
        d["commit_attempts_mean"] = (
            statistics.fmean(self.commit_attempts) if self.commit_attempts
            else None)
        d["commit_attempts_max"] = (max(self.commit_attempts)
                                    if self.commit_attempts else None)
        d["invocations"] = self.invocations
        d["edges_per_invocation"] = self.edges_per_invocation
        d["graph_revalidations"] = self.graph_revalidations
        d["graph"] = self.graph
        d["resources"] = self.resources
        # The full-population shape is what the node-count axis refers to, so
        # it is broken out instead of being buried in the delta dict.
        d["graph_peak"] = {
            k: self.graph_peak.get(k)
            for k in ("epochs", "edges", "versions", "objects",
                      "scc_count", "cyclic_scc_count", "max_scc_size",
                      "active_groups", "heap_alloc_bytes", "heap_inuse_bytes",
                      "sys_bytes", "goroutines")
        } if self.graph_peak else {}
        d["metadata_bytes_per_node"] = self.metadata_bytes_per_node
        return d


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def ensure_dep_dirs():
    """Create dependency work directories."""
    os.makedirs(DEP_WORK_ORIG, exist_ok=True)


def cleanup_dep_dir():
    """Remove all files in the dependency work directory."""
    import shutil
    if os.path.isdir(DEP_WORK_ORIG):
        shutil.rmtree(DEP_WORK_ORIG, ignore_errors=True)
    os.makedirs(DEP_WORK_ORIG, exist_ok=True)


def dep_fuse_path(rel: str) -> str:
    return os.path.join(DEP_WORK_FUSE, rel)


def create_seed_file(rel_path: str, content: str = "seed"):
    """Create a seed file in the orig (backing store) directory.

    Files MUST pre-exist in the backing store so FUSE Lookup succeeds
    when the consumer epoch opens them. Without this, the VFS returns
    ENOENT before reaching the Open handler where Resolve() records
    the read-from dependency edge.
    """
    full = os.path.join(DEP_WORK_ORIG, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)


@dataclass
class EpochNode:
    """A single epoch node in the dependency graph (one session = one epoch).

    `client` is set only for nodes that own their connection (D7, where the
    members must commit concurrently). Everywhere else it is None and the node
    is driven over the configuration's shared connection.
    """
    node_id: str
    session_id: str
    cgroup_id: str
    epoch_id: str
    agent_id: str
    client: Optional[OrchClient] = None

    def conn(self, shared: OrchClient) -> OrchClient:
        """The connection this node's RPCs must go over."""
        return self.client or shared


def open_epoch_node(client: OrchClient, node_id: str, run_tag: str,
                    res: Optional[DepGraphResult] = None,
                    own_client: bool = False) -> EpochNode:
    """Open a session and begin an epoch for one graph node.

    Each graph node gets its own session (hence its own cgroup and epoch),
    ensuring ShadowFS tracks it as an independent vertex in the dep graph.

    session_open and session_begin_epoch are timed and, when `res` is given,
    recorded there: admitting one more node into the graph is a real cost of
    graph size, and the orchestrator's own breakdown of begin (agent barrier,
    graph-sequence-lock wait, ShadowFS begin_epoch, ShadowProc fork) is what
    says WHICH part of it grows.

    own_client=True gives the node a private connection, which is the only way
    to commit several nodes concurrently: the protocol is line-oriented per
    connection, so two threads on one socket would read each other's replies.
    """
    agent_id = f"dep-{run_tag}-{node_id}"
    conn = OrchClient() if own_client else client
    if own_client:
        conn.connect()
    try:
        sess, open_ns = conn.timed_open(agent_id)
        sid = sess["session_id"]
        cg_id = sess["cgroup_id"]
        epoch_resp, begin_ns = conn.timed_begin_epoch(sid, agent_id=agent_id)
    except Exception:
        if own_client:
            conn.close()
        raise
    if res is not None:
        res.open_ns.append(float(open_ns))
        res.begin_ns.append(float(begin_ns))
        _merge_timings(res.begin_timings, epoch_resp.get("timings"))
    return EpochNode(node_id=node_id, session_id=sid, cgroup_id=cg_id,
                     epoch_id=epoch_resp.get("epoch_id", ""),
                     agent_id=agent_id,
                     client=conn if own_client else None)


def run_cmd(client: OrchClient, node: EpochNode, command: str,
            res: Optional[DepGraphResult] = None) -> Dict[str, Any]:
    """Run one command inside a node's live epoch, timed and exit-code checked.

    A non-zero exit raises rather than being recorded as a fast successful
    invocation: an edge that never formed because `cat` failed would otherwise
    show up only as a topology mismatch several RPCs later.
    """
    conn = node.conn(client)
    resp, ns = conn.timed_run(node.session_id, command)
    if res is not None:
        res.run_ns.append(float(ns))
        with res._ctr_lock:
            res.invocations += 1
    rc = resp.get("exit_code", 0)
    if rc != 0:
        out = str(resp.get("output", resp.get("stdout", "")))[:160]
        raise RuntimeError(
            f"node {node.node_id}: command exited {rc}: {command!r} -> {out!r}")
    return resp


def commit_succeeded(resp: Dict[str, Any]) -> bool:
    """True if this commit response means the epoch is published.

    `already finalized` is SUCCESS, not an error: it means a sibling member's
    commit published the whole component first, which is exactly what atomic
    SCC publication promises. Reporting it as a failure would make the
    worst-case contention result look like a correctness break.
    """
    if resp.get("status") == "ok":
        return True
    return "already finalized" in str(resp.get("message", ""))


def commit_node(client: OrchClient, node: EpochNode,
                res: Optional[DepGraphResult] = None,
                retry_pending: bool = True) -> Dict[str, Any]:
    """Commit one node's epoch; returns the last response.

    When `retry_pending` is set an `authorized_pending` reply is retried: the
    component cannot publish until every member has authorized, so a member
    that got there early parks and must come back. The orchestrator's own
    background retry loop ticks every 2 s, which would make any wait measured
    through it a reading of that interval rather than of the graph -- hence the
    client-side retry, whose attempt count is recorded as a result.

    `finalization_wait_ns` is this member's own wait: first attempt issued ->
    response that published (or found published) its component. The maximum
    over members is how long the least lucky member of an N-node SCC waited.
    """
    conn = node.conn(client)
    req = {"action": "session_commit_epoch", "session_id": node.session_id,
           "agent_id": node.agent_id, "allowed_ops": ALLOW_ALL_OPS}
    attempts = 0
    t_first = time.perf_counter_ns()
    deadline = time.monotonic() + PENDING_RETRY_BUDGET_S
    with Timer() as t:
        while True:
            attempts += 1
            resp = conn.request(req)
            if commit_succeeded(resp):
                break
            if (not retry_pending
                    or resp.get("decision") != "authorized_pending"
                    or attempts >= PENDING_RETRY_LIMIT
                    or time.monotonic() >= deadline):
                break
            time.sleep(PENDING_RETRY_SLEEP_S)
        elapsed = t.elapsed_ns
    if res is not None:
        res.commit_ns.append(float(elapsed))
        res.commit_attempts.append(attempts)
        if retry_pending:
            res.finalization_wait_ns.append(
                float(time.perf_counter_ns() - t_first))
        with res._ctr_lock:
            if attempts > 1:
                res.pending_commits += 1
            # Only a commit we actually tried to publish and could not. A
            # dimension that passes retry_pending=False, or one whose decision
            # is a denial, expects this epoch not to publish -- reporting that
            # as an error would bury the real ones.
            if retry_pending and resp.get("decision") == "authorized_pending":
                res.errors.append(
                    f"commit {node.epoch_id} still parked after {attempts} "
                    f"attempt(s) / {elapsed / 1e9:.0f}s")
            _merge_timings(res.commit_timings, resp.get("timings"))
    return resp


def commit_all(client: OrchClient, nodes: List[EpochNode],
               res: Optional[DepGraphResult] = None,
               concurrent: bool = False,
               retry_pending: bool = True) -> List[Dict[str, Any]]:
    """Commit every node, in order or all at once.

    Sequential is the right mode for an acyclic shape (topological order always
    publishes); concurrent is the only way to put N members of one SCC in the
    situation the atomicity rule actually governs.
    """
    if not concurrent:
        return [commit_node(client, n, res, retry_pending) for n in nodes]
    with ThreadPoolExecutor(max_workers=min(len(nodes), MAX_NODES)) as pool:
        futures = [pool.submit(commit_node, client, n, res, retry_pending)
                   for n in nodes]
        return [f.result() for f in futures]


def undo_node(client: OrchClient, node: EpochNode,
              res: Optional[DepGraphResult] = None,
              via: str = "deny") -> Tuple[Dict[str, Any], int]:
    """Undo one node's epoch; returns (response, elapsed_ns).

    via="deny" is the authorization-decision path (a policy refused this epoch);
    via="rollback" is the explicit one (the agent withdrew it). Both end in
    ShadowFS's RollbackWithAffected, so BOTH cascade to every dependent epoch
    inside the single call -- the elapsed time is the whole cascade, not its
    first hop, which is the only reading that makes a rollback curve mean
    anything.
    """
    action = ("session_resolve_epoch" if via == "deny"
              else "session_rollback_epoch")
    req = {"action": action, "session_id": node.session_id,
           "agent_id": node.agent_id}
    if via == "deny":
        req["decision"] = "deny"
    conn = node.conn(client)
    with Timer() as t:
        resp = conn.request(req)
        elapsed = t.elapsed_ns
    if res is not None:
        res.rollback_ns.append(float(elapsed))
        res.rollback_affected.append(
            len(resp.get("affected_epochs", []) or []))
        with res._ctr_lock:
            _merge_timings(res.rollback_timings, resp.get("timings"))
    return resp, elapsed


def record_graph_peak(res: DepGraphResult, obs: OrchClient):
    """Sample the graph with EVERY node's epoch still open.

    This is the only instant the dependency graph is fully populated: after
    publication the group's edges are dropped and its nodes removed on ack, so
    a sample taken later reports a graph that no longer exists. The largest
    population seen is kept, so a configuration whose repeats differ (a node
    that failed to open) still reports its real peak.

    Called outside every timed interval: the snapshot runs a full Tarjan sweep
    and runtime.ReadMemStats, which stops the Go world.
    """
    snap = obs.graph_stats()
    if not snap:
        return
    if snap.get("epochs", 0) >= res.graph_peak.get("epochs", -1):
        res.graph_peak = snap
    # Cross-check against the count the construction believes it built. Only a
    # SHORTFALL is reported: extra epochs would mean something else is using the
    # daemon, whereas missing ones mean the topology this configuration is
    # supposed to measure never existed.
    got = snap.get("epochs")
    if got is not None and got < res.node_count:
        res.errors.append(
            f"graph holds {got} epochs with every node open, expected at least "
            f"{res.node_count} -- the topology did not fully build")


class ConfigMeasure:
    """Brackets one configuration's repeats with graph_stats and daemon CPU/RSS.

    One window over ALL repeats, not one per repeat: edges-per-invocation and
    cpu-per-invocation then become ratios over a single shared denominator
    instead of an average of per-repeat ratios, which would weight a short
    repeat as heavily as a long one.

    A daemon it cannot find degrades a column of the results table (found=False
    plus an explanatory error) rather than aborting a run that may already have
    taken an hour.
    """

    def __init__(self, obs: OrchClient, res: DepGraphResult,
                 daemon_res: Optional[DaemonResources]):
        self.obs = obs
        self.res = res
        self.daemon_res = daemon_res
        self._before: Dict[str, Any] = {}
        self._win_cm = None
        self._win = None

    def __enter__(self) -> "ConfigMeasure":
        self._before = self.obs.graph_stats()
        if self.daemon_res is not None:
            self._win_cm = self.daemon_res.window()
            self._win = self._win_cm.__enter__()
        return self

    def __exit__(self, *exc) -> bool:
        if self._win_cm is not None:
            self._win_cm.__exit__(*exc)
            self.res.resources = summarize(self._win.result)
            self._win_cm = None
        # Sampled even when the body raised: a partial phase still did graph
        # work, and dropping its counters would understate the configuration
        # that failed rather than reporting it.
        self.res.graph = graph_delta(self._before, self.obs.graph_stats())
        return False


def verify_dependencies(client: OrchClient, nodes: List[EpochNode],
                        topology: str,
                        res: Optional[DepGraphResult] = None
                        ) -> Tuple[int, bool, List[str]]:
    """Verify cross-epoch dependencies with STRICT set-equality checks.

    Checks EVERY node's affected set against the exact expected set:
      - chain: affected(node[i]) == {cgroup[i], cgroup[i+1], ..., cgroup[N-1]}
      - fan-out: affected(root) == all; affected(each_leaf) == {leaf}
      - fan-in: affected(each_source) == {source, sink}; affected(sink) == {sink}
      - diamond: affected(root) == all; affected(mid) == {mid, sink};
                 affected(sink) == {sink}
      - scc: affected(each_node) == all
      - concurrent: affected(root) == all

    Set EQUALITY, not containment: an empty graph satisfies every "affected ⊇
    self" check, so a run that silently formed no edges would otherwise report
    a verified topology and a very flattering finalization latency.

    Returns (affected_count_from_root, topo_ok, errors).
    """
    if not nodes:
        return 0, False, ["no nodes to verify"]
    errors = []
    affected_count = 0
    topo_ok = True

    all_cgroups = {n.cgroup_id for n in nodes}

    def _get_aff(node: EpochNode) -> Optional[Set[str]]:
        try:
            resp = client.get_affected(node.cgroup_id)
            return set(resp.get("affected", []))
        except Exception as e:
            errors.append(f"get_affected({node.node_id}) failed: {e}")
            return None

    def _check(node: EpochNode, expected: Set[str], label: str):
        nonlocal topo_ok
        aff = _get_aff(node)
        if aff is None:
            topo_ok = False
            return
        if res is not None:
            res.affected_samples.append(len(aff))
        if aff != expected:
            topo_ok = False
            errors.append(
                f"{label}: affected={len(aff)} expected={len(expected)} "
                f"missing={len(expected - aff)} extra={len(aff - expected)}")

    if topology == "chain":
        # affected(node[i]) == {node[i], node[i+1], ..., node[N-1]}
        for i, node in enumerate(nodes):
            expected = {nodes[j].cgroup_id for j in range(i, len(nodes))}
            _check(node, expected, f"chain[{i}]")
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)

    elif topology == "fan-out":
        # affected(root) == all; affected(each leaf) == {leaf}
        _check(nodes[0], all_cgroups, "fan-out[root]")
        for leaf in nodes[1:]:
            _check(leaf, {leaf.cgroup_id}, f"fan-out[{leaf.node_id}]")
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)

    elif topology == "fan-in":
        # affected(each source) == {source, sink}; affected(sink) == {sink}
        sink = nodes[-1]
        for src in nodes[:-1]:
            _check(src, {src.cgroup_id, sink.cgroup_id},
                   f"fan-in[{src.node_id}]")
        _check(sink, {sink.cgroup_id}, "fan-in[sink]")
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)

    elif topology == "diamond":
        # nodes == [root, mid_0 .. mid_{W-1}, sink]. Rolling back the root must
        # reach both arms and the sink; rolling back one arm must NOT reach the
        # other -- that asymmetry is the whole point of the diamond.
        root, sink = nodes[0], nodes[-1]
        _check(root, all_cgroups, "diamond[root]")
        for mid in nodes[1:-1]:
            _check(mid, {mid.cgroup_id, sink.cgroup_id},
                   f"diamond[{mid.node_id}]")
        _check(sink, {sink.cgroup_id}, "diamond[sink]")
        aff = _get_aff(root)
        if aff is not None:
            affected_count = len(aff)

    elif topology == "scc":
        # affected(each node) == all (strongly connected)
        for node in nodes:
            _check(node, all_cgroups, f"scc[{node.node_id}]")
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)

    elif topology == "concurrent":
        # affected(root) == all agents
        _check(nodes[0], all_cgroups, "concurrent[root]")
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)

    else:
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)

    return affected_count, topo_ok, errors


def close_all_nodes(client: OrchClient, nodes: List[EpochNode]):
    """Close all sessions (best-effort cleanup).

    Not optional politeness: every open session holds one of ShadowProc's 64
    concurrent cgroup slots, so a leaked session silently shrinks the ceiling
    for every later configuration and eventually fails session_open with a
    capacity error that has nothing to do with the graph being measured.
    """
    for node in nodes:
        try:
            node.conn(client).session_close(node.session_id)
        except Exception:
            pass
        if node.client is not None:
            try:
                node.client.close()
            except Exception:
                pass
            node.client = None


def _print_row(r: DepGraphResult):
    """One line per configuration: the measured operation, the graph that was
    actually there, and the topology verdict."""
    if r.finalize_ns:
        s = compute_stats(r.resolution_op, r.finalize_ns)
        head = (f"{r.resolution_op}={s.mean_ns/1e6:.2f}ms "
                f"p95={s.p95_ns/1e6:.2f}ms n={s.n}")
    else:
        head = f"{r.resolution_op}=no-samples"
    peak = r.graph_peak
    graph = (f"nodes={peak.get('epochs', '?')} edges={peak.get('edges', '?')} "
             f"scc={peak.get('cyclic_scc_count', '?')}"
             f"/{peak.get('max_scc_size', '?')} "
             f"heap={int(peak.get('heap_alloc_bytes') or 0) / 1048576.0:.1f}MB"
             if peak else "graph=n/a")
    print(f"    {head} | {graph} | topo="
          f"{'OK' if r.topo_verified else 'FAIL'} errors={len(r.errors)}",
          flush=True)


# ═══════════════════════════════════════════════════════════════════════════
# Shared topology builders
# ═══════════════════════════════════════════════════════════════════════════

def seed_files(prefix: str, count: int, extra: Tuple[str, ...] = ()):
    """Pre-create every backing-store file a topology's reads will open.

    Not a convenience: a FUSE Lookup that returns ENOENT never reaches the Open
    handler, so Resolve() never runs and the read-from edge is silently not
    recorded. The experiment would then measure the cost of finalizing an empty
    graph and report it as a scalability result.
    """
    for i in range(count):
        create_seed_file(f"{prefix}_{i}.dat", f"base-{i}")
    for rel in extra:
        create_seed_file(rel, "base")


def build_chain(client: OrchClient, n: int, run_tag: str,
                res: Optional[DepGraphResult] = None,
                prefix: str = "chain") -> List[EpochNode]:
    """Open N epoch nodes and wire them into a linear read-from chain.

    node[i] writes file[i] and node[i+1] reads it, so each of the N-1 links is a
    real cross-epoch edge rather than an asserted one. All N epochs stay open
    until the caller resolves them, which is what makes the chain a single
    N-node dependency graph instead of N independent ones.
    """
    nodes = [open_epoch_node(client, f"n{i}", run_tag, res=res)
             for i in range(n)]
    for i in range(n):
        fpath = dep_fuse_path(f"{prefix}_{i}.dat")
        run_cmd(client, nodes[i], f"echo 'epoch-{i}' > {fpath}", res)
        if i + 1 < n:
            run_cmd(client, nodes[i + 1], f"cat {fpath} > /dev/null", res)
    return nodes


def build_cycle(client: OrchClient, n: int, run_tag: str,
                res: Optional[DepGraphResult] = None,
                prefix: str = "scc",
                own_clients: bool = False) -> List[EpochNode]:
    """Open N epoch nodes and wire them into a cycle (one SCC of size N).

    Two passes, and the split is load-bearing: EVERY node must have written its
    own file before ANY node reads its predecessor's, otherwise node[i] reads
    the backing-store version instead of node[i-1]'s live speculative version,
    ShadowFS records no edge, and the "cycle" is n isolated nodes. node[i] reads
    file[(i-1) mod n], which closes the ring.

    own_clients=True gives every node a private socket so the members can
    authorize concurrently -- the situation SCC-atomic publication exists for.
    """
    nodes = [open_epoch_node(client, f"cyc{i}", run_tag, res=res,
                             own_client=own_clients)
             for i in range(n)]
    for i in range(n):
        fpath = dep_fuse_path(f"{prefix}_{i}.dat")
        run_cmd(client, nodes[i], f"echo 'scc-{i}-written' > {fpath}", res)
    for i in range(n):
        read_path = dep_fuse_path(f"{prefix}_{(i - 1) % n}.dat")
        run_cmd(client, nodes[i], f"cat {read_path} > /dev/null", res)
    return nodes


def build_diamond(client: OrchClient, width: int, run_tag: str,
                  res: Optional[DepGraphResult] = None,
                  prefix: str = "dia") -> List[EpochNode]:
    """root -> {width middles} -> sink. Returns [root, mid_0..mid_{w-1}, sink].

    The generalized diamond: width=2 is the A/B/C/D case the correctness suite
    already covers. Fan-out and fan-in in ONE graph, so it is the smallest shape
    where a rollback of the root must cascade down two independent arms and
    reconverge, and where rolling back one arm must NOT reach the other.
    """
    nodes = [open_epoch_node(client, "root", run_tag, res=res)]
    nodes += [open_epoch_node(client, f"m{i}", run_tag, res=res)
              for i in range(width)]
    sink = open_epoch_node(client, "sink", run_tag, res=res)
    nodes.append(sink)

    root_file = dep_fuse_path(f"{prefix}_root.dat")
    run_cmd(client, nodes[0], f"echo 'diamond-root' > {root_file}", res)
    for i in range(width):
        mid_file = dep_fuse_path(f"{prefix}_mid_{i}.dat")
        run_cmd(client, nodes[i + 1], f"cat {root_file} > /dev/null", res)
        run_cmd(client, nodes[i + 1], f"echo 'diamond-mid-{i}' > {mid_file}",
                res)
    for i in range(width):
        mid_file = dep_fuse_path(f"{prefix}_mid_{i}.dat")
        run_cmd(client, sink, f"cat {mid_file} > /dev/null", res)
    return nodes


def build_fan_out(client: OrchClient, n: int, run_tag: str,
                  res: Optional[DepGraphResult] = None,
                  prefix: str = "fan") -> List[EpochNode]:
    """One producer feeding N consumers. Returns [root, leaf_0..leaf_{n-1}].

    The shape that asks whether a single hot version can be read by many epochs
    without the producer's publication cost growing with the reader count.
    """
    nodes = [open_epoch_node(client, "root", run_tag, res=res)]
    nodes += [open_epoch_node(client, f"leaf{i}", run_tag, res=res)
              for i in range(n)]
    root_file = dep_fuse_path(f"{prefix}_root.dat")
    run_cmd(client, nodes[0], f"echo 'root-output' > {root_file}", res)
    for leaf in nodes[1:]:
        run_cmd(client, leaf, f"cat {root_file} > /dev/null", res)
    return nodes


def build_fan_in(client: OrchClient, n: int, run_tag: str,
                 res: Optional[DepGraphResult] = None,
                 prefix: str = "fanin") -> List[EpochNode]:
    """N producers converging on one consumer. Returns [src_0..src_{n-1}, sink].

    The mirror image of fan-out and the harsher one for rollback: undoing ANY
    source invalidates the sink, so one node has N distinct reasons to be
    rolled back.
    """
    nodes = [open_epoch_node(client, f"src{i}", run_tag, res=res)
             for i in range(n)]
    sink = open_epoch_node(client, "sink", run_tag, res=res)
    nodes.append(sink)
    for i, src in enumerate(nodes[:-1]):
        fpath = dep_fuse_path(f"{prefix}_src_{i}.dat")
        run_cmd(client, src, f"echo 'src-{i}-output' > {fpath}", res)
    for i in range(n):
        fpath = dep_fuse_path(f"{prefix}_src_{i}.dat")
        run_cmd(client, sink, f"cat {fpath} > /dev/null", res)
    return nodes


# ═══════════════════════════════════════════════════════════════════════════
# D1: Chain topology
# ═══════════════════════════════════════════════════════════════════════════

def run_d1_chain(sizes: List[int], repeats: int, obs: OrchClient,
                 daemon_res: Optional[DaemonResources]
                 ) -> List[DepGraphResult]:
    """D1: Linear dependency chain, measured on BOTH resolution paths.

    Two rows per size:
      decision=allow      publication of the whole chain (group finalization)
      decision=root-deny  CASCADING ROLLBACK of the whole chain from the root

    Together these are the finalization-latency and rollback-latency curves
    against node count -- the two curves that decide whether the causal DAG is
    more than a correctness demo. Both are built by the identical construction,
    so the only difference between the rows is which way the graph is resolved.
    """
    print("\n[D1] Chain topology (linear dependency, cross-epoch)")
    results = []

    for decision in ("allow", "root-deny"):
        resolution = "commit" if decision == "allow" else "cascade-rollback"
        for n in sizes:
            print(f"  [D1] chain length={n} decision={decision}")
            r = DepGraphResult(dimension="D1", topology="chain", size=n,
                               decision=decision, resolution_op=resolution,
                               repeats=repeats)
            t0 = time.time()

            with ConfigMeasure(obs, r, daemon_res):
                for rep in range(repeats):
                    cleanup_dep_dir()
                    seed_files("chain", n)
                    run_tag = f"d1-{decision[:4]}-{n}-r{rep}"
                    nodes: List[EpochNode] = []
                    client = None
                    rep_t0 = time.time()
                    try:
                        client = OrchClient()
                        client.connect()

                        with Timer() as setup_t:
                            nodes = build_chain(client, n, run_tag, r)

                        # Sampled BEFORE resolution: the only instant the whole
                        # chain is in the graph at once.
                        record_graph_peak(r, obs)
                        verified, topo_ok, verrs = verify_dependencies(
                            client, nodes, "chain", res=r)
                        r.affected_epochs = verified
                        r.topo_checks.append(topo_ok)
                        r.errors.extend(verrs)

                        with Timer() as fin_t:
                            if decision == "allow":
                                for resp in commit_all(client, nodes, r):
                                    if not commit_succeeded(resp):
                                        r.errors.append(
                                            f"rep={rep}: commit refused: "
                                            f"{resp.get('message')}")
                            else:
                                # One RPC; ShadowFS walks the whole chain.
                                resp, _ = undo_node(client, nodes[0], r,
                                                    via="deny")
                                if resp.get("status") != "ok":
                                    r.errors.append(
                                        f"rep={rep}: root deny refused: "
                                        f"{resp.get('message')}")

                        r.setup_ns.append(setup_t.elapsed_ns)
                        r.finalize_ns.append(fin_t.elapsed_ns)
                        r.total_ns.append(setup_t.elapsed_ns
                                          + fin_t.elapsed_ns)
                        if n > 0:
                            r.per_epoch_finalize_ns.append(
                                fin_t.elapsed_ns / n)

                        if decision == "root-deny":
                            # The cascade already undid every dependent epoch;
                            # this only clears the survivors' session state.
                            for node in nodes[1:]:
                                try:
                                    undo_node(client, node, via="rollback")
                                except Exception:
                                    pass   # already rolled back by cascade

                        close_all_nodes(client, nodes)
                        client.close()

                    except Exception as e:
                        r.errors.append(f"rep={rep}: {e}")
                        try:
                            if client is not None:
                                close_all_nodes(client, nodes)
                                client.close()
                        except Exception:
                            pass

                    print(f"    rep {rep+1}/{repeats} done "
                          f"({time.time()-rep_t0:.1f}s)", flush=True)

            r.wall_time_s = time.time() - t0
            results.append(r)
            _print_row(r)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D2: Fan-out / Fan-in
# ═══════════════════════════════════════════════════════════════════════════

def run_d2_fan(sizes: List[int], repeats: int, obs: OrchClient,
               daemon_res: Optional[DaemonResources]
               ) -> List[DepGraphResult]:
    """D2: Fan-out (one root → N leaves) and Fan-in (N sources → one sink).

    Fan-out: root epoch writes a shared file; N leaf epochs each read it
    in their own independent epoch (creating N cross-epoch dep edges).
    Fan-in: N source epochs each write a distinct file; sink epoch reads
    all N files (creating N cross-epoch dep edges into one node).

    `size` is the WIDTH (number of leaves/sources), so the graph holds
    size+1 nodes; node_count is what lands on the x-axis and what
    per_epoch_finalize divides by.
    """
    print("\n[D2] Fan-out / Fan-in topology (cross-epoch)")
    results = []

    for topology in ("fan-out", "fan-in"):
        for n in sizes:
            print(f"  [D2] {topology} width={n}")
            r = DepGraphResult(dimension="D2", topology=topology, size=n,
                               repeats=repeats)
            t0 = time.time()

            with ConfigMeasure(obs, r, daemon_res):
                for rep in range(repeats):
                    cleanup_dep_dir()
                    if topology == "fan-out":
                        create_seed_file("fan_root.dat", "root-data")
                    else:
                        seed_files("fanin_src", n)
                    run_tag = f"d2{'fo' if topology == 'fan-out' else 'fi'}"
                    run_tag = f"{run_tag}-{n}-r{rep}"
                    nodes: List[EpochNode] = []
                    client = None
                    rep_t0 = time.time()

                    try:
                        client = OrchClient()
                        client.connect()

                        with Timer() as setup_t:
                            if topology == "fan-out":
                                nodes = build_fan_out(client, n, run_tag, r)
                            else:
                                nodes = build_fan_in(client, n, run_tag, r)

                        record_graph_peak(r, obs)
                        verified, topo_ok, verrs = verify_dependencies(
                            client, nodes, topology, res=r)
                        r.affected_epochs = verified
                        r.topo_checks.append(topo_ok)
                        r.errors.extend(verrs)

                        with Timer() as fin_t:
                            for resp in commit_all(client, nodes, r):
                                if not commit_succeeded(resp):
                                    r.errors.append(
                                        f"rep={rep}: commit refused: "
                                        f"{resp.get('message')}")

                        r.setup_ns.append(setup_t.elapsed_ns)
                        r.finalize_ns.append(fin_t.elapsed_ns)
                        r.total_ns.append(setup_t.elapsed_ns
                                          + fin_t.elapsed_ns)
                        if r.node_count:
                            r.per_epoch_finalize_ns.append(
                                fin_t.elapsed_ns / r.node_count)

                        close_all_nodes(client, nodes)
                        client.close()
                    except Exception as e:
                        r.errors.append(f"{topology} rep={rep}: {e}")
                        try:
                            if client is not None:
                                close_all_nodes(client, nodes)
                                client.close()
                        except Exception:
                            pass

                    print(f"    rep {rep+1}/{repeats} done "
                          f"({time.time()-rep_t0:.1f}s)", flush=True)

            r.wall_time_s = time.time() - t0
            results.append(r)
            _print_row(r)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D3: SCC (mutual dependencies / cycles)
# ═══════════════════════════════════════════════════════════════════════════

def run_d3_scc(sizes: List[int], repeats: int, obs: OrchClient,
               daemon_res: Optional[DaemonResources]
               ) -> List[DepGraphResult]:
    """D3: Strongly-connected components — epochs with mutual dependencies.

    Creates a cycle of N independent epochs: epoch[i] writes file[i] and
    reads file[(i-1) % N]. Since every epoch both produces and consumes
    another epoch's output, the dependency graph forms a cycle (SCC).

    SCCs cannot be committed sequentially (each epoch's finalize would
    require its dependencies to be finalized first — circular). Instead,
    this measures the CASCADE ROLLBACK cost: denying one epoch in the SCC
    triggers atomic rollback of the entire cycle. This is the meaningful
    scalability metric for SCC resolution. The PUBLISH side of the same
    component is D7.

    Also asserts that ShadowFS actually FOUND the component: an undetected
    cycle would still roll back correctly-looking numbers while the atomic
    publication guarantee silently did not exist.
    """
    print("\n[D3] SCC (mutual dependencies, cascade rollback)")
    results = []

    for n in sizes:
        print(f"  [D3] SCC size={n} (cycle of {n} epochs)")
        r = DepGraphResult(dimension="D3", topology="scc", size=n,
                           decision="rollback-cascade",
                           resolution_op="cascade-rollback",
                           repeats=repeats)
        t0 = time.time()

        with ConfigMeasure(obs, r, daemon_res):
            for rep in range(repeats):
                cleanup_dep_dir()
                seed_files("scc", n)
                run_tag = f"d3-{n}-r{rep}"
                nodes: List[EpochNode] = []
                client = None
                rep_t0 = time.time()

                try:
                    client = OrchClient()
                    client.connect()

                    with Timer() as setup_t:
                        nodes = build_cycle(client, n, run_tag, r)

                    record_graph_peak(r, obs)
                    peak = r.graph_peak
                    if peak and peak.get("cyclic_scc_count", 0) < 1:
                        r.errors.append(
                            f"rep={rep}: ShadowFS reports no cyclic SCC "
                            f"(cyclic_scc_count="
                            f"{peak.get('cyclic_scc_count')})")
                    elif peak and peak.get("max_scc_size", 0) != n:
                        r.errors.append(
                            f"rep={rep}: SCC detected with "
                            f"max_scc_size={peak.get('max_scc_size')}, "
                            f"expected {n}")

                    # Verify: in an SCC, rolling back any node should affect all
                    verified, topo_ok, verrs = verify_dependencies(
                        client, nodes, "scc", res=r)
                    r.affected_epochs = verified
                    r.topo_checks.append(topo_ok)
                    r.errors.extend(verrs)

                    # Measure cascade rollback: deny ONE epoch, ShadowFS
                    # cascades to the entire SCC atomically.
                    # Timer covers ONLY the single deny RPC — the cascade is
                    # handled internally by ShadowFS within that one call.
                    with Timer() as fin_t:
                        resp, _ = undo_node(client, nodes[0], r, via="deny")
                        if resp.get("status") != "ok":
                            r.errors.append(
                                f"rep={rep}: scc deny refused: "
                                f"{resp.get('message')}")

                    # Cleanup outside timer: rollback any surviving epochs
                    for node in nodes[1:]:
                        try:
                            undo_node(client, node, via="rollback")
                        except Exception:
                            pass  # already rolled back by cascade

                    r.setup_ns.append(setup_t.elapsed_ns)
                    r.finalize_ns.append(fin_t.elapsed_ns)
                    r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)
                    if n > 0:
                        r.per_epoch_finalize_ns.append(fin_t.elapsed_ns / n)

                    close_all_nodes(client, nodes)
                    client.close()
                except Exception as e:
                    r.errors.append(f"rep={rep}: {e}")
                    try:
                        if client is not None:
                            close_all_nodes(client, nodes)
                            client.close()
                    except Exception:
                        pass

                print(f"    rep {rep+1}/{repeats} done "
                      f"({time.time()-rep_t0:.1f}s)", flush=True)

        r.wall_time_s = time.time() - t0
        results.append(r)
        _print_row(r)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D4: Concurrent agents with shared dependency
# ═══════════════════════════════════════════════════════════════════════════

def _open_and_write_agent(agent_idx: int, run_tag: str, shared_file: str,
                          res: Optional[DepGraphResult] = None
                          ) -> Dict[str, Any]:
    """Open one agent's epoch and read the shared root file.

    Each agent forms a real dependency on the root epoch by reading the
    root's output file. Every agent owns its connection, which is what lets
    phase 2 authorize all of them at once. Returns the node (or the error).
    """
    agent_id = f"dep-d4-{run_tag}-agent{agent_idx}"
    client = OrchClient()
    for attempt in range(5):
        try:
            client.connect()
            break
        except (BlockingIOError, ConnectionRefusedError, OSError):
            if attempt == 4:
                return {"agent_idx": agent_idx, "error": "connect failed",
                        "node": None, "client": None, "agent_id": agent_id}
            time.sleep(0.05 * (attempt + 1))
    try:
        sess = client.session_open(agent_id=agent_id)
        node = EpochNode(
            node_id=f"agent{agent_idx}", session_id=sess["session_id"],
            cgroup_id=sess["cgroup_id"], epoch_id="",
            agent_id=agent_id, client=client)
        client.session_begin_epoch(node.session_id, agent_id=agent_id)
        # Read the shared root file → creates cross-epoch dep on root
        run_cmd(client, node, f"cat {shared_file} > /dev/null", res)
        # Also write agent's own output (so commit has effects)
        own_file = dep_fuse_path(f"concurrent_{agent_idx}.dat")
        run_cmd(client, node, f"echo 'agent-{agent_idx}' > {own_file}", res)
        return {"agent_idx": agent_idx, "error": None,
                "node": node, "client": client, "agent_id": agent_id}
    except Exception as e:
        client.close()
        return {"agent_idx": agent_idx, "error": str(e),
                "node": None, "client": None, "agent_id": agent_id}


def run_d4_concurrent(sizes: List[int], repeats: int, obs: OrchClient,
                      daemon_res: Optional[DaemonResources]
                      ) -> List[DepGraphResult]:
    """D4: Concurrent agents with shared dependency graph.

    A root epoch writes a shared file; N agent epochs each read it (forming
    a real fan-out dependency). Then all agents commit concurrently,
    measuring group-level finalization contention with actual dependencies.

    This is the publication-contention point of the graph experiment; the
    agent-count axis itself is swept in multi_agent_scaling.py.
    """
    print("\n[D4] Concurrent agents (shared dependency)")
    results = []

    for n_agents in sizes:
        print(f"  [D4] agents={n_agents}")
        r = DepGraphResult(dimension="D4", topology="concurrent",
                           size=n_agents, repeats=repeats)
        t0 = time.time()

        with ConfigMeasure(obs, r, daemon_res):
            for rep in range(repeats):
                cleanup_dep_dir()
                create_seed_file("shared_root.dat", "shared-base")
                seed_files("concurrent", n_agents)
                run_tag = f"d4-{n_agents}-r{rep}"

                root_client = None
                root_node = None
                agent_nodes: List[EpochNode] = []
                rep_t0 = time.time()
                try:
                    # Phase 0: root epoch writes the shared file
                    root_client = OrchClient()
                    root_client.connect()

                    # Phase 1: all agents open epochs and read the shared file
                    with Timer() as setup_t:
                        root_node = open_epoch_node(root_client, "root",
                                                    run_tag, r)
                        shared_file = dep_fuse_path("shared_root.dat")
                        run_cmd(root_client, root_node,
                                f"echo 'root-shared-output' > {shared_file}",
                                r)
                        with ThreadPoolExecutor(
                                max_workers=min(n_agents, MAX_NODES)) as pool:
                            futures = []
                            for i in range(n_agents):
                                futures.append(pool.submit(
                                    _open_and_write_agent, i, run_tag,
                                    shared_file, r))
                                if i < n_agents - 1:
                                    time.sleep(0.005)
                            phase1 = [f.result() for f in as_completed(futures)]

                    agent_nodes = [x["node"] for x in phase1
                                   if not x["error"] and x["node"]]
                    phase1_errors = [x["error"] for x in phase1
                                     if x["error"]]
                    if phase1_errors:
                        r.errors.extend(phase1_errors[:5])

                    nodes = ([root_node] + agent_nodes) if root_node else []
                    record_graph_peak(r, obs)

                    # Verify dependency: root rollback should affect all agents.
                    verified, topo_ok, verrs = verify_dependencies(
                        root_client, nodes, "concurrent", res=r)
                    r.affected_epochs = verified
                    r.topo_checks.append(topo_ok)
                    r.errors.extend(verrs)

                    # Phase 2: commit root + all agents concurrently (measured)
                    if agent_nodes:
                        with Timer() as batch_t:
                            # Root first: it is the producer.
                            root_resp = commit_node(root_client, root_node, r)
                            if not commit_succeeded(root_resp):
                                r.errors.append(
                                    f"rep={rep}: root commit refused: "
                                    f"{root_resp.get('message')}")
                            for resp in commit_all(root_client, agent_nodes, r,
                                                   concurrent=True):
                                if not commit_succeeded(resp):
                                    r.errors.append(
                                        f"rep={rep}: agent commit refused: "
                                        f"{resp.get('message')}")

                        r.finalize_ns.append(batch_t.elapsed_ns)
                        r.total_ns.append(setup_t.elapsed_ns
                                          + batch_t.elapsed_ns)
                        if r.node_count:
                            r.per_epoch_finalize_ns.append(
                                batch_t.elapsed_ns / r.node_count)
                    else:
                        r.total_ns.append(setup_t.elapsed_ns)

                    close_all_nodes(root_client, nodes)
                    root_client.close()

                except Exception as e:
                    r.errors.append(f"rep={rep}: {e}")
                    try:
                        if root_client:
                            all_nodes = ([root_node] if root_node else []) \
                                + agent_nodes
                            close_all_nodes(root_client, all_nodes)
                            root_client.close()
                    except Exception:
                        pass

                print(f"    rep {rep+1}/{repeats} done "
                      f"({time.time()-rep_t0:.1f}s)", flush=True)

        r.wall_time_s = time.time() - t0
        results.append(r)
        _print_row(r)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D5: Authorization decisions (allow / root-deny / middle-deny)
# ═══════════════════════════════════════════════════════════════════════════

def run_d5_decisions(chain_size: int, repeats: int, obs: OrchClient,
                     daemon_res: Optional[DaemonResources]
                     ) -> List[DepGraphResult]:
    """D5: Authorization decisions at different graph positions.

    Builds a real multi-epoch chain (same as D1), then:
    - allow: all epochs commit successfully
    - root-deny: the ROOT epoch (epoch[0]) is denied → cascading rollback
      of ALL downstream epochs
    - middle-deny: a MIDDLE epoch (epoch[chain_size//2]) is denied →
      partial rollback of only its downstream dependents

    D1 sweeps the SIZE of a decision's blast radius; this holds the size fixed
    and moves the decision's POSITION, which is the other half of "what does a
    decision cost".
    """
    print(f"\n[D5] Authorization decisions (chain_size={chain_size})")
    results = []

    for decision_mode in ["allow", "root-deny", "middle-deny"]:
        print(f"  [D5] decision={decision_mode}")
        resolution = ("commit" if decision_mode == "allow"
                      else "cascade-rollback")
        r = DepGraphResult(dimension="D5", topology="chain",
                           size=chain_size, decision=decision_mode,
                           resolution_op=resolution, repeats=repeats)
        t0 = time.time()

        with ConfigMeasure(obs, r, daemon_res):
            for rep in range(repeats):
                cleanup_dep_dir()
                seed_files("decision", chain_size)
                run_tag = f"d5-{decision_mode}-{chain_size}-r{rep}"
                nodes: List[EpochNode] = []
                client = None
                rep_t0 = time.time()

                try:
                    client = OrchClient()
                    client.connect()

                    # Setup: build a real multi-epoch chain
                    with Timer() as setup_t:
                        nodes = build_chain(client, chain_size, run_tag, r,
                                            prefix="decision")

                    record_graph_peak(r, obs)
                    # Verify dependencies formed (full chain before any commits)
                    verified, topo_ok, verrs = verify_dependencies(
                        client, nodes, "chain", res=r)
                    r.affected_epochs = verified
                    r.topo_checks.append(topo_ok)
                    r.errors.extend(verrs)

                    # Apply the decision at the correct graph position.
                    # Timer covers ONLY the decision RPC whose cost we want
                    # to measure; setup commits and cleanup rollbacks are
                    # outside the timed interval.
                    mid = chain_size // 2
                    if decision_mode == "middle-deny":
                        # Upstream publishes BEFORE the timed interval: the
                        # decision under measurement is the one at `mid`, not
                        # the commits that made it reachable.
                        for resp in commit_all(client, nodes[:mid], r):
                            if not commit_succeeded(resp):
                                r.errors.append(
                                    f"rep={rep}: upstream commit refused: "
                                    f"{resp.get('message')}")
                        # Affected set AFTER upstream committed: the upstream
                        # nodes are gone from the graph, so this is the cascade
                        # the deny is actually about to perform.
                        try:
                            aff = client.get_affected(nodes[mid].cgroup_id)
                            r.affected_samples.append(
                                len(aff.get("affected", []) or []))
                        except Exception:
                            pass

                    with Timer() as fin_t:
                        if decision_mode == "allow":
                            # Commit all epochs
                            for resp in commit_all(client, nodes, r):
                                if not commit_succeeded(resp):
                                    r.errors.append(
                                        f"rep={rep}: commit refused: "
                                        f"{resp.get('message')}")
                        else:
                            target = (nodes[mid]
                                      if decision_mode == "middle-deny"
                                      else nodes[0])
                            resp, _ = undo_node(client, target, r, via="deny")
                            if resp.get("status") != "ok":
                                r.errors.append(
                                    f"rep={rep}: {decision_mode} refused: "
                                    f"{resp.get('message')}")

                    # Cleanup outside timer: rollback any surviving epochs
                    if decision_mode == "root-deny":
                        survivors = nodes[1:]
                    elif decision_mode == "middle-deny":
                        survivors = nodes[mid + 1:]
                    else:
                        survivors = []
                    for node in survivors:
                        try:
                            undo_node(client, node, via="rollback")
                        except Exception:
                            pass   # already rolled back by the cascade

                    r.setup_ns.append(setup_t.elapsed_ns)
                    r.finalize_ns.append(fin_t.elapsed_ns)
                    r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                    close_all_nodes(client, nodes)
                    client.close()
                except Exception as e:
                    r.errors.append(f"rep={rep}: {e}")
                    try:
                        if client is not None:
                            close_all_nodes(client, nodes)
                            client.close()
                    except Exception:
                        pass

                print(f"    rep {rep+1}/{repeats} done "
                      f"({time.time()-rep_t0:.1f}s)", flush=True)

        r.wall_time_s = time.time() - t0
        results.append(r)
        _print_row(r)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D6: Diamond (fan-out and fan-in in one graph)
# ═══════════════════════════════════════════════════════════════════════════

def run_d6_diamond(widths: List[int], repeats: int, obs: OrchClient,
                   daemon_res: Optional[DaemonResources]
                   ) -> List[DepGraphResult]:
    """D6: root → {W middles} → sink, on both resolution paths.

    W=2 is the A/B/C/D diamond the correctness suite already covers; here W is
    swept so the shape that RECONVERGES gets a scaling curve of its own. It is
    the only topology in this file where a rollback must cascade down two
    independent arms and meet again at one sink, and where the strict
    set-equality check is asymmetric: affected(mid_i) is {mid_i, sink}, never
    the other arm.
    """
    print("\n[D6] Diamond topology (generalized A/B/C/D)")
    results = []

    for decision in ("allow", "root-deny"):
        resolution = "commit" if decision == "allow" else "cascade-rollback"
        for width in widths:
            print(f"  [D6] diamond width={width} decision={decision}")
            r = DepGraphResult(dimension="D6", topology="diamond", size=width,
                               decision=decision, resolution_op=resolution,
                               repeats=repeats)
            t0 = time.time()

            with ConfigMeasure(obs, r, daemon_res):
                for rep in range(repeats):
                    cleanup_dep_dir()
                    seed_files("dia_mid", width, extra=("dia_root.dat",))
                    run_tag = f"d6-{decision[:4]}-{width}-r{rep}"
                    nodes: List[EpochNode] = []
                    client = None
                    rep_t0 = time.time()

                    try:
                        client = OrchClient()
                        client.connect()

                        with Timer() as setup_t:
                            nodes = build_diamond(client, width, run_tag, r)

                        record_graph_peak(r, obs)
                        peak = r.graph_peak
                        # 2*W edges: W root→mid and W mid→sink. A diamond that
                        # recorded fewer is not a diamond.
                        want_edges = 2 * width
                        if peak and (peak.get("edges") or 0) < want_edges:
                            r.errors.append(
                                f"rep={rep}: graph holds {peak.get('edges')} "
                                f"edges at full population, expected at least "
                                f"{want_edges}")

                        verified, topo_ok, verrs = verify_dependencies(
                            client, nodes, "diamond", res=r)
                        r.affected_epochs = verified
                        r.topo_checks.append(topo_ok)
                        r.errors.extend(verrs)

                        with Timer() as fin_t:
                            if decision == "allow":
                                for resp in commit_all(client, nodes, r):
                                    if not commit_succeeded(resp):
                                        r.errors.append(
                                            f"rep={rep}: commit refused: "
                                            f"{resp.get('message')}")
                            else:
                                resp, _ = undo_node(client, nodes[0], r,
                                                    via="deny")
                                if resp.get("status") != "ok":
                                    r.errors.append(
                                        f"rep={rep}: root deny refused: "
                                        f"{resp.get('message')}")

                        r.setup_ns.append(setup_t.elapsed_ns)
                        r.finalize_ns.append(fin_t.elapsed_ns)
                        r.total_ns.append(setup_t.elapsed_ns
                                          + fin_t.elapsed_ns)
                        if r.node_count:
                            r.per_epoch_finalize_ns.append(
                                fin_t.elapsed_ns / r.node_count)

                        if decision == "root-deny":
                            for node in nodes[1:]:
                                try:
                                    undo_node(client, node, via="rollback")
                                except Exception:
                                    pass   # already rolled back by cascade

                        close_all_nodes(client, nodes)
                        client.close()
                    except Exception as e:
                        r.errors.append(f"rep={rep}: {e}")
                        try:
                            if client is not None:
                                close_all_nodes(client, nodes)
                                client.close()
                        except Exception:
                            pass

                    print(f"    rep {rep+1}/{repeats} done "
                          f"({time.time()-rep_t0:.1f}s)", flush=True)

            r.wall_time_s = time.time() - t0
            results.append(r)
            _print_row(r)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D7: SCC publication (atomic release of a cycle)
# ═══════════════════════════════════════════════════════════════════════════

def run_d7_scc_publish(sizes: List[int], repeats: int, obs: OrchClient,
                       daemon_res: Optional[DaemonResources]
                       ) -> List[DepGraphResult]:
    """D7: the PUBLISH side of the same cycles D3 rolls back.

    Every member authorizes concurrently, each on its own connection. None of
    them may appear until all of them have, so the first member to arrive gets
    `authorized_pending` and has to come back -- that is the finalization wait
    this dimension exists to measure, and it is the only place in the suite
    where dependency-safe publication is exercised under the contention it was
    designed for.

    Reported per size:
      finalization_wait_ns  each member's own wait, first attempt → published
      commit_attempts       how many retries a member needed to get there
      pending_commits       how many members had to park at all
      graph_revalidations   orchestrator re-preparations after a generation
                            mismatch (ShadowFS side: finalize_rejected_toctou)
      drain_ns              publication → the whole component gone from the graph
    """
    print("\n[D7] SCC publication (atomic release of a cycle)")
    results = []

    for n in sizes:
        print(f"  [D7] SCC publish size={n} (cycle of {n} epochs)")
        r = DepGraphResult(dimension="D7", topology="scc", size=n,
                           decision="publish", resolution_op="commit",
                           repeats=repeats)
        t0 = time.time()

        with ConfigMeasure(obs, r, daemon_res):
            for rep in range(repeats):
                cleanup_dep_dir()
                seed_files("sccp", n)
                run_tag = f"d7-{n}-r{rep}"
                nodes: List[EpochNode] = []
                client = None
                rep_t0 = time.time()

                try:
                    client = OrchClient()
                    client.connect()

                    with Timer() as setup_t:
                        # own_clients: the members must be able to authorize at
                        # the same instant, which one shared line-oriented
                        # socket cannot express.
                        nodes = build_cycle(client, n, run_tag, r,
                                            prefix="sccp", own_clients=True)

                    record_graph_peak(r, obs)
                    peak = r.graph_peak
                    if peak:
                        if peak.get("cyclic_scc_count", 0) != 1:
                            r.errors.append(
                                f"rep={rep}: expected exactly 1 cyclic SCC, "
                                f"got {peak.get('cyclic_scc_count')}")
                        if peak.get("max_scc_size", 0) != n:
                            r.errors.append(
                                f"rep={rep}: max_scc_size="
                                f"{peak.get('max_scc_size')}, expected {n}")

                    verified, topo_ok, verrs = verify_dependencies(
                        client, nodes, "scc", res=r)
                    r.affected_epochs = verified
                    r.topo_checks.append(topo_ok)
                    r.errors.extend(verrs)

                    with Timer() as fin_t:
                        for resp in commit_all(client, nodes, r,
                                               concurrent=True):
                            if not commit_succeeded(resp):
                                r.errors.append(
                                    f"rep={rep}: scc member not published: "
                                    f"{resp.get('message')} "
                                    f"decision={resp.get('decision')}")

                    r.setup_ns.append(setup_t.elapsed_ns)
                    r.finalize_ns.append(fin_t.elapsed_ns)
                    r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)
                    if n > 0:
                        r.per_epoch_finalize_ns.append(fin_t.elapsed_ns / n)

                    # Outside the timed interval: publication returning is not
                    # the same as the component having left the graph, and the
                    # gap is what a later session would have to wait out.
                    epoch_ids = [x.epoch_id for x in nodes if x.epoch_id]
                    if len(epoch_ids) == len(nodes):
                        gone, drain_ns, states = obs.wait_epochs_gone(
                            epoch_ids, timeout=GONE_TIMEOUT_S,
                            interval=GONE_POLL_INTERVAL_S)
                        r.drain_ns.append(float(drain_ns))
                        if not gone:
                            r.errors.append(
                                f"rep={rep}: component had not left the graph "
                                f"{GONE_TIMEOUT_S:.0f}s after publish; last "
                                f"observed states={states}")

                    close_all_nodes(client, nodes)
                    client.close()
                except Exception as e:
                    r.errors.append(f"rep={rep}: {e}")
                    try:
                        if client is not None:
                            close_all_nodes(client, nodes)
                            client.close()
                    except Exception:
                        pass

                print(f"    rep {rep+1}/{repeats} done "
                      f"({time.time()-rep_t0:.1f}s)", flush=True)

        r.wall_time_s = time.time() - t0
        results.append(r)
        _print_row(r)
        if r.finalization_wait_ns:
            w = compute_stats("scc-wait", r.finalization_wait_ns)
            print(f"    finalization wait: mean={w.mean_ns/1e6:.2f}ms "
                  f"p95={w.p95_ns/1e6:.2f}ms max={w.max_ns/1e6:.2f}ms "
                  f"parked={r.pending_commits} "
                  f"attempts_max="
                  f"{max(r.commit_attempts) if r.commit_attempts else 0} "
                  f"revalidations={r.graph_revalidations} "
                  f"toctou={r.graph.get('finalize_rejected_toctou', 0)}",
                  flush=True)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

# Default sizes — each graph node is an independent session (cgroup + fork),
# measured at ~0.7 s of sequential construction on this host, so a 64-node
# chain costs ~45 s per repeat before anything is timed. Sizes are capped at
# MAX_NODES because that is where ShadowProc's cgroup slot table runs out.
FULL_CHAIN_SIZES = [2, 4, 8, 16, 32, 64]
FULL_FAN_SIZES = [2, 4, 8, 16, 32]
FULL_SCC_SIZES = [2, 4, 8, 16, 32]
FULL_CONCURRENT_SIZES = [1, 4, 8, 16, 32]
FULL_DIAMOND_WIDTHS = [2, 4, 8, 16]
FULL_DECISION_CHAIN = 8

QUICK_CHAIN_SIZES = [2, 4]
QUICK_FAN_SIZES = [2, 4]
QUICK_SCC_SIZES = [2, 4]
QUICK_CONCURRENT_SIZES = [1, 4]
QUICK_DIAMOND_WIDTHS = [2]
QUICK_DECISION_CHAIN = 4

DEFAULT_REPEATS = 10
QUICK_REPEATS = 1


def _is_fuse_mounted(mount_point: str) -> bool:
    """Check if a FUSE filesystem is mounted at the given path.

    MUST use /proc/mounts instead of os.path.isdir(): os.path calls on a
    FUSE mount point can return False or raise errors if the FUSE daemon
    is not yet fully responsive, while /proc/mounts is a kernel-provided
    authoritative source.
    """
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
    """Check that all prerequisites are met."""
    errors = []
    if not RUN_EXPERIMENTS:
        errors.append("Set SHADOW_RUN_RQ3_EXPERIMENTS=1 to run experiments")
    orch_sock = os.environ.get("SHADOW_ORCH_SOCK", "/tmp/shadow-orch.sock")
    if not os.path.exists(orch_sock):
        errors.append(f"Orchestrator socket not found: {orch_sock}")
    if not _is_fuse_mounted(SHADOWFS_MNT):
        errors.append(f"ShadowFS FUSE not mounted at: {SHADOWFS_MNT}")
    return errors


def save_results(results: List[DepGraphResult], output_dir: str,
                 cfg: Optional[Dict[str, Any]] = None):
    """Save results to JSON.

    The configuration block is stored alongside the measurements so a result
    file says what was swept and what the node ceiling was, instead of leaving
    the reader to infer it from which sizes happen to appear.
    """
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "dep_graph_scalability.json")
    data = {
        "experiment": "rq3_dep_graph_scalability",
        "timestamp": time.time(),
        "config": dict(cfg or {}, max_nodes=MAX_NODES),
        "dimensions": [r.to_dict() for r in results],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n[save] Results written to {path}")


ALL_DIMENSIONS = (1, 2, 3, 4, 5, 6, 7)


def _mb(v: Any) -> Optional[float]:
    return None if v is None else float(v) / 1048576.0


def print_summary(all_results: List[DepGraphResult]):
    """Two tables: the latency verdict, then the graph/daemon evidence behind it.

    The second table is not decoration -- it is what separates "the finalization
    latency grew" from "the finalization latency grew because the graph grew",
    by showing the shape that was actually present and the CPU it cost.
    """
    print("\n" + "═" * 118)
    print("  SUMMARY — dependency graph shape scaling")
    print("═" * 118)
    hdr = (f"{'Dim':<4}{'Topology':<11}{'Sz':>4}{'Nd':>4} "
           f"{'Decision':<14}{'Op':<17}{'mean(ms)':>9}{'p95(ms)':>9}"
           f"{'wait(ms)':>9}{'E/inv':>7}{'SCC':>7}{'HeapMB':>8}"
           f"{'Topo':<6}{'Err':>4}")
    print(hdr)
    print("─" * 118)
    for r in all_results:
        if r.finalize_ns:
            s = compute_stats("summary", r.finalize_ns)
            mean = f"{s.mean_ns/1e6:.3f}"
            p95 = f"{s.p95_ns/1e6:.3f}"
        else:
            mean = p95 = "-"
        if r.finalization_wait_ns:
            w = statistics.fmean(r.finalization_wait_ns) / 1e6
            wait = f"{w:.3f}"
        else:
            wait = "-"
        epi = r.edges_per_invocation
        peak = r.graph_peak or {}
        scc = (f"{peak.get('cyclic_scc_count', 0)}/"
               f"{peak.get('max_scc_size', 0)}" if peak else "-")
        heap = _mb(peak.get("heap_alloc_bytes"))
        print(f"{r.dimension:<4}{r.topology:<11}{r.size:>4}{r.node_count:>4} "
              f"{r.decision:<14}{r.resolution_op:<17}{mean:>9}{p95:>9}"
              f"{wait:>9}{(f'{epi:.2f}' if epi is not None else '-'):>7}"
              f"{scc:>7}{(f'{heap:.1f}' if heap else '-'):>8}"
              f"{'OK' if r.topo_verified else 'FAIL':<6}{len(r.errors):>4}")

    print("\n" + "─" * 118)
    print("  GRAPH COUNTERS / DAEMON RESOURCES (whole configuration, all "
          "repeats)")
    print("─" * 118)
    for r in all_results:
        g, res, peak = r.graph or {}, r.resources or {}, r.graph_peak or {}
        scc_comps = g.get("scc_computations") or 0
        scc_ns = (g.get("scc_compute_ns") or 0) / scc_comps if scc_comps else 0
        aff_q = g.get("affected_queries") or 0
        aff_ns = (g.get("affected_query_ns") or 0) / aff_q if aff_q else 0
        rb = g.get("rollbacks") or 0
        rb_ns = (g.get("rollback_ns") or 0) / rb if rb else 0
        print(f"  {r.dimension} {r.topology} nodes={r.node_count} "
              f"decision={r.decision} wall={r.wall_time_s:.1f}s")
        print(f"    peak  : epochs={peak.get('epochs')} "
              f"edges={peak.get('edges')} versions={peak.get('versions')} "
              f"objects={peak.get('objects')} scc={peak.get('scc_count')} "
              f"cyclic={peak.get('cyclic_scc_count')} "
              f"max_scc={peak.get('max_scc_size')} "
              f"heap={_mb(peak.get('heap_alloc_bytes')) or 0:.1f}MB")
        print(f"    work  : edges={g.get('edge_insertions')} "
              f"invocations={r.invocations} "
              f"edges/inv={(f'{r.edges_per_invocation:.2f}' if r.edges_per_invocation is not None else '-')} "
              f"scc_sweeps={scc_comps} scc_us/sweep={scc_ns/1e3:.1f} "
              f"affected_q={aff_q} affected_us/q={aff_ns/1e3:.1f} "
              f"prepare={g.get('prepare_calls')} "
              f"finalize={g.get('finalize_calls')} "
              f"finalized_nodes={g.get('finalized_nodes_total')}")
        print(f"    undo  : rollbacks={rb} rollback_us/call={rb_ns/1e3:.1f} "
              f"rollback_nodes={g.get('rollback_nodes_total')} "
              f"toctou_rejected={g.get('finalize_rejected_toctou')} "
              f"orch_revalidations={r.graph_revalidations} "
              f"cascaded_mean="
              f"{(f'{statistics.fmean(r.rollback_affected):.1f}' if r.rollback_affected else '-')}")
        print(f"    publish: parked={r.pending_commits} "
              f"attempts_max="
              f"{max(r.commit_attempts) if r.commit_attempts else 0} "
              f"wait_ms_mean="
              f"{(f'{statistics.fmean(r.finalization_wait_ns)/1e6:.2f}' if r.finalization_wait_ns else '-')} "
              f"drain_ms_mean="
              f"{(f'{statistics.fmean(r.drain_ns)/1e6:.2f}' if r.drain_ns else '-')}")
        print(f"    daemons: cpu%={res.get('daemons_cpu_pct')} "
              f"shadowfs={res.get('shadowfs_cpu_pct')}/"
              f"{res.get('shadowfs_rss_peak_mb')}MB "
              f"shadowproc={res.get('shadowproc_cpu_pct')}/"
              f"{res.get('shadowproc_rss_peak_mb')}MB "
              f"orchestrator={res.get('orchestrator_cpu_pct')}/"
              f"{res.get('orchestrator_rss_peak_mb')}MB "
              f"wall={res.get('wall_seconds')}")
        if r.errors:
            print(f"    errors: {len(r.errors)} (first: {r.errors[0][:110]})")


def main():
    parser = argparse.ArgumentParser(
        description="RQ3 Experiment B: Dependency Graph Shape Scaling")
    parser.add_argument("--output-dir", default="./results")
    parser.add_argument("--dimension", default="all",
                        help="Dimension (1-7, comma-separated) or 'all'")
    parser.add_argument("--repeats", type=int, default=None,
                        help=f"Repeats per configuration "
                             f"(default: {DEFAULT_REPEATS}, "
                             f"{QUICK_REPEATS} with --quick)")
    parser.add_argument("--quick", action="store_true",
                        help="Reduced sizes for quick testing")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.quick:
        cfg = {
            "chain_sizes": list(QUICK_CHAIN_SIZES),
            "fan_sizes": list(QUICK_FAN_SIZES),
            "scc_sizes": list(QUICK_SCC_SIZES),
            "concurrent_sizes": list(QUICK_CONCURRENT_SIZES),
            "diamond_widths": list(QUICK_DIAMOND_WIDTHS),
            "decision_chain": QUICK_DECISION_CHAIN,
            "repeats": QUICK_REPEATS,
        }
    else:
        cfg = {
            "chain_sizes": list(FULL_CHAIN_SIZES),
            "fan_sizes": list(FULL_FAN_SIZES),
            "scc_sizes": list(FULL_SCC_SIZES),
            "concurrent_sizes": list(FULL_CONCURRENT_SIZES),
            "diamond_widths": list(FULL_DIAMOND_WIDTHS),
            "decision_chain": FULL_DECISION_CHAIN,
            "repeats": DEFAULT_REPEATS,
        }
    if args.repeats is not None:
        if args.repeats < 1:
            parser.error("--repeats must be >= 1")
        cfg["repeats"] = args.repeats

    # One node holds one cgroup for the whole repeat, so the ceiling is on the
    # NODE count, not on the shape parameter: a fan-out of width W holds W+1.
    over = sorted({v for key in ("chain_sizes", "fan_sizes", "scc_sizes",
                                 "concurrent_sizes", "diamond_widths")
                   for v in cfg[key]} | {cfg["decision_chain"]})
    over = [v for v in over if v > MAX_NODES]
    if over:
        parser.error(f"sizes {over} exceed MAX_NODES={MAX_NODES} "
                     f"(ShadowProc's concurrent cgroup slots)")

    if args.dimension == "all":
        dims = list(ALL_DIMENSIONS)
    else:
        try:
            dims = [int(x) for x in args.dimension.split(",") if x.strip()]
        except ValueError:
            parser.error(f"--dimension must be 1-7 or 'all', "
                         f"got {args.dimension!r}")
        bad = [d for d in dims if d not in ALL_DIMENSIONS]
        if bad:
            parser.error(f"unknown dimension(s) {bad}; valid: "
                         f"{','.join(str(d) for d in ALL_DIMENSIONS)}")
    cfg["dimensions"] = dims

    errors = check_prerequisites()
    if errors and not args.dry_run:
        print("PREREQUISITE FAILURES:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    if args.dry_run:
        print("\n[DRY RUN] Would execute:")
        if 1 in dims:
            print(f"  D1 Chain: sizes={cfg['chain_sizes']} x2 decisions, "
                  f"repeats={cfg['repeats']}")
        if 2 in dims:
            print(f"  D2 Fan-out/in: widths={cfg['fan_sizes']} "
                  f"(nodes=width+1), repeats={cfg['repeats']}")
        if 3 in dims:
            print(f"  D3 SCC cascade rollback: sizes={cfg['scc_sizes']}, "
                  f"repeats={cfg['repeats']}")
        if 4 in dims:
            print(f"  D4 Concurrent publish: agents={cfg['concurrent_sizes']}, "
                  f"repeats={cfg['repeats']}")
        if 5 in dims:
            print(f"  D5 Decisions: chain={cfg['decision_chain']} x3 "
                  f"positions, repeats={cfg['repeats']}")
        if 6 in dims:
            print(f"  D6 Diamond: widths={cfg['diamond_widths']} "
                  f"(nodes=width+2) x2 decisions, repeats={cfg['repeats']}")
        if 7 in dims:
            print(f"  D7 SCC atomic publish: sizes={cfg['scc_sizes']}, "
                  f"repeats={cfg['repeats']}")
        # Rough cost model, calibrated from a previous full run at ~0.7 s of
        # sequential construction per node. Printed so an hour-long run is a
        # choice rather than a surprise. Counted per SELECTED dimension: a
        # conditional inside one big sum would silently zero the total, since
        # `a + b if cond else 0` parses as `(a + b) if cond else 0`.
        nodes = 0
        if 1 in dims:
            nodes += 2 * sum(cfg["chain_sizes"])          # x2 decisions
        if 2 in dims:
            nodes += 2 * sum(s + 1 for s in cfg["fan_sizes"])
        if 3 in dims:
            nodes += sum(cfg["scc_sizes"])
        if 4 in dims:
            nodes += sum(a + 1 for a in cfg["concurrent_sizes"])
        if 5 in dims:
            nodes += 3 * cfg["decision_chain"]            # x3 positions
        if 6 in dims:
            nodes += 2 * sum(w + 2 for w in cfg["diamond_widths"])
        if 7 in dims:
            nodes += sum(cfg["scc_sizes"])
        print(f"  ~{nodes} node-builds/repeat x {cfg['repeats']} repeats "
              f"≈ {nodes * cfg['repeats'] * 0.7 / 60.0:.0f} min "
              f"(construction only, at ~0.7 s/node)")
        sys.exit(0)

    print("═" * 78)
    print("  RQ3 Experiment B — Dependency Graph Shape Scaling")
    print(f"  dimensions={dims} repeats={cfg['repeats']} "
          f"max_nodes={MAX_NODES}")
    print(f"  chain={cfg['chain_sizes']} fan={cfg['fan_sizes']} "
          f"scc={cfg['scc_sizes']} concurrent={cfg['concurrent_sizes']} "
          f"diamond={cfg['diamond_widths']} decision_chain="
          f"{cfg['decision_chain']}")
    print("═" * 78)

    daemon_res = DaemonResources()
    pids = daemon_res.discover()
    print(f"[daemons] {pids}")
    missing = daemon_res.missing()
    if missing:
        print(f"[daemons] WARNING: not found -> {missing}; their CPU/RSS "
              f"columns will be empty (pidfiles are written by "
              f"start_and_run.sh)")

    # Observation-only connection: graph_stats/epoch_states must never share a
    # socket with a session that is mid-commit, or a snapshot reply can be read
    # as that commit's answer.
    obs = OrchClient()
    obs.connect()
    if not obs.graph_stats():
        print("[warn] graph_stats unavailable -- the running ShadowFS predates "
              "the instrumentation; graph shape, SCC detection and metadata "
              "memory columns will be empty")

    ensure_dep_dirs()
    all_results: List[DepGraphResult] = []
    reps = cfg["repeats"]

    try:
        if 1 in dims:
            all_results.extend(
                run_d1_chain(cfg["chain_sizes"], reps, obs, daemon_res))
        if 2 in dims:
            all_results.extend(
                run_d2_fan(cfg["fan_sizes"], reps, obs, daemon_res))
        if 3 in dims:
            all_results.extend(
                run_d3_scc(cfg["scc_sizes"], reps, obs, daemon_res))
        if 4 in dims:
            all_results.extend(
                run_d4_concurrent(cfg["concurrent_sizes"], reps, obs,
                                  daemon_res))
        if 5 in dims:
            all_results.extend(
                run_d5_decisions(cfg["decision_chain"], reps, obs, daemon_res))
        if 6 in dims:
            all_results.extend(
                run_d6_diamond(cfg["diamond_widths"], reps, obs, daemon_res))
        if 7 in dims:
            all_results.extend(
                run_d7_scc_publish(cfg["scc_sizes"], reps, obs, daemon_res))
    except KeyboardInterrupt:
        print("\n[interrupted]")
    except Exception as e:
        print(f"\n[FATAL] {e}")
        traceback.print_exc()
    finally:
        try:
            obs.close()
        except Exception:
            pass

    if all_results:
        save_results(all_results, args.output_dir, cfg)
        print_summary(all_results)

    cleanup_dep_dir()
    print("\n[done] Dependency graph scalability experiment complete.")


if __name__ == "__main__":
    main()
