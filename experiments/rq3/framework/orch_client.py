#!/usr/bin/env python3
"""Orchestrator session API client for RQ3 performance experiments.

Communicates with the ShadowOrchestrator daemon over its Unix socket
using the JSON-line protocol. Provides session lifecycle management
and epoch operations with integrated timing.
"""

import json
import os
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

from .timing import Timer


ORCH_SOCK = os.environ.get("SHADOW_ORCH_SOCK", "/tmp/shadow-orch.sock")


# Cumulative graph-maintenance counters. These are the ONLY graph_stats fields
# for which a difference is meaningful: the remaining fields are an
# instantaneous shape (epochs/edges/scc_*) or a whole-process memory reading
# (heap_*/sys_bytes), where the second sample is the value to report.
GRAPH_COUNTER_KEYS = (
    "edge_insertions", "edge_insert_ns",
    "scc_computations", "scc_compute_ns",
    "affected_queries", "affected_query_ns", "affected_nodes_total",
    "prepare_calls", "prepare_ns",
    "finalize_calls", "finalize_ns", "finalized_nodes_total",
    "finalize_rejected_toctou",
    "rollbacks", "rollback_ns", "rollback_nodes_total",
)

# Fields describing the live graph at the moment of the sample.
GRAPH_SHAPE_KEYS = (
    "epochs", "edges", "versions", "objects", "graph_generation",
    "scc_count", "cyclic_scc_count", "max_scc_size", "active_groups",
)

# Whole-daemon memory, reported as-is from the later sample.
GRAPH_MEMORY_KEYS = ("heap_alloc_bytes", "heap_inuse_bytes", "sys_bytes",
                     "goroutines")


def graph_delta(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Attribute the graph work done between two snapshots to a phase.

    Prefer this over graph_stats(reset=True): a delta needs no mutation of the
    shared daemon, so a crashed or interrupted phase cannot leave the counters
    zeroed for whoever runs next.

    The returned dict carries three groups, so a results table can tell them
    apart:
      counters  after-before for every GRAPH_COUNTER_KEYS entry
      shape     the AFTER value of the instantaneous fields, under `shape_*`
      memory    the AFTER value of the daemon memory fields, under `mem_*`

    Derived per-invocation figures (edges per invocation, nanoseconds per SCC
    sweep) are deliberately NOT computed here: they need the invocation count,
    which only the calling experiment knows. Dividing by a count this function
    cannot see is how a scaling curve ends up quietly wrong.
    """
    out: Dict[str, Any] = {}
    for key in GRAPH_COUNTER_KEYS:
        a = before.get(key) or 0
        b = after.get(key) or 0
        out[key] = b - a
    for key in GRAPH_SHAPE_KEYS:
        out[f"shape_{key}"] = after.get(key)
    for key in GRAPH_MEMORY_KEYS:
        out[f"mem_{key}"] = after.get(key)
    return out


class OrchClient:
    """Client for the ShadowOrchestrator session API.

    Provides session_open, session_begin_epoch, session_run,
    session_commit_epoch, session_rollback_epoch, session_close.
    """

    def __init__(self, sock_path: str = None):
        self.sock_path = sock_path or ORCH_SOCK
        self._sock: Optional[socket.socket] = None
        self._file = None

    def connect(self):
        """Connect to the orchestrator Unix socket."""
        if not os.path.exists(self.sock_path):
            raise FileNotFoundError(
                f"Orchestrator socket not found: {self.sock_path}\n"
                f"Start the orchestrator with --listen {self.sock_path}")
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(120.0)  # Long timeout for large workloads
        self._sock.connect(self.sock_path)
        self._file = self._sock.makefile("rw", buffering=1)

    def close(self):
        """Close the connection."""
        if self._file:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON request and return the JSON response."""
        if not self._sock:
            self.connect()
        line = json.dumps(req) + "\n"
        self._file.write(line)
        self._file.flush()
        resp_line = self._file.readline()
        if not resp_line:
            raise ConnectionError(
                f"Orchestrator connection closed during {req.get('action')}")
        return json.loads(resp_line)

    def request_ok(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Send a request and assert status==ok."""
        resp = self.request(req)
        if resp.get("status") != "ok":
            raise RuntimeError(
                f"Orchestrator {req.get('action')} failed: "
                f"{resp.get('message', resp)}")
        return resp

    # ─── Session lifecycle ────────────────────────────────────────────────

    def session_open(self, agent_id: str = "rq3-bench") -> Dict:
        """Open a new session. Returns {session_id, cgroup_id, ...}."""
        return self.request_ok({
            "action": "session_open",
            "agent_id": agent_id,
        })

    def session_close(self, session_id: str) -> Dict:
        """Close a session."""
        return self.request_ok({
            "action": "session_close",
            "session_id": session_id,
        })

    # ─── Epoch operations ─────────────────────────────────────────────────

    def session_begin_epoch(self, session_id: str,
                            agent_id: str = "rq3-bench") -> Dict:
        """Begin a speculative epoch. Returns {epoch_id, cgroup_id}."""
        return self.request_ok({
            "action": "session_begin_epoch",
            "session_id": session_id,
            "agent_id": agent_id,
        })

    def session_run(self, session_id: str, command: str) -> Dict:
        """Run a command in the session's live shell.

        Returns {stdout, exit_code, ...}.
        """
        return self.request_ok({
            "action": "session_run",
            "session_id": session_id,
            "command": command,
        })

    def session_pin_epoch_cpu(self, session_id: str, cpu: int) -> Dict:
        """Pin the session's live speculative shell to one CPU.

        One call covers every command the epoch runs (the candidate shell
        is long-lived), matching the raw baseline's single `taskset`
        wrapper without paying the taskset startup once per run.
        """
        return self.request_ok({
            "action": "session_pin_epoch_cpu",
            "session_id": session_id,
            "cpu": cpu,
        })

    def session_commit_epoch(self, session_id: str,
                             agent_id: str = "rq3-bench",
                             allowed_ops: list = None) -> Dict:
        """Commit the current epoch (finalize + release).

        allowed_ops is MANDATORY: the typed prospective policy that authorizes
        the epoch's effects. Defaults to a wildcard allow for benchmarks.
        """
        if allowed_ops is None:
            allowed_ops = [{"event_type": "*", "action": "allow",
                            "path_pattern": "/"}]
        return self.request_ok({
            "action": "session_commit_epoch",
            "session_id": session_id,
            "agent_id": agent_id,
            "allowed_ops": allowed_ops,
        })

    def session_resolve_epoch(self, session_id: str,
                              agent_id: str = "rq3-bench",
                              decision: str = "allow",
                              allowed_ops: list = None,
                              policy_metadata: dict = None) -> Dict:
        """Unified authorization-resolution interface.

        decision='allow' commits with the typed policy;
        decision='deny' rolls back losslessly.
        """
        if allowed_ops is None and decision == "allow":
            allowed_ops = [{"event_type": "*", "action": "allow",
                            "path_pattern": "/"}]
        req = {
            "action": "session_resolve_epoch",
            "session_id": session_id,
            "agent_id": agent_id,
            "decision": decision,
        }
        if allowed_ops is not None:
            req["allowed_ops"] = allowed_ops
        if policy_metadata is not None:
            req["policy_metadata"] = policy_metadata
        return self.request_ok(req)

    def session_rollback_epoch(self, session_id: str,
                               agent_id: str = "rq3-bench") -> Dict:
        """Rollback the current epoch (discard changes)."""
        return self.request_ok({
            "action": "session_rollback_epoch",
            "session_id": session_id,
            "agent_id": agent_id,
        })

    # ─── Dependency graph queries ─────────────────────────────────────────

    def get_affected(self, cgroup_id: str) -> Dict:
        """Query which cgroups would be affected by a rollback (dry-run).

        Returns {status, affected: [cgroup_id, ...]}.
        Used to verify that cross-epoch dependencies actually formed
        before measuring finalization cost.
        """
        return self.request_ok({
            "action": "get_affected",
            "cgroup_id": cgroup_id,
        })

    def graph_stats(self, reset: bool = False) -> Dict[str, Any]:
        """Dependency-graph shape + cumulative maintenance counters.

        Returns the `graph` object (see GRAPH_*_KEYS), or {} if the daemon does
        not implement the action -- an older ShadowFS must degrade a column of
        the results table, not abort a multi-hour experiment.

        Sample OUTSIDE timed intervals: the snapshot runs a full Tarjan sweep
        and runtime.ReadMemStats, which stops the Go world.
        """
        resp = self.request({"action": "graph_stats", "reset": bool(reset)})
        if resp.get("status") != "ok":
            return {}
        return resp.get("graph") or {}

    def epoch_states(self) -> List[Dict[str, Any]]:
        """Per-epoch ShadowFS state: [{epoch_id, state, versions, cgroup_id}].

        Needed because a contended commit can legitimately return
        `authorized_pending` -- an SCC member that authorized before its
        siblings -- and the experiment must then poll to the real outcome
        instead of recording the first response as final.
        """
        resp = self.request({"action": "epoch_states"})
        if resp.get("status") != "ok":
            return []
        return resp.get("epochs") or []

    def wait_epochs_gone(self, epoch_ids: List[str], timeout: float = 60.0,
                         interval: float = 0.02) -> Tuple[bool, int, List[str]]:
        """Poll until every listed epoch has left the graph.

        A committed epoch is finalized (edges dropped) and then acked (node
        dropped), so "gone" is the observable end state of a successful commit;
        a rolled-back epoch leaves the same way. Returns
        (all_gone, elapsed_ns, states_seen) where states_seen is the last state
        each epoch was observed in -- empty string once it has left.

        This measures the DRAIN after publication: the gap between a commit
        returning and the component actually leaving the graph, which is what a
        later session opening the same files would have to wait out. It is not
        the finalization wait itself -- that is measured by the caller retrying
        an `authorized_pending` reply, because the orchestrator's own background
        retry loop ticks every 2 s and would quantize any wait read through it
        to that interval instead of to the size of the graph.
        """
        want = set(epoch_ids)
        t0 = time.perf_counter_ns()
        seen: Dict[str, str] = {e: "" for e in want}
        deadline = time.perf_counter() + timeout
        while True:
            present = {e["epoch_id"]: e.get("state", "")
                       for e in self.epoch_states() if e.get("epoch_id") in want}
            for eid, st in present.items():
                seen[eid] = st
            if not present:
                return True, time.perf_counter_ns() - t0, [seen[e] for e in epoch_ids]
            if time.perf_counter() >= deadline:
                return (False, time.perf_counter_ns() - t0,
                        [seen.get(e) or present.get(e, "missing") for e in epoch_ids])
            time.sleep(interval)

    # ─── Timed operations ─────────────────────────────────────────────────

    def timed_begin_epoch(self, session_id: str,
                          agent_id: str = "rq3-bench") -> Tuple[Dict, int]:
        """Begin epoch and return (response, elapsed_ns)."""
        with Timer() as t:
            resp = self.session_begin_epoch(session_id, agent_id)
        return resp, t.elapsed_ns

    def timed_open(self, agent_id: str = "rq3-bench") -> Tuple[Dict, int]:
        """Open a session and return (response, elapsed_ns).

        session_open creates the cgroup and forks the baseline shell, so under
        agent scaling it is a real cost of admitting one more agent and has to
        be reported separately from the per-invocation epoch begin.
        """
        with Timer() as t:
            resp = self.session_open(agent_id)
        return resp, t.elapsed_ns

    def timed_run(self, session_id: str, command: str) -> Tuple[Dict, int]:
        """Run command and return (response, elapsed_ns)."""
        with Timer() as t:
            resp = self.session_run(session_id, command)
        return resp, t.elapsed_ns

    def timed_pin_epoch_cpu(self, session_id: str,
                            cpu: int) -> Tuple[Dict, int]:
        """Pin epoch candidate and return (response, elapsed_ns)."""
        with Timer() as t:
            resp = self.session_pin_epoch_cpu(session_id, cpu)
        return resp, t.elapsed_ns

    def timed_commit(self, session_id: str,
                     agent_id: str = "rq3-bench",
                     allowed_ops: list = None) -> Tuple[Dict, int]:
        """Commit epoch and return (response, elapsed_ns)."""
        with Timer() as t:
            resp = self.session_commit_epoch(session_id, agent_id,
                                            allowed_ops=allowed_ops)
        return resp, t.elapsed_ns

    def timed_resolve(self, session_id: str,
                      agent_id: str = "rq3-bench",
                      decision: str = "allow",
                      allowed_ops: list = None) -> Tuple[Dict, int]:
        """Resolve epoch (commit or rollback) and return (response, elapsed_ns)."""
        with Timer() as t:
            resp = self.session_resolve_epoch(session_id, agent_id,
                                             decision=decision,
                                             allowed_ops=allowed_ops)
        return resp, t.elapsed_ns

    def timed_rollback(self, session_id: str,
                       agent_id: str = "rq3-bench") -> Tuple[Dict, int]:
        """Rollback epoch and return (response, elapsed_ns)."""
        with Timer() as t:
            resp = self.session_rollback_epoch(session_id, agent_id)
        return resp, t.elapsed_ns

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()
