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
from typing import Any, Dict, Optional, Tuple

from .timing import Timer


ORCH_SOCK = os.environ.get("SHADOW_ORCH_SOCK", "/tmp/shadow-orch.sock")


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

    # ─── Timed operations ─────────────────────────────────────────────────

    def timed_begin_epoch(self, session_id: str,
                          agent_id: str = "rq3-bench") -> Tuple[Dict, int]:
        """Begin epoch and return (response, elapsed_ns)."""
        with Timer() as t:
            resp = self.session_begin_epoch(session_id, agent_id)
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
