#!/usr/bin/env python3
"""Thin client for the ShadowOrchestrator JSON-line Unix socket API.

One connection per request: the orchestrator serves each connection on its own
thread and a guarded tool call can block for a long time inside the per-agent
barrier, so sharing a connection between threads would interleave replies.
"""

from __future__ import annotations

import json
import os
import socket
import time
from typing import Any, Dict, List, Optional


class PenumbraError(RuntimeError):
    """Base class for every error this integration raises."""


class OrchestratorUnavailable(PenumbraError):
    """The orchestrator socket is missing or refused the connection."""


class OrchestratorError(PenumbraError):
    """The orchestrator answered with ``status != "ok"``."""

    def __init__(self, action: str, response: Dict[str, Any]):
        self.action = action
        self.response = response
        message = response.get("message") or json.dumps(response)
        super().__init__(f"{action} failed: {message}")


class OrchestratorClient:
    """JSON-line client for the orchestrator API."""

    def __init__(self, sock_path: str, timeout: float = 180.0):
        self.sock_path = sock_path
        self.timeout = timeout

    # ── transport ────────────────────────────────────────────────────────

    def is_listening(self) -> bool:
        """True when something accepts connections on the socket path."""
        if not os.path.exists(self.sock_path):
            return False
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect(self.sock_path)
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def wait_until_listening(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.is_listening():
                return True
            time.sleep(0.1)
        return False

    def request(self, action: str, timeout: Optional[float] = None,
                extra: Optional[Dict[str, Any]] = None,
                **payload) -> Dict[str, Any]:
        """Send one request and return the parsed response dict.

        ``extra`` carries request fields whose names collide with this method's
        own parameters (notably the API's own ``timeout`` field).
        """
        req = {"action": action}
        req.update({k: v for k, v in payload.items() if v is not None})
        if extra:
            req.update({k: v for k, v in extra.items() if v is not None})
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout if timeout is not None else self.timeout)
        try:
            sock.connect(self.sock_path)
        except OSError as exc:
            sock.close()
            raise OrchestratorUnavailable(
                f"cannot reach orchestrator at {self.sock_path}: {exc}. "
                f"Call penumbra.start() first, or point PENUMBRA_ORCH_SOCK at "
                f"a running orchestrator.") from exc
        try:
            stream = sock.makefile("rw", buffering=1)
            stream.write(json.dumps(req) + "\n")
            stream.flush()
            line = stream.readline()
            if not line:
                raise OrchestratorUnavailable(
                    f"orchestrator closed the connection during {action!r}")
            return json.loads(line)
        except socket.timeout as exc:
            raise OrchestratorUnavailable(
                f"orchestrator timed out during {action!r} after "
                f"{sock.gettimeout()}s") from exc
        finally:
            sock.close()

    def request_ok(self, action: str, timeout: Optional[float] = None,
                   extra: Optional[Dict[str, Any]] = None,
                   **payload) -> Dict[str, Any]:
        """Like :meth:`request` but raise unless the response is ``ok``."""
        resp = self.request(action, timeout=timeout, extra=extra, **payload)
        if resp.get("status") != "ok":
            raise OrchestratorError(action, resp)
        return resp

    # ── session lifecycle ────────────────────────────────────────────────

    def session_open(self, agent_id: str,
                     cgroup_name: Optional[str] = None) -> Dict[str, Any]:
        return self.request_ok("session_open", agent_id=agent_id,
                               cgroup_name=cgroup_name)

    def session_close(self, session_id: str) -> Dict[str, Any]:
        return self.request_ok("session_close", session_id=session_id)

    def session_list(self) -> List[str]:
        return self.request_ok("session_list").get("sessions", [])

    # ── epoch lifecycle ─────────────────────────────────────────────────

    def session_begin_epoch(self, session_id: str,
                            agent_id: str) -> Dict[str, Any]:
        return self.request_ok("session_begin_epoch", session_id=session_id,
                               agent_id=agent_id)

    def session_run(self, session_id: str, command: str,
                    timeout: float = 60.0) -> Dict[str, Any]:
        # The socket read must outlive the command the orchestrator is waiting
        # on, otherwise a slow command looks like a dead daemon.
        return self.request_ok("session_run", timeout=timeout + 30.0,
                               session_id=session_id, command=command,
                               extra={"timeout": timeout})

    def session_resolve_epoch(self, session_id: str, agent_id: str,
                              decision: str,
                              allowed_ops: Optional[List[Dict]] = None,
                              policy_metadata: Optional[Dict] = None
                              ) -> Dict[str, Any]:
        return self.request_ok("session_resolve_epoch", session_id=session_id,
                               agent_id=agent_id, decision=decision,
                               allowed_ops=allowed_ops,
                               policy_metadata=policy_metadata)

    def session_rollback_epoch(self, session_id: str,
                               agent_id: str) -> Dict[str, Any]:
        return self.request_ok("session_rollback_epoch", session_id=session_id,
                               agent_id=agent_id)

    def session_get_output(self, session_id: str) -> str:
        return self.request_ok("session_get_output",
                               session_id=session_id).get("output", "")

    # ── diagnostics ──────────────────────────────────────────────────────

    def drain_violations(self, cgroup_id: str = "") -> List[Dict[str, Any]]:
        """Fenced process-layer effects recorded for a cgroup (best effort).

        Diagnostics only: a failure here must never block a resolution, so the
        caller treats an error as "no violations observed".
        """
        try:
            resp = self.request("drain_violations", cgroup_id=cgroup_id)
        except PenumbraError:
            return []
        if resp.get("status") != "ok":
            return []
        return resp.get("violations", []) or []

    def get_affected(self, cgroup_id: str) -> List[str]:
        return self.request_ok("get_affected",
                               cgroup_id=cgroup_id).get("affected", [])

    def list_agents(self) -> List[Any]:
        return self.request_ok("list_agents").get("agents", [])
