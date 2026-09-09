#!/usr/bin/env python3
"""Orchestrator session-API client for the RQ2 experiments.

RQ2 measures the *system*, so every lifecycle step goes through the real
ShadowOrchestrator (freeze -> drain -> seal -> batch audit -> promote/rollback
-> release) instead of poking ShadowFS/ShadowProc directly from the harness.

Transport notes:
  * One connection per request. A guarded ``session_run`` can block inside the
    per-agent barrier for a long time, and RQ2 deliberately issues
    ``session_run`` from a worker thread while the main thread fences/resolve
    the same session. Sharing a socket would interleave the two replies.
  * Every non-``ok`` reply and every transport failure is turned into an
    :class:`~framework.errors.InfrastructureError`. Those are INFRA_ERROR
    outcomes: they must never be swallowed into a passing property check.
"""

import json
import os
import socket
import time
from typing import Any, Dict, List, Optional

from .errors import InfrastructureError

# The launcher exports PENUMBRA_ORCH_SOCK; SHADOW_ORCH_SOCK is kept as an alias
# because RQ3 uses that name for the same socket.
DEFAULT_ORCH_SOCK = "/tmp/shadow-orch.sock"


def orch_sock_path() -> str:
    return (os.environ.get("PENUMBRA_ORCH_SOCK")
            or os.environ.get("SHADOW_ORCH_SOCK")
            or DEFAULT_ORCH_SOCK)


class OrchClient:
    """JSON-line client for the ShadowOrchestrator session API."""

    def __init__(self, sock_path: Optional[str] = None,
                 timeout: float = 180.0):
        self.sock_path = sock_path or orch_sock_path()
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

    def wait_until_listening(self, timeout: float = 30.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.is_listening():
                return True
            time.sleep(0.1)
        return False

    def require_listening(self):
        """Fail closed when the orchestrator is not reachable."""
        if not self.is_listening():
            raise InfrastructureError(
                "orchestrator_socket",
                f"orchestrator socket is not accepting connections: "
                f"{self.sock_path}")

    def request(self, action: str, timeout: Optional[float] = None,
                extra: Optional[Dict[str, Any]] = None,
                **payload) -> Dict[str, Any]:
        """Send one request and return the parsed reply.

        ``extra`` carries request fields whose names collide with this method's
        own parameters (notably the API's own ``timeout`` field).
        """
        req: Dict[str, Any] = {"action": action}
        req.update({k: v for k, v in payload.items() if v is not None})
        if extra:
            req.update({k: v for k, v in extra.items() if v is not None})

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout if timeout is not None else self.timeout)
        try:
            sock.connect(self.sock_path)
        except OSError as exc:
            sock.close()
            raise InfrastructureError(
                "orchestrator_connect",
                f"cannot reach orchestrator at {self.sock_path}", exc)
        try:
            stream = sock.makefile("rw", buffering=1)
            stream.write(json.dumps(req) + "\n")
            stream.flush()
            line = stream.readline()
            if not line:
                raise InfrastructureError(
                    "orchestrator_eof",
                    f"orchestrator closed the connection during {action!r}")
            return json.loads(line)
        except socket.timeout as exc:
            raise InfrastructureError(
                "orchestrator_timeout",
                f"orchestrator timed out during {action!r} after "
                f"{sock.gettimeout()}s", exc)
        except json.JSONDecodeError as exc:
            raise InfrastructureError(
                "orchestrator_protocol",
                f"orchestrator returned malformed JSON for {action!r}", exc)
        finally:
            sock.close()

    def request_ok(self, action: str, timeout: Optional[float] = None,
                   extra: Optional[Dict[str, Any]] = None,
                   **payload) -> Dict[str, Any]:
        """Like :meth:`request` but raise INFRA_ERROR unless the reply is ok."""
        resp = self.request(action, timeout=timeout, extra=extra, **payload)
        if resp.get("status") != "ok":
            raise InfrastructureError(
                f"orchestrator_{action}",
                str(resp.get("message") or json.dumps(resp)))
        return resp

    # ── session lifecycle ────────────────────────────────────────────────

    def session_open(self, agent_id: str,
                     cgroup_name: Optional[str] = None) -> Dict[str, Any]:
        """Open a persistent session. Returns {session_id, cgroup_id, agent_id}."""
        return self.request_ok("session_open", agent_id=agent_id,
                               cgroup_name=cgroup_name)

    def session_close(self, session_id: str) -> Dict[str, Any]:
        return self.request_ok("session_close", session_id=session_id)

    def session_list(self) -> List[str]:
        return self.request_ok("session_list").get("sessions", [])

    # ── epoch lifecycle ─────────────────────────────────────────────────

    def session_begin_epoch(self, session_id: str,
                            agent_id: str) -> Dict[str, Any]:
        """Fork the candidate and register the ShadowFS epoch.

        Returns {cgroup_id, epoch_id}. A failure here means the epoch never
        existed, so nothing downstream may be interpreted as a security result.
        """
        return self.request_ok("session_begin_epoch", session_id=session_id,
                               agent_id=agent_id)

    def session_run(self, session_id: str, command: str,
                    timeout: float = 60.0) -> Dict[str, Any]:
        """Run one command in the session's live candidate shell.

        The socket read must outlive the command, otherwise a fenced (i.e.
        deliberately blocked) syscall looks like a dead daemon.
        """
        return self.request_ok("session_run", timeout=timeout + 30.0,
                               session_id=session_id, command=command,
                               extra={"timeout": timeout})

    def session_resolve_epoch(self, session_id: str, agent_id: str,
                              decision: str,
                              allowed_ops: Optional[List[Dict]] = None,
                              policy_metadata: Optional[Dict] = None,
                              timeout: float = 180.0) -> Dict[str, Any]:
        """Unified authorization resolution (audit + promote/rollback).

        ``decision='allow'`` compiles ``allowed_ops`` into one PolicyIR that the
        orchestrator uses BOTH to audit the sealed trace (retrospective) and to
        install the prospective proc_policy. If the sealed trace contains an
        operation that policy does not allow, the orchestrator rejects the epoch
        on its own and reports it in the reply (``audit`` block, ``resolved``).
        ``decision='deny'`` rolls the epoch back losslessly.
        """
        return self.request_ok("session_resolve_epoch", timeout=timeout,
                               session_id=session_id, agent_id=agent_id,
                               decision=decision, allowed_ops=allowed_ops,
                               policy_metadata=policy_metadata)

    def session_rollback_epoch(self, session_id: str,
                               agent_id: str) -> Dict[str, Any]:
        return self.request_ok("session_rollback_epoch", session_id=session_id,
                               agent_id=agent_id)

    def session_get_output(self, session_id: str) -> str:
        """Committed (commit-gated) transcript of the session."""
        return self.request_ok("session_get_output",
                               session_id=session_id).get("output", "")

    # ── diagnostics / observation ────────────────────────────────────────

    def get_affected(self, cgroup_id: str) -> List[str]:
        """Cgroup set that a rollback of ``cgroup_id`` would cascade to."""
        return self.request_ok("get_affected",
                               cgroup_id=cgroup_id).get("affected", [])

    def drain_violations(self, cgroup_id: str = "") -> List[Dict[str, Any]]:
        """Fenced process-layer effects recorded for a cgroup (best effort).

        Diagnostics only: a failure here must never block a resolution, so the
        caller treats an error as "no violations observed".
        """
        try:
            resp = self.request("drain_violations", cgroup_id=cgroup_id)
        except InfrastructureError:
            return []
        if resp.get("status") != "ok":
            return []
        return resp.get("violations", []) or []

    def list_frozen(self, cgroup_id: str = "") -> List[Any]:
        try:
            resp = self.request("list_frozen", cgroup_id=cgroup_id)
        except InfrastructureError:
            return []
        if resp.get("status") != "ok":
            return []
        return resp.get("frozen", []) or []

    def list_agents(self) -> List[Any]:
        return self.request_ok("list_agents").get("agents", [])
