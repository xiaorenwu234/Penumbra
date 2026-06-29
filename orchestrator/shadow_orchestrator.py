#!/usr/bin/env python3
"""
ShadowOrchestrator - Unified orchestrator for ShadowFS and ShadowProc.

Manages the lifecycle of both components and coordinates commit/rollback
operations across the filesystem layer (ShadowFS) and the process layer
(ShadowProc).

Usage:
    # As a library
    from shadow_orchestrator import ShadowOrchestrator
    orch = ShadowOrchestrator(shadowfs_sock="/tmp/shadowfs.sock",
                               shadowproc_sock="/tmp/shadowproc.sock")
    orch.commit("/user.slice/shadow-agent-1")
    orch.rollback("/user.slice/shadow-agent-1")

    # As a standalone server
    python shadow_orchestrator.py --shadowfs-sock /tmp/shadowfs.sock \
                                   --shadowproc-sock /tmp/shadowproc.sock \
                                   --listen /tmp/shadow-orch.sock
"""

import json
import socket
import os
import sys
import argparse
import logging
import threading
import signal
from typing import Optional, List, Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("orchestrator")


class SocketClient:
    """Simple Unix socket JSON-line client."""

    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self._sock: Optional[socket.socket] = None

    def connect(self):
        """Connect to the Unix socket."""
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self.sock_path)
        self._file = self._sock.makefile("rw", buffering=1)

    def close(self):
        """Close the connection."""
        if self._sock:
            self._sock.close()
            self._sock = None

    def request(self, data: dict) -> dict:
        """Send a JSON request and return the JSON response."""
        if not self._sock:
            self.connect()
        line = json.dumps(data) + "\n"
        self._file.write(line)
        self._file.flush()
        resp_line = self._file.readline()
        if not resp_line:
            raise ConnectionError(f"Connection to {self.sock_path} closed")
        return json.loads(resp_line)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


class ShadowOrchestrator:
    """
    Orchestrates ShadowFS (file layer) and ShadowProc (process layer).

    Coordinates commit and rollback operations:
    - Commit: resume frozen processes, then commit filesystem changes.
    - Rollback: rollback filesystem (cascade), then kill affected frozen processes.
    """

    def __init__(self, shadowfs_sock: str, shadowproc_sock: str):
        self.fs_client = SocketClient(shadowfs_sock)
        self.proc_client = SocketClient(shadowproc_sock)
        self.fs_client.connect()
        self.proc_client.connect()
        log.info("Connected to ShadowFS (%s) and ShadowProc (%s)",
                 shadowfs_sock, shadowproc_sock)

    def close(self):
        """Close connections to both services."""
        self.fs_client.close()
        self.proc_client.close()

    def add_cgroup(self, cgroup_path: str) -> dict:
        """
        Register a new cgroup for monitoring by ShadowProc.

        Args:
            cgroup_path: Filesystem path to the cgroup
                         (e.g., /sys/fs/cgroup/user.slice/shadow)
        """
        resp = self.proc_client.request({
            "action": "add_cgroup",
            "cgroup_path": cgroup_path,
        })
        if resp["status"] != "ok":
            log.error("add_cgroup failed: %s", resp.get("message"))
        else:
            log.info("Registered cgroup: %s", cgroup_path)
        return resp

    def commit(self, cgroup_id: str) -> dict:
        """
        Commit changes for a cgroup.

        Flow:
        1. Check if ShadowProc has frozen processes for this cgroup.
        2. If yes, resume them (continue_by_cgroup).
        3. Tell ShadowFS to commit the agent.

        Args:
            cgroup_id: The cgroup identifier (path from /proc/<pid>/cgroup)
        """
        log.info("COMMIT cgroup=%s", cgroup_id)

        # Step 1: Check and resume frozen processes
        frozen_resp = self.proc_client.request({
            "action": "list_frozen",
            "cgroup_id": cgroup_id,
        })
        if frozen_resp["status"] == "ok" and frozen_resp.get("frozen"):
            frozen_count = len(frozen_resp["frozen"])
            log.info("  Found %d frozen process(es), resuming...", frozen_count)
            resume_resp = self.proc_client.request({
                "action": "continue_by_cgroup",
                "cgroup_id": cgroup_id,
            })
            if resume_resp["status"] == "ok":
                pids = resume_resp.get("pids", [])
                log.info("  Resumed PIDs: %s", pids)
            else:
                log.warning("  Resume failed: %s", resume_resp.get("message"))

        # Step 2: Commit in ShadowFS
        fs_resp = self.fs_client.request({
            "action": "commit",
            "cgroup_id": cgroup_id,
        })
        if fs_resp["status"] == "ok":
            log.info("  ShadowFS commit successful")
        else:
            log.error("  ShadowFS commit failed: %s", fs_resp.get("message"))

        return fs_resp

    def rollback(self, cgroup_id: str) -> dict:
        """
        Rollback changes for a cgroup (with cascade).

        Flow:
        1. Tell ShadowFS to rollback (returns affected cgroup list).
        2. For each affected cgroup, kill any frozen processes in ShadowProc.

        Args:
            cgroup_id: The cgroup identifier (path from /proc/<pid>/cgroup)
        """
        log.info("ROLLBACK cgroup=%s", cgroup_id)

        # Step 1: Rollback in ShadowFS (cascade)
        fs_resp = self.fs_client.request({
            "action": "rollback",
            "cgroup_id": cgroup_id,
        })
        if fs_resp["status"] != "ok":
            log.error("  ShadowFS rollback failed: %s", fs_resp.get("message"))
            return fs_resp

        affected = fs_resp.get("affected", [])
        log.info("  ShadowFS rollback successful, affected cgroups: %s", affected)

        # Step 2: Kill frozen processes for all affected cgroups
        total_killed = []
        for affected_cgroup in affected:
            kill_resp = self.proc_client.request({
                "action": "kill_by_cgroup",
                "cgroup_id": affected_cgroup,
            })
            if kill_resp["status"] == "ok":
                killed = kill_resp.get("pids", [])
                if killed:
                    log.info("  Killed PIDs in cgroup %s: %s",
                             affected_cgroup, killed)
                    total_killed.extend(killed)

        if total_killed:
            log.info("  Total killed processes: %d", len(total_killed))

        return {"status": "ok", "affected": affected, "killed_pids": total_killed}

    def list_agents(self) -> List[str]:
        """List all active ShadowFS agents."""
        resp = self.fs_client.request({"action": "list_agents"})
        return resp.get("agents", [])

    def list_frozen(self, cgroup_id: Optional[str] = None) -> List[dict]:
        """List frozen processes, optionally filtered by cgroup."""
        if cgroup_id:
            resp = self.proc_client.request({
                "action": "list_frozen",
                "cgroup_id": cgroup_id,
            })
        else:
            resp = self.proc_client.request({"action": "list_all_frozen"})
        return resp.get("frozen", [])

    def get_affected(self, cgroup_id: str) -> List[str]:
        """Get cgroups that would be affected by a rollback (dry-run)."""
        resp = self.fs_client.request({
            "action": "rollback_affected",
            "cgroup_id": cgroup_id,
        })
        return resp.get("affected", [])


# ──────────────────────────────────────────────────────────────────────────────
# Standalone server mode: expose the orchestrator's API via its own Unix socket
# ──────────────────────────────────────────────────────────────────────────────

class OrchestratorServer:
    """
    Exposes the ShadowOrchestrator API over a Unix socket.

    Protocol: JSON-line request/response (same pattern as ShadowFS/ShadowProc).

    Supported actions:
        commit, rollback, add_cgroup, list_agents, list_frozen, get_affected
    """

    def __init__(self, orchestrator: ShadowOrchestrator, listen_path: str):
        self.orch = orchestrator
        self.listen_path = listen_path
        self._running = True

    def serve(self):
        """Run the server (blocking)."""
        if os.path.exists(self.listen_path):
            os.remove(self.listen_path)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.listen_path)
        server.listen(16)
        server.settimeout(1.0)
        log.info("Orchestrator API listening on %s", self.listen_path)

        while self._running:
            try:
                conn, _ = server.accept()
                t = threading.Thread(target=self._handle_conn, args=(conn,),
                                     daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

        server.close()
        if os.path.exists(self.listen_path):
            os.remove(self.listen_path)

    def stop(self):
        self._running = False

    def _handle_conn(self, conn: socket.socket):
        try:
            f = conn.makefile("rw", buffering=1)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError as e:
                    resp = {"status": "error", "message": f"invalid JSON: {e}"}
                    f.write(json.dumps(resp) + "\n")
                    f.flush()
                    continue

                resp = self._dispatch(req)
                f.write(json.dumps(resp) + "\n")
                f.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()

    def _dispatch(self, req: dict) -> dict:
        action = req.get("action", "")
        cgroup_id = req.get("cgroup_id", "")
        cgroup_path = req.get("cgroup_path", "")

        try:
            if action == "commit":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                return self.orch.commit(cgroup_id)

            elif action == "rollback":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                return self.orch.rollback(cgroup_id)

            elif action == "add_cgroup":
                if not cgroup_path:
                    return {"status": "error", "message": "cgroup_path required"}
                return self.orch.add_cgroup(cgroup_path)

            elif action == "list_agents":
                agents = self.orch.list_agents()
                return {"status": "ok", "agents": agents}

            elif action == "list_frozen":
                frozen = self.orch.list_frozen(cgroup_id or None)
                return {"status": "ok", "frozen": frozen}

            elif action == "get_affected":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                affected = self.orch.get_affected(cgroup_id)
                return {"status": "ok", "affected": affected}

            else:
                return {"status": "error", "message": f"unknown action: {action}"}

        except Exception as e:
            log.exception("Error handling request: %s", req)
            return {"status": "error", "message": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="ShadowOrchestrator - coordinate ShadowFS and ShadowProc"
    )
    parser.add_argument("--shadowfs-sock", required=True,
                        help="Unix socket path to ShadowFS")
    parser.add_argument("--shadowproc-sock", required=True,
                        help="Unix socket path to ShadowProc")
    parser.add_argument("--listen", required=True,
                        help="Unix socket path for orchestrator API")
    args = parser.parse_args()

    orch = ShadowOrchestrator(args.shadowfs_sock, args.shadowproc_sock)
    server = OrchestratorServer(orch, args.listen)

    def sig_handler(signum, frame):
        log.info("Shutting down...")
        server.stop()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        server.serve()
    finally:
        orch.close()
        log.info("Orchestrator stopped.")


if __name__ == "__main__":
    main()
