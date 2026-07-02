#!/usr/bin/env python3
"""
ShadowOrchestrator - Unified orchestrator for ShadowFS, ShadowProc, and ShadowObserve.

Manages the lifecycle of all three components and coordinates commit/rollback
operations across the filesystem layer (ShadowFS), the process layer
(ShadowProc), and the observation/enforcement layer (ShadowObserve).

Usage:
    # As a library
    from shadow_orchestrator import ShadowOrchestrator
    orch = ShadowOrchestrator(shadowfs_sock="/tmp/shadowfs.sock",
                               shadowproc_sock="/tmp/shadowproc.sock",
                               shadowobserve_sock="/tmp/shadowobserve.sock")
    orch.start_observe("/shadow-demo", cgroup_inode=12345)
    orch.submit_policy("/shadow-demo", allowed_ops=[...])

    # As a standalone server
    python shadow_orchestrator.py --shadowfs-sock /tmp/shadowfs.sock \
                                   --shadowproc-sock /tmp/shadowproc.sock \
                                   --shadowobserve-sock /tmp/shadowobserve.sock \
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
import tempfile
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
    Orchestrates ShadowFS (file layer), ShadowProc (process layer),
    and ShadowObserve (observation/enforcement layer).

    Coordinates commit and rollback operations:
    - Commit: resume frozen processes, then commit filesystem changes.
    - Rollback: rollback filesystem (cascade), then kill affected frozen processes.
    - Submit Policy: freeze → audit → commit/rollback based on audit result.
    """

    def __init__(self, shadowfs_sock: str, shadowproc_sock: str,
                 shadowobserve_sock: Optional[str] = None):
        self.fs_client = SocketClient(shadowfs_sock)
        self.proc_client = SocketClient(shadowproc_sock)
        self.observe_client = None
        self.fs_client.connect()
        self.proc_client.connect()

        if shadowobserve_sock:
            self.observe_client = SocketClient(shadowobserve_sock)
            self.observe_client.connect()
            log.info("Connected to ShadowFS (%s), ShadowProc (%s), ShadowObserve (%s)",
                     shadowfs_sock, shadowproc_sock, shadowobserve_sock)
        else:
            log.info("Connected to ShadowFS (%s) and ShadowProc (%s)",
                     shadowfs_sock, shadowproc_sock)

        # Track observation state: cgroup_id → {log_path, cgroup_inode}
        self._observe_state: Dict[str, Dict[str, Any]] = {}

    def close(self):
        """Close connections to all services."""
        self.fs_client.close()
        self.proc_client.close()
        if self.observe_client:
            self.observe_client.close()

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

    def list_completed(self, cgroup_id: Optional[str] = None) -> List[dict]:
        """
        List processes that have completed execution and are being held
        (frozen at exit_group syscall, awaiting commit/rollback decision).

        Args:
            cgroup_id: Optional cgroup filter
        """
        req = {"action": "list_completed"}
        if cgroup_id:
            req["cgroup_id"] = cgroup_id
        resp = self.proc_client.request(req)
        return resp.get("frozen", [])

    # ──────────────────────────────────────────────────────────────────────
    # ShadowObserve integration
    # ──────────────────────────────────────────────────────────────────────

    def start_observe(self, cgroup_id: str, cgroup_inode: int,
                      log_path: Optional[str] = None) -> dict:
        """
        Start observing a cgroup via ShadowObserve.

        Args:
            cgroup_id: The cgroup identifier (e.g., "/shadow-demo")
            cgroup_inode: The cgroup directory inode number (uint64)
            log_path: Path for JSONL event log (auto-generated if None)
        """
        if not self.observe_client:
            return {"status": "error", "message": "ShadowObserve not configured"}

        if log_path is None:
            log_path = tempfile.mktemp(
                prefix=f"observ_{cgroup_id.strip('/').replace('/', '_')}_",
                suffix=".jsonl"
            )

        log.info("START_OBSERVE cgroup=%s inode=%d log=%s",
                 cgroup_id, cgroup_inode, log_path)

        resp = self.observe_client.request({
            "action": "start_observe",
            "cgroup_id": cgroup_inode,
            "log_path": log_path,
        })

        if resp.get("status") == "ok":
            self._observe_state[cgroup_id] = {
                "log_path": log_path,
                "cgroup_inode": cgroup_inode,
            }
            log.info("  Observation started: %s", log_path)
        else:
            log.error("  start_observe failed: %s", resp.get("message"))

        return resp

    def stop_observe(self, cgroup_id: str) -> dict:
        """
        Stop observing a cgroup.

        Args:
            cgroup_id: The cgroup identifier
        """
        if not self.observe_client:
            return {"status": "error", "message": "ShadowObserve not configured"}

        state = self._observe_state.get(cgroup_id)
        if not state:
            return {"status": "error", "message": f"No active observation for {cgroup_id}"}

        resp = self.observe_client.request({
            "action": "stop_observe",
            "cgroup_id": state["cgroup_inode"],
        })

        if resp.get("status") == "ok":
            log.info("STOP_OBSERVE cgroup=%s", cgroup_id)
        return resp

    def submit_policy(self, cgroup_id: str, allowed_ops: List[Dict]) -> dict:
        """
        Submit an allowed operations policy for a cgroup.

        This triggers the core orchestration flow:
        1. Freeze all processes in the cgroup (ShadowProc)
        2. Stop observation (ShadowObserve)
        3. Audit recorded events against allowed_ops
        4. If audit passes: install whitelist eBPF + commit files + resume processes
        5. If audit fails: rollback files + kill processes

        Args:
            cgroup_id: The cgroup identifier (e.g., "/shadow-demo")
            allowed_ops: List of allowed operation dicts, each with:
                - event_type: str ("OPEN", "CREATE", "DELETE", etc.) or "*" for any
                - action: "allow" or "deny"
                - path_pattern: str (prefix match, e.g., "/tmp/")

        Returns:
            dict with status="committed" or status="rolled_back"
        """
        if not self.observe_client:
            return {"status": "error", "message": "ShadowObserve not configured"}

        state = self._observe_state.get(cgroup_id)
        if not state:
            return {"status": "error",
                    "message": f"No active observation for {cgroup_id}. "
                               f"Call start_observe first."}

        log.info("SUBMIT_POLICY cgroup=%s rules=%d", cgroup_id, len(allowed_ops))

        # ── Step 1: Freeze all processes in the cgroup ──
        log.info("  Step 1: Freezing processes...")
        freeze_resp = self.proc_client.request({
            "action": "freeze_by_cgroup",
            "cgroup_id": cgroup_id,
        })
        if freeze_resp.get("status") != "ok":
            log.warning("  Freeze returned: %s (continuing anyway)",
                       freeze_resp.get("message"))
        else:
            frozen_pids = freeze_resp.get("pids", [])
            log.info("  Froze %d processes: %s", len(frozen_pids), frozen_pids)

        # ── Step 2: Stop observation (ensures log is complete) ──
        log.info("  Step 2: Stopping observation...")
        self.observe_client.request({
            "action": "stop_observe",
            "cgroup_id": state["cgroup_inode"],
        })

        # ── Step 3: Audit recorded events against policy ──
        log.info("  Step 3: Auditing events...")
        audit_rules = self._convert_policy_to_audit_rules(allowed_ops)
        audit_resp = self.observe_client.request({
            "action": "audit",
            "log_path": state["log_path"],
            "rules": audit_rules,
        })

        if audit_resp.get("status") != "ok":
            log.error("  Audit request failed: %s", audit_resp.get("message"))
            return {"status": "error", "message": "audit failed",
                    "detail": audit_resp.get("message")}

        total_violations = audit_resp.get("total_violations", 0)
        total_events = audit_resp.get("total_events", 0)
        log.info("  Audit result: %d events, %d violations",
                 total_events, total_violations)

        # ── Step 4: Decision based on audit ──
        if total_violations == 0:
            # AUDIT PASSED: install whitelist → commit → resume
            log.info("  Step 4: Audit PASSED - committing...")

            # Install whitelist eBPF filter
            whitelist_ops = self._convert_policy_to_whitelist(allowed_ops,
                                                             state["cgroup_inode"])
            wl_resp = self.observe_client.request({
                "action": "install_whitelist",
                "cgroup_id": state["cgroup_inode"],
                "allowed_ops": whitelist_ops,
            })
            if wl_resp.get("status") == "ok":
                log.info("  Whitelist installed: %s rules",
                         wl_resp.get("rules_added"))
            else:
                log.warning("  Whitelist install failed: %s",
                           wl_resp.get("message"))

            # Commit filesystem changes
            fs_resp = self.fs_client.request({
                "action": "commit",
                "cgroup_id": cgroup_id,
            })
            if fs_resp.get("status") == "ok":
                log.info("  ShadowFS commit successful")
            else:
                log.error("  ShadowFS commit failed: %s", fs_resp.get("message"))

            # Resume frozen processes
            resume_resp = self.proc_client.request({
                "action": "continue_by_cgroup",
                "cgroup_id": cgroup_id,
            })
            if resume_resp.get("status") == "ok":
                log.info("  Processes resumed: %s", resume_resp.get("pids", []))

            # Cleanup observation state
            del self._observe_state[cgroup_id]

            return {
                "status": "ok",
                "decision": "committed",
                "total_events": total_events,
                "total_violations": 0,
            }
        else:
            # AUDIT FAILED: rollback → kill
            log.info("  Step 4: Audit FAILED (%d violations) - rolling back...",
                     total_violations)

            violations = audit_resp.get("violations", [])
            for v in violations[:5]:  # Log first 5
                log.info("    VIOLATION: %s", v.get("description", str(v)))

            # Rollback filesystem
            fs_resp = self.fs_client.request({
                "action": "rollback",
                "cgroup_id": cgroup_id,
            })
            affected = []
            if fs_resp.get("status") == "ok":
                affected = fs_resp.get("affected", [])
                log.info("  ShadowFS rollback successful, affected: %s", affected)
            else:
                log.error("  ShadowFS rollback failed: %s", fs_resp.get("message"))

            # Kill frozen processes (all affected cgroups)
            total_killed = []
            kill_cgroups = affected if affected else [cgroup_id]
            for cg in kill_cgroups:
                kill_resp = self.proc_client.request({
                    "action": "kill_by_cgroup",
                    "cgroup_id": cg,
                })
                if kill_resp.get("status") == "ok":
                    killed = kill_resp.get("pids", [])
                    total_killed.extend(killed)

            if total_killed:
                log.info("  Killed PIDs: %s", total_killed)

            # Cleanup observation state
            del self._observe_state[cgroup_id]

            return {
                "status": "ok",
                "decision": "rolled_back",
                "total_events": total_events,
                "total_violations": total_violations,
                "violations": violations,
                "killed_pids": total_killed,
            }

    @staticmethod
    def _convert_policy_to_audit_rules(allowed_ops: List[Dict]) -> List[Dict]:
        """
        Convert user-facing policy format to ShadowObserve audit rules.

        Allowed ops format:
            [{"event_type": "CREATE", "action": "allow", "path_pattern": "/tmp/"}]

        Audit rules format:
            [{"event_type": 2, "action": "allow", "path_pattern": "/tmp/"}]
        """
        EVENT_TYPE_MAP = {
            "OPEN": 1, "CREATE": 2, "DELETE": 3, "RENAME": 4,
            "CHMOD": 5, "CHOWN": 6, "MKDIR": 7, "RMDIR": 8,
            "LINK": 9, "SYMLINK": 10, "TRUNCATE": 11,
            "EXEC": 100, "FORK": 101, "EXIT": 102, "KILL": 103,
            "SETUID": 106, "CAPSET": 107, "EXEC_PRIV": 108,
            "*": -1, "ANY": -1,
        }
        rules = []
        for op in allowed_ops:
            event_str = op.get("event_type", "*").upper()
            event_num = EVENT_TYPE_MAP.get(event_str, -1)
            rules.append({
                "event_type": event_num,
                "action": op.get("action", "allow"),
                "path_pattern": op.get("path_pattern", ""),
            })
        return rules

    @staticmethod
    def _convert_policy_to_whitelist(allowed_ops: List[Dict],
                                     cgroup_inode: int) -> List[Dict]:
        """
        Convert allowed_ops to whitelist format for eBPF enforcer.

        Whitelist format:
            [{"event_type": 2, "path_prefix": "/tmp/"}]
        """
        EVENT_TYPE_MAP = {
            "OPEN": 1, "CREATE": 2, "DELETE": 3, "RENAME": 4,
            "CHMOD": 5, "CHOWN": 6, "MKDIR": 7, "RMDIR": 8,
            "LINK": 9, "SYMLINK": 10, "TRUNCATE": 11,
            "EXEC": 100, "FORK": 101, "EXIT": 102, "KILL": 103,
            "SETUID": 106, "CAPSET": 107, "EXEC_PRIV": 108,
            "*": 0xFFFF, "ANY": 0xFFFF,
        }
        whitelist = []
        for op in allowed_ops:
            if op.get("action", "allow").lower() != "allow":
                continue
            event_str = op.get("event_type", "*").upper()
            event_num = EVENT_TYPE_MAP.get(event_str, 0xFFFF)
            whitelist.append({
                "event_type": event_num,
                "path_prefix": op.get("path_pattern", ""),
            })
        return whitelist


# ──────────────────────────────────────────────────────────────────────────────
# Standalone server mode: expose the orchestrator's API via its own Unix socket
# ──────────────────────────────────────────────────────────────────────────────

class OrchestratorServer:
    """
    Exposes the ShadowOrchestrator API over a Unix socket.

    Protocol: JSON-line request/response (same pattern as ShadowFS/ShadowProc).

    Supported actions:
        commit, rollback, add_cgroup, list_agents, list_frozen, get_affected,
        start_observe, stop_observe, submit_policy
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

            elif action == "list_completed":
                completed = self.orch.list_completed(cgroup_id or None)
                return {"status": "ok", "completed": completed}

            elif action == "get_affected":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                affected = self.orch.get_affected(cgroup_id)
                return {"status": "ok", "affected": affected}

            elif action == "start_observe":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                cgroup_inode = req.get("cgroup_inode", 0)
                if not cgroup_inode:
                    return {"status": "error", "message": "cgroup_inode required"}
                log_path = req.get("log_path", None)
                return self.orch.start_observe(cgroup_id, int(cgroup_inode), log_path)

            elif action == "stop_observe":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                return self.orch.stop_observe(cgroup_id)

            elif action == "submit_policy":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                allowed_ops = req.get("allowed_ops", [])
                if not allowed_ops:
                    return {"status": "error", "message": "allowed_ops required"}
                return self.orch.submit_policy(cgroup_id, allowed_ops)

            else:
                return {"status": "error", "message": f"unknown action: {action}"}

        except Exception as e:
            log.exception("Error handling request: %s", req)
            return {"status": "error", "message": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="ShadowOrchestrator - coordinate ShadowFS, ShadowProc, and ShadowObserve"
    )
    parser.add_argument("--shadowfs-sock", required=True,
                        help="Unix socket path to ShadowFS")
    parser.add_argument("--shadowproc-sock", required=True,
                        help="Unix socket path to ShadowProc")
    parser.add_argument("--shadowobserve-sock", default=None,
                        help="Unix socket path to ShadowObserve (optional)")
    parser.add_argument("--listen", required=True,
                        help="Unix socket path for orchestrator API")
    args = parser.parse_args()

    orch = ShadowOrchestrator(args.shadowfs_sock, args.shadowproc_sock,
                              args.shadowobserve_sock)
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
