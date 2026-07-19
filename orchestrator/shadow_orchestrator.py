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

        # Track stdout buffer files: cgroup_id → output_file_path
        # Populated via register_output(); flushed on commit; discarded on rollback.
        self._output_buffers: Dict[str, str] = {}

        # Deferred external-operation release.
        #
        # A cgroup may be committed (user intent) while its upstream
        # dependencies in ShadowFS are not yet fully committed. In that
        # window ShadowFS holds the agent's file changes un-promoted so a
        # cascade rollback can still undo them. ShadowProc MUST likewise
        # keep the agent's processes frozen so their IPC / network side
        # effects don't escape prematurely. Such cgroups are parked here
        # and released once ShadowFS reports their upstreams are committed
        # (see _try_release_pending).
        self._pending_release: set = set()
        self._pending_lock = threading.Lock()

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

    def register_output(self, cgroup_id: str, output_file: str) -> dict:
        """
        Register a stdout/stderr buffer file for a cgroup.

        Launchers (e.g. cgroup_exec via SHADOW_OUTPUT_FILE env) redirect the
        agent's stdout/stderr into this file. The buffered output is only
        released to the caller on commit; on rollback it is discarded.
        """
        self._output_buffers[cgroup_id] = output_file
        log.info("Registered stdout buffer for cgroup=%s → %s",
                 cgroup_id, output_file)
        return {"status": "ok", "output_file": output_file}

    def _flush_output(self, cgroup_id: str) -> str:
        """Read and remove the buffered stdout for a cgroup. Returns the content."""
        output_file = self._output_buffers.pop(cgroup_id, None)
        if not output_file:
            return ""
        try:
            with open(output_file, "r", errors="replace") as f:
                content = f.read()
        except FileNotFoundError:
            return ""
        except OSError as e:
            log.warning("Failed to read buffered stdout %s: %s", output_file, e)
            return ""
        try:
            os.unlink(output_file)
        except OSError:
            pass
        return content

    def _discard_output(self, cgroup_id: str) -> None:
        """Discard the buffered stdout for a cgroup (used on rollback)."""
        output_file = self._output_buffers.pop(cgroup_id, None)
        if output_file:
            try:
                os.unlink(output_file)
            except OSError:
                pass

    def get_buffered_output(self, cgroup_id: str) -> dict:
        """Return the current buffered stdout for a cgroup without flushing it."""
        output_file = self._output_buffers.get(cgroup_id)
        if not output_file:
            return {"status": "ok", "output": "", "buffered": False}
        try:
            with open(output_file, "r", errors="replace") as f:
                content = f.read()
            return {"status": "ok", "output": content, "buffered": True,
                    "output_file": output_file}
        except FileNotFoundError:
            return {"status": "ok", "output": "", "buffered": False}
        except OSError as e:
            return {"status": "error", "message": str(e)}

    def _fs_can_release(self, cgroup_id: str) -> bool:
        """
        Ask ShadowFS whether a cgroup's external side effects are safe to
        release, i.e. all of its upstream dependencies are committed.

        This is the SAME gate ShadowFS uses to promote the agent's file
        changes, so ShadowProc's process layer stays consistent with the
        filesystem layer.
        """
        resp = self.fs_client.request({
            "action": "can_release",
            "cgroup_id": cgroup_id,
        })
        if resp.get("status") != "ok":
            # Unknown / not tracked by ShadowFS: no filesystem dependency
            # can cascade a rollback into it, so it is safe to release.
            return True
        return bool(resp.get("releasable", True))

    def _release_proc(self, cgroup_id: str) -> str:
        """
        Resume ShadowProc's frozen processes for a cgroup (letting their
        held IPC / network / exit operations proceed) and flush the
        cgroup's buffered stdout to the caller.

        Returns the flushed stdout content.
        """
        frozen_resp = self.proc_client.request({
            "action": "list_frozen",
            "cgroup_id": cgroup_id,
        })
        if frozen_resp.get("status") == "ok" and frozen_resp.get("frozen"):
            frozen_count = len(frozen_resp["frozen"])
            log.info("  Releasing %d frozen process(es) for cgroup=%s",
                     frozen_count, cgroup_id)
            resume_resp = self.proc_client.request({
                "action": "continue_by_cgroup",
                "cgroup_id": cgroup_id,
            })
            if resume_resp.get("status") == "ok":
                log.info("  Resumed PIDs: %s", resume_resp.get("pids", []))
            else:
                log.warning("  Resume failed: %s", resume_resp.get("message"))

        buffered = self._flush_output(cgroup_id)
        if buffered:
            log.info("  Releasing %d bytes of buffered stdout for cgroup=%s",
                     len(buffered), cgroup_id)
        return buffered

    def _try_release_pending(self) -> None:
        """
        Re-evaluate every deferred cgroup and release those whose upstream
        dependencies have since been committed. Committing one cgroup can
        unblock previously-deferred downstream cgroups, so this is called
        after every commit.
        """
        with self._pending_lock:
            pending = list(self._pending_release)
        for cg in pending:
            if self._fs_can_release(cg):
                log.info("  Upstream now committed — releasing deferred "
                         "cgroup=%s", cg)
                self._release_proc(cg)
                with self._pending_lock:
                    self._pending_release.discard(cg)

    def commit(self, cgroup_id: str) -> dict:
        """
        Commit changes for a cgroup.

        Flow:
        1. Commit filesystem changes in ShadowFS FIRST, so the dependency
           graph reflects this commit before any release decision.
        2. Release the cgroup's frozen processes ONLY if all of its
           upstream dependencies are committed. Otherwise defer the
           release (keep the processes frozen and stdout buffered) until a
           later upstream commit unblocks it.
        3. Re-evaluate previously-deferred cgroups this commit may unblock.

        Args:
            cgroup_id: The cgroup identifier (path from /proc/<pid>/cgroup)
        """
        log.info("COMMIT cgroup=%s", cgroup_id)

        # Step 1: Commit in ShadowFS first.
        fs_resp = self.fs_client.request({
            "action": "commit",
            "cgroup_id": cgroup_id,
        })
        if fs_resp["status"] != "ok":
            log.error("  ShadowFS commit failed: %s", fs_resp.get("message"))
            return fs_resp
        log.info("  ShadowFS commit successful")

        # Step 2: Gate the process-layer release on upstream commit status.
        if self._fs_can_release(cgroup_id):
            fs_resp["stdout"] = self._release_proc(cgroup_id)
            fs_resp["released"] = True
        else:
            with self._pending_lock:
                self._pending_release.add(cgroup_id)
            log.info("  Deferring release of cgroup=%s: upstream "
                     "dependencies not fully committed yet", cgroup_id)
            fs_resp["stdout"] = ""
            fs_resp["released"] = False
            fs_resp["deferred"] = True

        # Step 3: This commit may have unblocked deferred downstream cgroups.
        self._try_release_pending()

        return fs_resp

    def _rollback_proc(self, cgroup_id: str) -> dict:
        """
        Roll back ShadowProc's process layer for a cgroup.

        Long-lived speculative sessions are rolled back LOSSLESSLY: discard the
        candidate (and its epoch descendants) and RESUME the pristine baseline
        via reject_by_cgroup, so the session's shell survives with its identity,
        session and parent lineage intact. Only NON-versioned frozen processes
        (e.g. one-shot audited processes with no active epoch) are killed.

        This replaces the old kill-everything path, which would have destroyed a
        long-lived session's shell along with its speculative work.

        Returns {"resumed": [...baseline pids...], "killed": [...pids...]}.
        """
        resumed: List[int] = []
        killed: List[int] = []

        # Step 1: Reject any active speculative epochs — discard the candidate,
        # resume the pristine baseline. Lossless; the canonical pid is unchanged.
        reject_resp = self.proc_client.request({
            "action": "reject_by_cgroup",
            "cgroup_id": cgroup_id,
        })
        if reject_resp.get("status") == "ok":
            resumed = reject_resp.get("pids", []) or []
            if resumed:
                log.info("  Restored %d baseline(s) in cgroup %s: %s",
                         len(resumed), cgroup_id, resumed)
        else:
            log.warning("  reject_by_cgroup failed for %s: %s",
                        cgroup_id, reject_resp.get("message"))

        # Step 2: Kill any remaining NON-versioned frozen processes. The
        # just-resumed baselines were removed from ShadowProc's frozen set by the
        # reject, so they are not affected here.
        kill_resp = self.proc_client.request({
            "action": "kill_by_cgroup",
            "cgroup_id": cgroup_id,
        })
        if kill_resp.get("status") == "ok":
            killed = kill_resp.get("pids", []) or []
            if killed:
                log.info("  Killed %d non-versioned process(es) in cgroup %s: %s",
                         len(killed), cgroup_id, killed)

        return {"resumed": resumed, "killed": killed}

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

        # Step 2: Roll back the process layer for all affected cgroups. Each
        # long-lived speculative session is restored to its pristine baseline
        # (lossless); only non-versioned frozen processes are killed.
        total_killed = []
        total_resumed = []
        for affected_cgroup in affected:
            res = self._rollback_proc(affected_cgroup)
            total_resumed.extend(res["resumed"])
            total_killed.extend(res["killed"])

        if total_resumed:
            log.info("  Total baselines restored: %d", len(total_resumed))
        if total_killed:
            log.info("  Total killed processes: %d", len(total_killed))

        # Discard buffered stdout for all affected cgroups.
        for affected_cgroup in affected:
            self._discard_output(affected_cgroup)
        self._discard_output(cgroup_id)

        # Drop any deferred releases for cgroups undone by this cascade:
        # their processes were rolled back, so there is nothing to release.
        with self._pending_lock:
            for affected_cgroup in affected:
                self._pending_release.discard(affected_cgroup)
            self._pending_release.discard(cgroup_id)

        return {"status": "ok", "affected": affected,
                "killed_pids": total_killed, "resumed_pids": total_resumed}

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
            log_path = tempfile.mkstemp(
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
            buffered = ""
            fs_resp = self.fs_client.request({
                "action": "commit",
                "cgroup_id": cgroup_id,
            })
            if fs_resp.get("status") == "ok":
                log.info("  ShadowFS commit successful")
            else:
                log.error("  ShadowFS commit failed: %s", fs_resp.get("message"))

            # Release frozen processes only when all upstream dependencies
            # are committed; otherwise defer until a later upstream commit
            # unblocks this cgroup (keeps IPC / stdout held).
            released = False
            if self._fs_can_release(cgroup_id):
                buffered = self._release_proc(cgroup_id)
                released = True
            else:
                with self._pending_lock:
                    self._pending_release.add(cgroup_id)
                log.info("  Deferring release of cgroup=%s: upstream "
                         "dependencies not fully committed yet", cgroup_id)

            # Cleanup observation state
            del self._observe_state[cgroup_id]

            # This commit may unblock previously-deferred downstream cgroups.
            self._try_release_pending()

            return {
                "status": "ok",
                "decision": "committed",
                "total_events": total_events,
                "total_violations": 0,
                "stdout": buffered,
                "released": released,
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

            # Roll back the process layer (all affected cgroups). Long-lived
            # speculative sessions are restored to their pristine baseline
            # (lossless); only non-versioned frozen processes are killed.
            total_killed = []
            total_resumed = []
            kill_cgroups = affected if affected else [cgroup_id]
            for cg in kill_cgroups:
                res = self._rollback_proc(cg)
                total_resumed.extend(res["resumed"])
                total_killed.extend(res["killed"])

            if total_resumed:
                log.info("  Restored baselines: %s", total_resumed)
            if total_killed:
                log.info("  Killed PIDs: %s", total_killed)

            # Discard buffered stdout for all affected cgroups
            for cg in kill_cgroups:
                self._discard_output(cg)

            # Drop any deferred releases for the undone cgroups.
            with self._pending_lock:
                for cg in kill_cgroups:
                    self._pending_release.discard(cg)

            # Cleanup observation state
            del self._observe_state[cgroup_id]

            return {
                "status": "ok",
                "decision": "rolled_back",
                "total_events": total_events,
                "total_violations": total_violations,
                "violations": violations,
                "killed_pids": total_killed,
                "resumed_pids": total_resumed,
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

            elif action == "register_output":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                output_file = req.get("output_file", "")
                if not output_file:
                    return {"status": "error", "message": "output_file required"}
                return self.orch.register_output(cgroup_id, output_file)

            elif action == "get_output":
                if not cgroup_id:
                    return {"status": "error", "message": "cgroup_id required"}
                return self.orch.get_buffered_output(cgroup_id)

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
