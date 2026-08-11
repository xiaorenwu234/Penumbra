#!/usr/bin/env python3
"""Unix socket JSON-line clients for ShadowProc, ShadowFS, and ShadowObserve.

Mirrors the communication protocol used by test_kernel_effect_decisions.py and
the orchestrator's SocketClient: newline-delimited JSON over AF_UNIX.
"""

import json
import os
import socket
import threading
from typing import Any, Dict, Optional


class DaemonClient:
    """Thread-safe Unix socket JSON-line client for a Shadow daemon."""

    def __init__(self, sock_path: str, name: str = "daemon"):
        self.sock_path = sock_path
        self.name = name
        self._sock: Optional[socket.socket] = None
        self._file = None
        self._lock = threading.Lock()

    def connect(self):
        """Connect to the Unix domain socket."""
        if not os.path.exists(self.sock_path):
            raise FileNotFoundError(
                f"{self.name} socket not found: {self.sock_path}")
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(10.0)
        self._sock.connect(self.sock_path)
        self._file = self._sock.makefile("rw", buffering=1)

    def close(self):
        """Close the connection."""
        with self._lock:
            if self._file:
                self._file.close()
                self._file = None
            if self._sock:
                self._sock.close()
                self._sock = None

    def request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON request and return the JSON response (thread-safe)."""
        with self._lock:
            if not self._sock:
                self.connect()
            line = json.dumps(req) + "\n"
            self._file.write(line)
            self._file.flush()
            resp_line = self._file.readline()
            if not resp_line:
                raise ConnectionError(
                    f"{self.name}: connection closed during {req.get('action')}")
            return json.loads(resp_line)

    def request_ok(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Send a request and assert status==ok."""
        resp = self.request(req)
        if resp.get("status") != "ok":
            raise RuntimeError(
                f"{self.name} {req.get('action')} failed: {resp}")
        return resp

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


class ShadowProcClient(DaemonClient):
    """Client for the ShadowProc daemon (process-layer BPF enforcement).

    Key actions:
      add_cgroup, remove_cgroup, set_epoch_mode, install_class_policy,
      install_proc_policy, list_frozen, freeze_by_cgroup, continue_by_cgroup,
      commit_by_cgroup, reject_by_cgroup, kill_by_cgroup, clear_all_policies
    """

    def __init__(self, sock_path: str = None):
        path = sock_path or os.environ.get(
            "SHADOWPROC_SOCK", "/tmp/shadow_proc.sock")
        super().__init__(path, name="ShadowProc")

    def add_cgroup(self, cgroup_path: str) -> Dict:
        return self.request_ok({
            "action": "add_cgroup", "cgroup_path": cgroup_path})

    def remove_cgroup(self, cgroup_path: str) -> Dict:
        return self.request_ok({
            "action": "remove_cgroup", "cgroup_path": cgroup_path})

    def set_epoch_mode(self, cgroup_path: str, mode: int) -> Dict:
        """Set epoch mode: 0=SPECULATIVE, 1=AUTHORIZED_PENDING, 2=ENFORCED.
        cgroup_path should be relative to /sys/fs/cgroup (e.g. /shadow-rq2/xxx)."""
        return self.request_ok({
            "action": "set_epoch_mode", "cgroup_path": cgroup_path,
            "mode": mode})

    def install_class_policy(self, cgroup_path: str, effect_class: int,
                             operation: int, allow: int) -> Dict:
        """Install a single class-level policy entry.
        cgroup_path should be relative to /sys/fs/cgroup."""
        return self.request_ok({
            "action": "install_class_policy", "cgroup_path": cgroup_path,
            "effect_class": effect_class, "operation": operation,
            "allow": allow})

    def install_proc_policy(self, cgroup_path: str, policy: Dict) -> Dict:
        """Install a full proc_policy by iterating its class entries.

        Translates PolicyIR.to_proc_policy() output into individual
        install_class_policy calls (the ShadowProc daemon API).
        cgroup_path should be relative to /sys/fs/cgroup.
        """
        for cls_entry in policy.get("classes", []):
            self.install_class_policy(
                cgroup_path,
                cls_entry["effect_class"],
                cls_entry["operation"],
                1 if cls_entry.get("mode", 0) >= 1 else 0)
        return {"status": "ok"}

    def clear_all_policies(self, cgroup_path: str) -> Dict:
        """cgroup_path should be relative to /sys/fs/cgroup."""
        return self.request_ok({
            "action": "clear_all_policies", "cgroup_path": cgroup_path})

    def list_frozen(self, cgroup_id: str) -> list:
        resp = self.request_ok({"action": "list_frozen", "cgroup_id": cgroup_id})
        return resp.get("frozen", [])

    def freeze_by_cgroup(self, cgroup_id: str) -> Dict:
        return self.request_ok({
            "action": "freeze_by_cgroup", "cgroup_id": cgroup_id})

    def continue_by_cgroup(self, cgroup_id: str, policy: Dict = None) -> Dict:
        req = {"action": "continue_by_cgroup", "cgroup_id": cgroup_id}
        if policy is not None:
            req["policy"] = policy
        return self.request_ok(req)

    def continue_with_policy(self, cgroup_id: str, policy: Dict) -> Dict:
        """Continue frozen processes with fine-grained policy (mode=2).

        The policy dict follows the proc_policy schema:
          {
            "classes": [{"effect_class": N, "operation": N, "mode": 2}, ...],
            "network": [{"operation": N, "family": N, "addr": u32, "port": u16, "allow": 1}, ...],
            "ipc": [{"operation": N, "ipc_type": N, "target": u64, "allow": 1}, ...],
            "signal": [{"operation": N, "target_cgroup": u64, "allow": 1}, ...]
          }
        """
        return self.request_ok({
            "action": "continue_by_cgroup",
            "cgroup_id": cgroup_id,
            "policy": policy
        })

    def commit_by_cgroup(self, cgroup_id: str) -> Dict:
        return self.request_ok({
            "action": "commit_by_cgroup", "cgroup_id": cgroup_id})

    def reject_by_cgroup(self, cgroup_id: str) -> Dict:
        return self.request_ok({
            "action": "reject_by_cgroup", "cgroup_id": cgroup_id})

    def kill_by_cgroup(self, cgroup_id: str) -> Dict:
        return self.request_ok({
            "action": "kill_by_cgroup", "cgroup_id": cgroup_id})


class ShadowFSClient(DaemonClient):
    """Client for the ShadowFS daemon (filesystem-layer FUSE overlay).

    Key actions:
      list_agents, begin_epoch, commit, rollback, can_release,
      ack_release, prepare_resolution, begin_finalize, get_finalize_status,
      ack_release_group, retry_finalize
    """

    def __init__(self, sock_path: str = None):
        path = sock_path or os.environ.get(
            "SHADOWFS_SOCK", "/tmp/shadowfs.sock")
        super().__init__(path, name="ShadowFS")

    def list_agents(self) -> list:
        resp = self.request_ok({"action": "list_agents"})
        return resp.get("agents_info", [])

    def begin_epoch(self, cgroup_id: str, epoch_id: str) -> Dict:
        return self.request_ok({
            "action": "begin_epoch", "cgroup_id": cgroup_id,
            "epoch_id": epoch_id})

    def commit(self, cgroup_id: str, epoch_id: str = None) -> Dict:
        req = {"action": "commit", "cgroup_id": cgroup_id}
        if epoch_id:
            req["epoch_id"] = epoch_id
        return self.request_ok(req)

    def rollback(self, cgroup_id: str, epoch_id: str = None) -> Dict:
        req = {"action": "rollback", "cgroup_id": cgroup_id}
        if epoch_id:
            req["epoch_id"] = epoch_id
        return self.request_ok(req)

    def can_release(self, cgroup_id: str) -> bool:
        resp = self.request({"action": "can_release", "cgroup_id": cgroup_id})
        return resp.get("status") == "ok" and resp.get("releasable", False)

    def ack_release(self, cgroup_id: str) -> Dict:
        return self.request_ok({
            "action": "ack_release", "cgroup_id": cgroup_id})

    def prepare_resolution(self, cgroup_id: str, epoch_id: str) -> Dict:
        return self.request_ok({
            "action": "prepare_resolution", "cgroup_id": cgroup_id,
            "epoch_id": epoch_id})

    def begin_finalize(self, cgroup_id: str, epoch_id: str) -> Dict:
        return self.request_ok({
            "action": "begin_finalize", "cgroup_id": cgroup_id,
            "epoch_id": epoch_id})

    def get_finalize_status(self, cgroup_id: str, epoch_id: str) -> str:
        resp = self.request_ok({
            "action": "get_finalize_status", "cgroup_id": cgroup_id,
            "epoch_id": epoch_id})
        return resp.get("state", "unknown")

    def ack_release_group(self, group_id: int) -> Dict:
        return self.request_ok({
            "action": "ack_release_group", "group_id": group_id})


class ShadowObserveClient(DaemonClient):
    """Client for the ShadowObserve daemon (audit engine + BPF observer).

    Key actions:
      start_observe, stop_observe, audit, install_whitelist
    """

    def __init__(self, sock_path: str = None):
        path = sock_path or os.environ.get(
            "SHADOWOBSERVE_SOCK", "/tmp/shadow_observe.sock")
        super().__init__(path, name="ShadowObserve")

    def start_observe(self, cgroup_id: str, cgroup_inode: int,
                      log_path: str) -> Dict:
        return self.request_ok({
            "action": "start_observe", "cgroup_id": cgroup_id,
            "cgroup_inode": cgroup_inode, "log_path": log_path})

    def stop_observe(self, cgroup_id: str) -> Dict:
        return self.request_ok({
            "action": "stop_observe", "cgroup_id": cgroup_id})

    def audit(self, cgroup_id: str, log_path: str,
              rules: list) -> Dict:
        return self.request_ok({
            "action": "audit", "cgroup_id": cgroup_id,
            "log_path": log_path, "rules": rules})

    def install_whitelist(self, cgroup_id: str, entries: list) -> Dict:
        return self.request_ok({
            "action": "install_whitelist", "cgroup_id": cgroup_id,
            "entries": entries})
