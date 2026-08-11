#!/usr/bin/env python3
"""Cgroup v2 lifecycle management for RQ2 experiments.

Handles creation, process placement, and teardown of test cgroups under
/sys/fs/cgroup. Each experiment trial gets an isolated cgroup so BPF
attribution is unambiguous.
"""

import os
import shutil
import time
from typing import List, Optional


CGROUP_ROOT = os.environ.get("SHADOW_CGROUP_ROOT", "/sys/fs/cgroup")


class CgroupManager:
    """Manages ephemeral cgroup v2 hierarchies for experiment probes."""

    def __init__(self, root: str = None, prefix: str = "shadow-rq2"):
        self.root = root or CGROUP_ROOT
        self.prefix = prefix
        self._created: List[str] = []

    def create(self, name: Optional[str] = None) -> str:
        """Create a new cgroup and return its absolute path.

        If name is None, generates a unique name from pid + timestamp.
        """
        if name is None:
            name = f"{self.prefix}-{os.getpid()}-{int(time.time() * 1000)}"
        path = os.path.join(self.root, name)
        os.makedirs(path, exist_ok=True)
        self._created.append(path)
        return path

    def create_nested(self, parent_path: str, child_name: str) -> str:
        """Create a child cgroup under parent_path."""
        path = os.path.join(parent_path, child_name)
        os.makedirs(path, exist_ok=True)
        if path not in self._created:
            self._created.append(path)
        return path

    def add_proc(self, cgroup_path: str, pid: int):
        """Place a process into the cgroup."""
        procs_file = os.path.join(cgroup_path, "cgroup.procs")
        with open(procs_file, "w") as f:
            f.write(str(pid))

    def get_procs(self, cgroup_path: str) -> List[int]:
        """List all PIDs in the cgroup."""
        procs_file = os.path.join(cgroup_path, "cgroup.procs")
        try:
            with open(procs_file, "r") as f:
                return [int(line.strip()) for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def get_cgroup_id(self, cgroup_path: str) -> str:
        """Return the cgroup identifier used by ShadowProc (relative path).

        This is the path relative to /sys/fs/cgroup with a leading /,
        used for list_frozen, kill_by_cgroup, continue_by_cgroup, etc.
        Example: /shadow-rq2/exp1-fence-fs_write-0-123
        """
        rel = os.path.relpath(cgroup_path, self.root)
        return f"/{rel}"

    def get_relative_path(self, cgroup_path: str) -> str:
        """Return the path relative to /sys/fs/cgroup (for set_epoch_mode,
        install_class_policy, clear_all_policies).

        ShadowProc's cgroup_id_from_path() prepends /sys/fs/cgroup to this.
        Example: /shadow-rq2/exp1-fence-fs_write-0-123
        """
        rel = os.path.relpath(cgroup_path, self.root)
        return f"/{rel}"

    def get_inode(self, cgroup_path: str) -> int:
        """Get the cgroup directory inode (used as cgroup_inode for BPF)."""
        return os.stat(cgroup_path).st_ino

    def remove(self, cgroup_path: str):
        """Remove a cgroup (must be empty of processes)."""
        try:
            os.rmdir(cgroup_path)
        except OSError:
            # Try killing remaining processes first
            for pid in self.get_procs(cgroup_path):
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass
            time.sleep(0.1)
            try:
                os.rmdir(cgroup_path)
            except OSError:
                pass
        if cgroup_path in self._created:
            self._created.remove(cgroup_path)

    def cleanup_all(self):
        """Remove all cgroups created by this manager (reverse order)."""
        for path in reversed(self._created[:]):
            self.remove(path)
        self._created.clear()

    def enable_controllers(self, cgroup_path: str,
                           controllers: List[str] = None):
        """Enable subtree controllers (needed for nested cgroups)."""
        if controllers is None:
            controllers = ["cpuset", "cpu", "io", "memory", "pids"]
        parent = os.path.dirname(cgroup_path)
        subtree = os.path.join(parent, "cgroup.subtree_control")
        try:
            with open(subtree, "w") as f:
                f.write(" ".join(f"+{c}" for c in controllers))
        except OSError:
            pass  # Not all controllers may be available

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup_all()
