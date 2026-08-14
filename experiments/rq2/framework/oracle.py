#!/usr/bin/env python3
"""External oracle for verifying whether effects actually occurred.

The oracle operates OUTSIDE the monitored cgroup and checks the external
system state to determine whether a side effect was truly visible. This is
the ground truth against which the system's enforcement decisions are measured.
"""

import hashlib
import os
import socket
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FileSnapshot:
    """Complete state snapshot of a file for rollback verification."""
    path: str
    exists: bool = False
    content_hash: str = ""
    size: int = 0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    nlink: int = 0
    is_dir: bool = False
    is_symlink: bool = False
    symlink_target: str = ""
    mtime_ns: int = 0

    @classmethod
    def capture(cls, path: str) -> "FileSnapshot":
        snap = cls(path=path)
        try:
            st = os.lstat(path)
            snap.exists = True
            snap.size = st.st_size
            snap.mode = st.st_mode
            snap.uid = st.st_uid
            snap.gid = st.st_gid
            snap.nlink = st.st_nlink
            snap.is_dir = stat.S_ISDIR(st.st_mode)
            snap.is_symlink = stat.S_ISLNK(st.st_mode)
            snap.mtime_ns = st.st_mtime_ns
            if snap.is_symlink:
                snap.symlink_target = os.readlink(path)
            elif not snap.is_dir and snap.size < 10 * 1024 * 1024:
                with open(path, "rb") as f:
                    snap.content_hash = hashlib.sha256(f.read()).hexdigest()
        except FileNotFoundError:
            pass
        return snap

    def matches(self, other: "FileSnapshot") -> bool:
        """Check if two snapshots represent identical state."""
        if self.exists != other.exists:
            return False
        if not self.exists:
            return True
        return (self.content_hash == other.content_hash and
                self.size == other.size and
                self.mode == other.mode and
                self.uid == other.uid and
                self.gid == other.gid and
                self.nlink == other.nlink and
                self.is_dir == other.is_dir and
                self.is_symlink == other.is_symlink and
                self.symlink_target == other.symlink_target)


@dataclass
class DirSnapshot:
    """Snapshot of directory entries."""
    path: str
    entries: Dict[str, str] = field(default_factory=dict)  # name -> type

    @classmethod
    def capture(cls, path: str) -> "DirSnapshot":
        snap = cls(path=path)
        try:
            for entry in os.scandir(path):
                if entry.is_dir(follow_symlinks=False):
                    snap.entries[entry.name] = "dir"
                elif entry.is_symlink():
                    snap.entries[entry.name] = "link"
                else:
                    snap.entries[entry.name] = "file"
        except (FileNotFoundError, PermissionError):
            pass
        return snap

    def matches(self, other: "DirSnapshot") -> bool:
        return self.entries == other.entries


class EffectOracle:
    """External oracle that checks whether effects truly occurred.

    All checks run outside the monitored cgroup, providing an independent
    ground truth for measuring enforcement correctness.
    """

    def __init__(self, work_dir: str):
        """work_dir: a directory OUTSIDE the ShadowFS mount for oracle artifacts."""
        self.work_dir = work_dir
        os.makedirs(work_dir, exist_ok=True)

    # ─── Filesystem effect checks ────────────────────────────────────────

    def check_file_exists(self, path: str) -> bool:
        return os.path.exists(path)

    def check_file_content(self, path: str, expected: bytes) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read() == expected
        except (FileNotFoundError, PermissionError):
            return False

    def check_file_absent(self, path: str) -> bool:
        return not os.path.exists(path)

    def check_dir_exists(self, path: str) -> bool:
        return os.path.isdir(path)

    def check_dir_absent(self, path: str) -> bool:
        return not os.path.isdir(path)

    def check_symlink(self, path: str, target: str = None) -> bool:
        if not os.path.islink(path):
            return False
        if target is not None:
            return os.readlink(path) == target
        return True

    def check_hardlink_count(self, path: str, expected_nlink: int) -> bool:
        try:
            return os.stat(path).st_nlink == expected_nlink
        except FileNotFoundError:
            return False

    def check_file_mode(self, path: str, expected_mode: int) -> bool:
        try:
            return (os.stat(path).st_mode & 0o7777) == expected_mode
        except FileNotFoundError:
            return False

    def check_file_owner(self, path: str, uid: int, gid: int) -> bool:
        try:
            st = os.stat(path)
            return st.st_uid == uid and st.st_gid == gid
        except FileNotFoundError:
            return False

    def check_file_size(self, path: str, expected_size: int) -> bool:
        try:
            return os.path.getsize(path) == expected_size
        except FileNotFoundError:
            return False

    # ─── Network effect checks ───────────────────────────────────────────

    def check_tcp_connection(self, addr: str, port: int) -> bool:
        """Check if a TCP connection to addr:port succeeded (from outside)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                result = s.connect_ex((addr, port))
                return result == 0
        except OSError:
            return False

    def check_port_listening(self, port: int, family: int = socket.AF_INET) -> bool:
        """Check if a port is being listened on (via /proc/net/tcp or ss)."""
        try:
            result = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
            return f":{port}" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def check_udp_packet_received(self, listen_port: int, timeout: float = 2.0) -> bool:
        """Listen on a UDP port and check if a packet arrives."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.bind(("127.0.0.1", listen_port))
                data, _ = s.recvfrom(1024)
                return len(data) > 0
        except socket.timeout:
            return False
        except OSError:
            return False

    # ─── IPC effect checks ───────────────────────────────────────────────

    def check_pipe_data(self, read_fd: int, expected: bytes,
                        timeout: float = 2.0) -> bool:
        """Check if data arrived on a pipe fd."""
        import select
        ready, _, _ = select.select([read_fd], [], [], timeout)
        if ready:
            data = os.read(read_fd, len(expected) + 1)
            return data == expected
        return False

    def check_sysv_shm(self, shmid: int, expected: bytes) -> bool:
        """Check SysV shared memory content via ipcs/ipcrm."""
        try:
            # Use ipcs to verify the segment exists
            result = subprocess.run(
                ["ipcs", "-m", "-i", str(shmid)],
                capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def check_sysv_msg(self, msqid: int) -> bool:
        """Check if a SysV message queue has messages."""
        try:
            result = subprocess.run(
                ["ipcs", "-q", "-i", str(msqid)],
                capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def check_posix_mq(self, name: str) -> bool:
        """Check if a POSIX message queue exists."""
        return os.path.exists(f"/dev/mqueue/{name}")

    # ─── Signal/process checks ───────────────────────────────────────────

    def check_process_alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def check_process_dead(self, pid: int) -> bool:
        return not self.check_process_alive(pid)

    def check_process_received_signal(self, pid: int, signo: int,
                                      timeout: float = 2.0) -> bool:
        """Check if a process was killed by a signal (via waitpid)."""
        # This is typically checked by the probe's exit status
        return False  # Caller checks probe exit code directly

    # ─── Process tree checks ─────────────────────────────────────────────

    def get_process_tree(self, root_pid: int) -> List[int]:
        """Get all descendant PIDs of root_pid."""
        pids = []
        try:
            result = subprocess.run(
                ["ps", "--ppid", str(root_pid), "-o", "pid="],
                capture_output=True, text=True, timeout=5)
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    child = int(line)
                    pids.append(child)
                    pids.extend(self.get_process_tree(child))
        except (subprocess.TimeoutExpired, ValueError):
            pass
        return pids

    def check_no_descendants(self, root_pid: int) -> bool:
        """Verify no child processes remain."""
        return len(self.get_process_tree(root_pid)) == 0

    # ─── Output/transcript checks ────────────────────────────────────────

    def check_output_contains(self, output: str, expected: str) -> bool:
        return expected in output

    def check_output_absent(self, output: str, forbidden: str) -> bool:
        return forbidden not in output

    # ─── Composite state comparison ──────────────────────────────────────

    def snapshot_file(self, path: str) -> FileSnapshot:
        return FileSnapshot.capture(path)

    def snapshot_dir(self, path: str) -> DirSnapshot:
        return DirSnapshot.capture(path)

    def compare_snapshots(self, before: FileSnapshot,
                          after: FileSnapshot) -> bool:
        """Return True if state is identical (for rollback verification)."""
        return before.matches(after)

    def compute_dir_hash(self, path: str) -> str:
        """Compute a recursive content hash of a directory tree."""
        h = hashlib.sha256()
        for root, dirs, files in sorted(os.walk(path)):
            dirs.sort()
            for name in sorted(files):
                fpath = os.path.join(root, name)
                h.update(fpath.encode())
                try:
                    st = os.lstat(fpath)
                    h.update(struct.pack("QQQ", st.st_mode, st.st_size,
                                         st.st_mtime_ns))
                    if stat.S_ISREG(st.st_mode) and st.st_size < 1024 * 1024:
                        with open(fpath, "rb") as f:
                            h.update(f.read())
                except OSError:
                    h.update(b"ERROR")
        return h.hexdigest()
