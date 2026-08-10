#!/usr/bin/env python3
"""
Session Proxy for ShadowProc — Frozen Baseline + Speculative Clone.

The Session Proxy gives an agent a *stable* handle (a `session_id`) to a
long-lived shell, and hides the fact that speculative execution keeps swapping
the underlying pid between a frozen "baseline" and a running "candidate".

Mechanism (all delegated to the ShadowProc daemon over its Unix socket):

  open_session()      launch a real bash inside a monitored cgroup, driven by a
                      FIFO. The live shell idles blocked in read() on the FIFO —
                      this is the natural per-epoch snapshot boundary.

  begin_epoch(sid)    freeze the live shell at its read() boundary, then
                      begin_speculative: the ORIGINAL becomes the pristine
                      *baseline* (never runs the epoch's commands) and a COW
                      *candidate* is forked and resumed. The candidate is now the
                      live shell; the proxy tracks the pid swap internally.

  run(sid, cmd)       feed a command to the current live shell (the candidate,
                      during an epoch) and capture its stdout.

  commit(sid)         accept the candidate as canonical and discard the baseline.
                      The candidate keeps running; session_id is unchanged.

  reject(sid)         discard the candidate and resume the pristine baseline —
                      the ORIGINAL process, lineage intact, which never ran the
                      epoch's commands. Rollback is lossless; session_id is
                      unchanged.

The agent only ever sees `session_id`. It never learns, or needs, a pid.

Requires: root, Linux >= 5.15 with BPF LSM, cgroup v2, and a running ShadowProc
daemon whose socket this proxy connects to. `cgroup_exec` (from
demo/test_programs) is used to place bash into the cgroup atomically.
"""

import argparse
import ctypes
import fcntl
import itertools
import json
import os
import re
import select
import shutil
import signal
import socket
import stat
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass


# ──────────────────────────── Mount namespace helpers ───────────────────────

# mount(2) flag constants (see <sys/mount.h>).
_MS_RDONLY     = 0x00000001
_MS_NOSUID     = 0x00000002
_MS_NODEV      = 0x00000004
_MS_NOEXEC     = 0x00000008
_MS_BIND       = 0x00001000
_MS_REC        = 0x00004000
_MS_REMOUNT    = 0x00000020
_MS_PRIVATE    = 0x00040000
_MS_MOVE       = 0x00008000

# MNT_DETACH for umount2.
_MNT_DETACH    = 0x00000002

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.mount.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_ulong, ctypes.c_void_p,
]
_libc.mount.restype = ctypes.c_int
_libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
_libc.umount2.restype = ctypes.c_int
_libc.setns.argtypes = [ctypes.c_int, ctypes.c_int]
_libc.setns.restype = ctypes.c_int


def _mount(source, target, fstype, flags, data=None):
    """Thin wrapper for the mount(2) syscall.

    Raises OSError(errno, strerror, target) on failure.
    """
    src = source.encode() if source else None
    tgt = target.encode()
    fs = fstype.encode() if fstype else None
    dat = data.encode() if data else None
    ret = _libc.mount(src, tgt, fs, ctypes.c_ulong(flags), dat)
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), target)


def _umount2(target, flags=0):
    """Wrapper for umount2(2)."""
    tgt = target.encode()
    ret = _libc.umount2(tgt, flags)
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), target)


# ──────────────────────────── pidfd helpers ──────────────────────────────────

# pidfd_open(2) / pidfd_getfd(2) syscall numbers (generic numbering, same on
# x86_64 and aarch64).  pidfd_getfd obtains an fd that refers to the SAME open
# file description as the target's fd, so lseek(2) / fcntl(F_SETFL) on it take
# effect on the description shared with the baseline — this is what makes fd
# offset/flag rollback actually possible from userspace.  Linux >= 5.6.
_SYS_PIDFD_OPEN  = 434
_SYS_PIDFD_GETFD = 438

_libc.syscall.restype = ctypes.c_long


def _pidfd_open(pid: int) -> int:
    fd = _libc.syscall(ctypes.c_long(_SYS_PIDFD_OPEN),
                       ctypes.c_int(pid), ctypes.c_uint(0))
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return fd


def _pidfd_getfd(pidfd: int, target_fd: int) -> int:
    fd = _libc.syscall(ctypes.c_long(_SYS_PIDFD_GETFD),
                       ctypes.c_int(pidfd), ctypes.c_int(target_fd),
                       ctypes.c_uint(0))
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return fd


_pidfd_supported_cache = None


def _pidfd_supported() -> bool:
    """Probe once whether pidfd_open/pidfd_getfd are usable (kernel >= 5.6).

    The result is cached for the lifetime of the process.  The probe uses a
    freshly opened /dev/null fd so it does not depend on stdio state.
    """
    global _pidfd_supported_cache
    if _pidfd_supported_cache is None:
        try:
            probe = os.open("/dev/null", os.O_RDONLY)
            try:
                pidfd = _pidfd_open(os.getpid())
                try:
                    dupfd = _pidfd_getfd(pidfd, probe)
                    os.close(dupfd)
                finally:
                    os.close(pidfd)
            finally:
                os.close(probe)
            _pidfd_supported_cache = True
        except OSError:
            _pidfd_supported_cache = False
    return _pidfd_supported_cache


# ──────────────────────────── Speculation Domain Launcher ───────────────────

class SpeculationDomainLauncher:
    """Creates a closed speculation domain via mount-namespace isolation.

    Called in the child process after fork(), before exec().  Sets up:

    1.  Mount namespace (CLONE_NEWNS) — isolates all mount changes from the
        parent (the orchestrator / ShadowFS daemon).
    2.  Read-only root filesystem — blocks direct writes to host paths.
        The only writable mounts are:
          • ShadowFS (FUSE, separate mount — versioned, rollback-safe)
          • Per-candidate tmpfs at /tmp, /dev/shm, /var/tmp, /run (ephemeral)
        /sys/fs/cgroup is remounted read-only inside the candidate namespace;
        the trusted parent is responsible for placing the process in cgroups.
    3.  Per-candidate tmpfs at /dev/shm — the host's shared tmpfs is a
        persistent write channel that bypasses ShadowFS entirely (POSIX shm
        files, host-visible content), so it is replaced before anything
        else.  The ShadowFS preserve staging point lives inside it.
    4.  Per-candidate tmpfs at /tmp — discarded on rollback.  If the ShadowFS
        mount lives under /tmp it is preserved by bind-mounting it aside,
        mounting the tmpfs, then bind-mounting it back.
    5.  Backing directory masked — the candidate cannot read or write the
        ShadowFS staging/lower directories directly, preventing bypass.
    6.  Dangerous escape vectors masked — /proc/kcore, /proc/bus,
        /sys/firmware, etc. are covered (directories with read-only tmpfs,
        files with a read-only /dev/null bind-mount).

    Fail-closed: every step that guards a concrete escape channel must
    succeed when its target exists (unshare, private mount, /dev/shm, /tmp,
    root remount, /proc//sys remount, backing-dir and masked-path covers).
    Any failure raises OSError and the caller aborts the launch (exit 126)
    rather than running the workload in a partially-isolated domain.
    """

    # Paths to mask with read-only tmpfs (block information leakage / escape).
    _MASKED_PATHS = (
        "/proc/kcore",
        "/proc/bus",
        "/proc/kallsyms",
        "/sys/firmware",
        "/sys/kernel",
    )

    # Ephemeral tmpfs mount points (per-candidate, discarded on rollback).
    # /tmp is handled specially (ShadowFS may live there).
    _TMPFS_PATHS = ("/var/tmp", "/run")

    def __init__(self, backing_dir=None, shadowfs_mount=None,
                 require_isolation=True):
        """
        Args:
            backing_dir:     ShadowFS staging/lower directory to mask (block
                             direct access).  May be a list or single path.
            shadowfs_mount:  Path where ShadowFS FUSE is mounted.  Used to
                             preserve the mount when it lives under /tmp.
            require_isolation: If True (default), fail-closed when namespace
                             setup fails.  If False, log and continue.
        """
        if isinstance(backing_dir, str):
            backing_dir = [backing_dir]
        self.backing_dirs = backing_dir or []
        self.shadowfs_mount = shadowfs_mount
        self.require_isolation = require_isolation

    def setup_in_child(self):
        """Set up the mount namespace isolation.

        Must be called in the child process after fork(), before exec().
        Raises OSError on failure (caller should os._exit(126)).
        Every step whose target exists is mandatory — there is no silent
        "except: pass" fallback for a failed cover.
        """
        # 1. Create mount namespace.
        os.unshare(os.CLONE_NEWNS)

        # 2. Make ALL existing mounts private so changes don't propagate
        #    to the parent namespace (critical: without this, remounting /
        #    read-only would affect the host).
        _mount("", "/", None, _MS_REC | _MS_PRIVATE)

        # 3. Replace /dev/shm with a per-candidate tmpfs.  The host's shared
        #    tmpfs is a persistent write channel that bypasses ShadowFS
        #    (POSIX shm segments, files the host can read after rollback),
        #    so it must not leak into the speculation domain.  Mounted now
        #    because step 4 stages the ShadowFS preserve bind inside it.
        #    Mandatory when /dev/shm exists.
        if os.path.isdir("/dev/shm"):
            _mount("tmpfs", "/dev/shm", "tmpfs",
                   _MS_NOSUID | _MS_NODEV, "size=64m")

        # 4. Preserve ShadowFS mount if it lives under /tmp.
        #    Bind-mount it to a temporary location outside /tmp, mount the
        #    tmpfs, then bind-mount it back.  The staging point sits in the
        #    private /dev/shm tmpfs from step 3.
        preserve_path = None
        if self.shadowfs_mount and self.shadowfs_mount.startswith("/tmp/"):
            preserve_path = "/dev/shm/.shadowfs-preserve"
            os.makedirs(preserve_path, exist_ok=True)
            _mount(self.shadowfs_mount, preserve_path, None, _MS_BIND)

        # 5. Mount per-candidate tmpfs at /tmp.
        _mount("tmpfs", "/tmp", "tmpfs",
               _MS_NOSUID | _MS_NODEV, "size=256m")

        # 6. Restore ShadowFS mount if preserved.
        if preserve_path:
            os.makedirs(self.shadowfs_mount, exist_ok=True)
            _mount(preserve_path, self.shadowfs_mount, None, _MS_BIND)
            _umount2(preserve_path, _MNT_DETACH)
            try:
                os.rmdir(preserve_path)
            except OSError:
                pass

        # 7. Mount tmpfs at other ephemeral paths.  If the directory exists,
        #    covering it is mandatory: otherwise the host directory stays
        #    visible (content leak) instead of being replaced by an
        #    ephemeral per-candidate store.
        for p in self._TMPFS_PATHS:
            if os.path.isdir(p):
                _mount("tmpfs", p, "tmpfs",
                       _MS_NOSUID | _MS_NODEV, "size=64m")

        # 8. Make root read-only in THIS namespace — blocks writes to ALL host
        #    paths. ShadowFS (FUSE) and cgroup2 are separate mounts, unaffected.
        #
        #    Must go through _remount_ro (MS_REMOUNT|MS_BIND), NOT a plain
        #    MS_REMOUNT. A plain remount targets the SUPERBLOCK, which "/"
        #    shares with the host, so it both (a) reaches outside this namespace
        #    and (b) fails EBUSY on any live system, because
        #    sb_prepare_remount_readonly() refuses while the root filesystem
        #    still has files open for writing — which it essentially always
        #    does. The bind form changes only this mount's flags, which is all
        #    the domain needs. Same reasoning as steps 9/11 already use.
        self._remount_ro("/")

        # 9. Remount /proc, /sys and cgroupfs as read-only to block procfs,
        #    sysfs and cgroup-controller escape vectors.  Candidate processes
        #    must not be able to move/freeze/kill domain-external processes by
        #    writing cgroupfs; the trusted parent performs cgroup placement.
        #    When the path is a mount point the remount is mandatory — a
        #    silently skipped remount would leave those vectors writable.
        for p in ("/proc", "/sys", "/sys/fs/cgroup"):
            if os.path.ismount(p):
                self._remount_ro(p)

        # 10. Block access to ShadowFS backing directories (staging, lower).
        #     Mount a read-only tmpfs over each to prevent direct access.
        #     Mandatory when the directory exists: a silently skipped cover
        #     would let the candidate read/write the store behind ShadowFS's
        #     back and break versioning.  (Dirs under /tmp no longer exist
        #     after the step-5 tmpfs, so the isdir check skips them.)
        for bd in self.backing_dirs:
            if bd and os.path.isdir(bd):
                _mount("tmpfs", bd, "tmpfs", _MS_RDONLY, "size=1")

        # 11. Mask dangerous escape vectors.  Mandatory when present.
        for p in self._MASKED_PATHS:
            if os.path.exists(p):
                self._mask_path(p)

    @staticmethod
    def _remount_ro(path):
        """Make `path` read-only in THIS mount namespace.

        MS_REMOUNT|MS_BIND changes only this mount's flags, which is what we
        actually want: a private namespace must not alter what other namespaces
        see, and a plain MS_REMOUNT targets the SUPERBLOCK -- shared with every
        other mount of it, including ones outside this namespace.  Plain
        MS_REMOUNT is kept as a fallback for filesystems that reject the bind
        form.

        A mount that is already read-only satisfies the requirement; anything
        else propagates the original error rather than being skipped, since a
        silently writable /proc or cgroupfs is an escape vector.
        """
        try:
            _mount("", path, None, _MS_REMOUNT | _MS_BIND | _MS_RDONLY)
            return
        except OSError as bind_err:
            try:
                _mount("", path, None, _MS_REMOUNT | _MS_RDONLY)
                return
            except OSError:
                pass
            try:
                already_ro = bool(os.statvfs(path).f_flag & os.ST_RDONLY)
            except OSError:
                already_ro = False
            if not already_ro:
                raise bind_err

    @staticmethod
    def _mask_path(path):
        """Mask a dangerous path so it cannot be used as an escape vector.

        Directories are covered with a read-only tmpfs.  Non-directories
        (e.g. /proc/kcore, /proc/kallsyms) are covered by bind-mounting
        /dev/null over them and remounting the bind read-only — a plain
        tmpfs mount over a file fails with ENOTDIR, which previously made
        the cover silently ineffective.
        """
        if os.path.isdir(path):
            _mount("tmpfs", path, "tmpfs", _MS_RDONLY, "size=1")
        else:
            _mount("/dev/null", path, None, _MS_BIND)
            _mount("", path, None,
                   _MS_REMOUNT | _MS_BIND | _MS_RDONLY)


# ──────────────────────────── Admission control ────────────────────────────

class NotAdmissibleError(RuntimeError):
    """The baseline process is not in a snapshot-safe state for versioning.
    Raised by _admit_for_versioning; begin_epoch translates this into a
    'not_admissible' response so the session degrades to non-speculative mode.
    """


class FdRestoreError(RuntimeError):
    """Baseline fd state could not be losslessly restored on reject.

    Raised by _restore_fds when an fd drifted (or vanished) and the snapshot
    values could not be written back onto the shared open file description.
    The epoch IS rejected (baseline resumed), but the caller must treat the
    rollback as lossy — the session should be torn down rather than trusted.
    """


class PendingSignalError(RuntimeError):
    """Baseline pending-signal state could not be proven clean on reject.

    Raised after rejecting an epoch if the resumed baseline has any pending
    signal or if /proc cannot be inspected. Pending signals are unrollbackable
    user-visible effects, so the recovered session must be treated as lossy.
    """


@dataclass
class FdSnapshot:
    """Snapshot of a seekable regular-file fd for rollback restoration."""
    fd: int
    dev: int
    ino: int
    offset: int    # lseek position at snapshot time
    flags: int     # fcntl F_GETFL flags at snapshot time


# ──────────────────────────── ShadowProc client ────────────────────────────
class ShadowProcClient:
    """Thin newline-delimited-JSON client for the ShadowProc Unix socket."""

    def __init__(self, sock_path):
        self.sock_path = sock_path

    def call(self, action, **fields):
        """Send one request, return the parsed response dict.

        Raises RuntimeError if the daemon reports status == "error".
        """
        req = {"action": action}
        req.update({k: v for k, v in fields.items() if v is not None})
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.sock_path)
        try:
            f = s.makefile("rw", buffering=1)
            f.write(json.dumps(req) + "\n")
            f.flush()
            line = f.readline()
        finally:
            s.close()
        if not line:
            raise RuntimeError(f"{action}: empty response from ShadowProc")
        resp = json.loads(line)
        if resp.get("status") == "error":
            raise RuntimeError(f"{action}: {resp.get('message')}")
        return resp


# ──────────────────────────── Session state ────────────────────────────────
# Where a session's control files (stdin FIFO + transcript log) live.
#
# Deliberately NOT under the ephemeral tmp roots (/tmp, /var/tmp, /run,
# /dev/shm) that the speculation domain replaces per candidate.  These files are
# proxy-owned infrastructure, not workload state; with them under /tmp every
# session held a regular fd into a rollback-unsafe tmp path, which
# _reject_tmp_regular_fds correctly refused -- so no session could ever enter a
# speculative epoch at all.  Overridable for unprivileged test runs.
_SESSION_DIR = os.environ.get("SHADOW_SESSION_DIR",
                              "/var/lib/shadow-proxy/sessions")


class _Session:
    def __init__(self, session_id, cgroup_name, cgroup_root):
        self.id = session_id
        self.cgroup_name = cgroup_name
        self.cgroup_id = "/" + cgroup_name                     # ShadowProc form
        self.cgroup_path = os.path.join(cgroup_root, cgroup_name)
        self.fifo_path = os.path.join(
            _SESSION_DIR, f"shadow-session-{session_id}.fifo")
        self.log_path = os.path.join(
            _SESSION_DIR, f"shadow-session-{session_id}.log")
        self.fifo_wfd = None        # held-open write end (keeps FIFO from EOF)
        self.live_pid = None        # current canonical pid (agent never sees it)
        self.epoch = None           # {"baseline": pid, "candidate": pid} or None
        # Identity of the in-flight epoch, used to tag transcript entries.
        # Proxy-local and monotonic: it only has to distinguish this session's
        # epochs from each other, so it does not need the orchestrator's EpochID.
        self.epoch_id = None
        self._epoch_seq = 0
        self.tmp_snapshot_dir = None # host-side snapshot of namespace tmp state
        # Output is released to the caller IMMEDIATELY, including inside an
        # epoch (optimistic release). There is no held-back speculative buffer.
        #
        # `transcript` is an append-only list of (epoch_id, text) entries, where
        # epoch_id is None for canonical output produced outside any epoch. The
        # tag — not a separate buffer, and not an external index — is what lets
        # the two duties the old epoch_buffer served still be met:
        #   - reject drops exactly the entries tagged with the rejected epoch;
        #   - peek_epoch_output() still returns "committed + in-flight", so the
        #     orchestrator can journal a deterministic committed result at the
        #     file-layer decision point (crash recovery depends on it).
        # Tagging beats an index because it survives any other mutation of the
        # list and cannot silently truncate the wrong range.
        self.transcript = []


# ──────────────────────────── The proxy ────────────────────────────────────
class SessionProxy:
    def __init__(self, sock_path, cgroup_root="/sys/fs/cgroup",
                 cgroup_exec=None, verbose=True,
                 backing_dir=None, shadowfs_mount=None,
                 require_isolation=True):
        self.client = ShadowProcClient(sock_path)
        self.cgroup_root = cgroup_root
        self.cgroup_exec = cgroup_exec or self._default_cgroup_exec()
        self.verbose = verbose
        self.sessions = {}
        self._sentinel_ids = itertools.count(1)
        # SpeculationDomainLauncher: creates a mount namespace per candidate
        # so writes to /tmp, host paths, and backing directories are blocked.
        self._domain_launcher = SpeculationDomainLauncher(
            backing_dir=backing_dir,
            shadowfs_mount=shadowfs_mount,
            require_isolation=require_isolation,
        )

    # ---- infra helpers -----------------------------------------------------
    @staticmethod
    def _default_cgroup_exec():
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        return os.path.join(root, "demo", "test_programs", "cgroup_exec")

    def _log(self, msg):
        if self.verbose:
            print(f"  [proxy] {msg}", flush=True)

    @staticmethod
    def _proc_state(pid):
        try:
            with open(f"/proc/{pid}/status") as fh:
                for ln in fh:
                    if ln.startswith("State:"):
                        return ln.split()[1]
        except OSError:
            return None
        return None

    def _wait_state_T(self, pid, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc_state(pid) == "T":
                return True
            time.sleep(0.05)
        return False

    @staticmethod
    def _read_wchan(pid):
        """Read the kernel wait-channel name for a process.

        Returns the wchan string (e.g. 'pipe_read', 'do_wait') or '' if
        unreadable.  A process blocked in its stdin read() shows 'pipe_read'
        (or 'pipe_wait' on some kernels).
        """
        try:
            with open(f"/proc/{pid}/wchan") as fh:
                return fh.read().strip()
        except OSError:
            return ""

    def _wait_wchan_read(self, pid, timeout=1.0, poll_interval=0.005):
        """Wait until *pid* is blocked in a pipe/read wait-channel.

        Replaces the legacy time.sleep(0.3) that blindly waited for the
        process to settle back into its read() boundary.  Polls
        /proc/<pid>/wchan every *poll_interval* seconds; returns True as
        soon as the wchan indicates a read/pipe/poll block, False on timeout.

        The fallback sleep on timeout is a short 20ms (not the original
        300ms) — if wchan is unreadable the process is almost certainly
        already at its boundary (the only case where wchan is '0' or
        empty is when the process is in userspace between syscalls, which
        for bash lasts < 1ms before it re-enters read()).
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            wc = self._read_wchan(pid)
            # 'pipe_read' (≥5.10), 'pipe_wait' (some kernels), 'poll_schedule_timeout'
            # (if stdin is a pty), 'do_select' — all mean the process is blocked
            # waiting for input, which is exactly the boundary we need.
            if wc and ("pipe" in wc or "read" in wc or "poll" in wc
                       or "select" in wc or "wait" in wc):
                return True
            # wchan == '0' or '' means the process is in userspace (between
            # syscalls).  For bash this transient window is < 1ms; if we see
            # it, the process is alive and about to re-enter read().
            if wc == "0" or wc == "":
                # Give it one more poll cycle to land in read().
                time.sleep(poll_interval)
                wc2 = self._read_wchan(pid)
                if wc2 and wc2 != "0":
                    return True
            time.sleep(poll_interval)
        # Timeout: fall back to a short conservative sleep (20ms, not 300ms).
        time.sleep(0.02)
        return False

    @staticmethod
    def _reap(pid, timeout=2.0):
        """Reap a child the daemon killed, so it doesn't linger as a zombie.

        The daemon SIGKILLs the process but is NOT its parent (candidates are
        CLONE_PARENT siblings of the shell, i.e. children of this launcher), so
        only we can reap it. The candidate now exits with SIGCHLD, so a normal
        waitpid() can collect it. Poll briefly because the target may not have
        become a zombie yet at the instant we're called (the daemon's SIGKILL is
        asynchronous).
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                wpid, _ = os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                return  # already reaped, or not our child
            if wpid == pid:
                return  # reaped
            time.sleep(0.02)

    def _loglines(self, sess):
        try:
            with open(sess.log_path, "r", errors="replace") as fh:
                return fh.read().splitlines()
        except OSError:
            return []

    def _feed(self, sess, line):
        os.write(sess.fifo_wfd, (line + "\n").encode())

    # ---- Phase 4: admission / snapshot / restore ---------------------------
    def _admit_for_versioning(self, pid: int) -> None:
        """Pre-fork admission control: verify the baseline process is in a
        snapshot-safe state.  Raises NotAdmissibleError if any check fails so
        the caller can degrade to non-speculative mode instead of producing an
        unrecoverable rollback.
        """
        # 1. Single-threaded (COW fork of a multi-threaded process is unsafe).
        try:
            tasks = os.listdir(f"/proc/{pid}/task")
        except OSError as e:
            raise NotAdmissibleError(f"cannot read /proc/{pid}/task: {e}")
        if len(tasks) != 1:
            raise NotAdmissibleError(
                f"process has {len(tasks)} threads (must be single-threaded)")

        # 2. No pre-existing descendants (children share fd tables and are
        #    impossible to roll back atomically).
        try:
            with open(f"/proc/{pid}/task/{pid}/children") as fh:
                children = fh.read().strip()
        except OSError:
            children = ""
        if children:
            raise NotAdmissibleError(
                f"process has child processes: {children}")

        # 3. No writable MAP_SHARED mappings (changes are immediately visible
        #    to other processes and cannot be undone by COW fork).
        try:
            with open(f"/proc/{pid}/maps") as fh:
                for ln in fh:
                    parts = ln.split()
                    if len(parts) >= 2:
                        perms = parts[1]
                        if "w" in perms and "s" in perms:
                            path = parts[-1] if len(parts) > 5 else "(anon)"
                            raise NotAdmissibleError(
                                f"writable MAP_SHARED mapping: {path}")
        except OSError as e:
            raise NotAdmissibleError(f"cannot read /proc/{pid}/maps: {e}")

        # 4. No pending signals (would be delivered on resume and are
        #    impossible to clear from userspace without ptrace).
        try:
            with open(f"/proc/{pid}/status") as fh:
                for ln in fh:
                    if ln.startswith("SigPnd:") or ln.startswith("ShdPnd:"):
                        parts = ln.split()
                        if len(parts) >= 2:
                            val = int(parts[1], 16)
                            if val != 0:
                                raise NotAdmissibleError(
                                    f"pending signals ({ln.split(':')[0].strip()}):"
                                    f" 0x{val:x}")
        except OSError as e:
            raise NotAdmissibleError(f"cannot read /proc/{pid}/status: {e}")

        # 5. No controlling terminal: tty state (termios settings, job
        #    control, ^C/^Z delivery) is shared with whoever owns the
        #    terminal and can never be rolled back.  tty_nr is field 7 of
        #    /proc/pid/stat; fields are counted after comm, which may itself
        #    contain spaces or parens.
        try:
            with open(f"/proc/{pid}/stat") as fh:
                stat_line = fh.read()
            after_comm = stat_line[stat_line.rfind(")") + 2:].split()
            tty_nr = int(after_comm[4])  # field 7 overall (state..tty_nr)
        except (OSError, ValueError, IndexError) as e:
            raise NotAdmissibleError(f"cannot parse /proc/{pid}/stat: {e}")
        if tty_nr != 0:
            raise NotAdmissibleError(
                f"process has a controlling terminal (tty_nr={tty_nr})")

        # 6. No active POSIX timers (timer_create): an armed timer fires a
        #    signal at the baseline after resume — an unrollbackable effect
        #    with no fd that admission could snapshot.  /proc/pid/timers
        #    exists only with CONFIG_CHECKPOINT_RESTORE; when the kernel
        #    does not expose it there is nothing to check.
        try:
            with open(f"/proc/{pid}/timers") as fh:
                timers = fh.read().strip()
        except FileNotFoundError:
            timers = ""  # kernel without CONFIG_CHECKPOINT_RESTORE
        except OSError as e:
            raise NotAdmissibleError(f"cannot read /proc/{pid}/timers: {e}")
        if timers:
            raise NotAdmissibleError(
                f"process has active POSIX timers:\n{timers}")

        # 7. fd scan: fds 0-2 must be FIFO/regular/char (our stdin/out/err)
        #    but never a terminal; fds > 2 must be regular files (the only
        #    type we can snapshot and restore via pidfd_getfd).
        reg_fds = []
        try:
            fd_entries = os.listdir(f"/proc/{pid}/fd")
        except OSError as e:
            raise NotAdmissibleError(f"cannot read /proc/{pid}/fd: {e}")
        for fd_name in fd_entries:
            if not fd_name.isdigit():
                continue
            fd = int(fd_name)
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            try:
                fd_stat = os.stat(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            mode = fd_stat.st_mode
            if fd <= 2:
                if (link.startswith("/dev/pts/")
                        or link in ("/dev/tty", "/dev/console")
                        or re.fullmatch(r"/dev/tty\d+", link)):
                    raise NotAdmissibleError(f"fd {fd} is a terminal: {link}")
                if (stat.S_ISFIFO(mode) or stat.S_ISREG(mode)
                        or stat.S_ISCHR(mode)):
                    continue
                raise NotAdmissibleError(
                    f"fd {fd} is not FIFO/regular/char: {link}")
            # fds > 2: only regular files are snapshot-safe.
            if stat.S_ISREG(mode):
                reg_fds.append(fd)
                continue
            if stat.S_ISSOCK(mode):
                raise NotAdmissibleError(f"socket fd {fd}: {link}")
            if stat.S_ISFIFO(mode):
                raise NotAdmissibleError(f"pipe/FIFO fd {fd}: {link}")
            if link.startswith("anon_inode:"):
                raise NotAdmissibleError(f"special fd {fd}: {link}")
            if stat.S_ISCHR(mode):
                raise NotAdmissibleError(f"device fd {fd}: {link}")
            raise NotAdmissibleError(f"unknown fd type {fd}: {link}")

        # 8. fd restoration capability: with regular fds > 2 the ONLY way to
        #    roll back candidate offset/flag drift is pidfd_getfd (Linux
        #    >= 5.6).  If it is unavailable, refuse versioning outright
        #    instead of silently resuming a drifted baseline on reject.
        if reg_fds and not _pidfd_supported():
            raise NotAdmissibleError(
                f"pidfd_open/pidfd_getfd unavailable and {len(reg_fds)} "
                f"regular fd(s) > 2 could not be restored on reject")

    def _reject_tmp_regular_fds(self, pid: int) -> None:
        tmp_roots = ("/tmp", "/dev/shm", "/var/tmp", "/run")
        try:
            fd_entries = os.listdir(f"/proc/{pid}/fd")
        except OSError as e:
            raise NotAdmissibleError(f"cannot read /proc/{pid}/fd: {e}")
        for fd_name in fd_entries:
            if not fd_name.isdigit():
                continue
            fd_path = f"/proc/{pid}/fd/{fd_name}"
            try:
                link = os.readlink(fd_path)
                fd_stat = os.stat(fd_path)
            except OSError:
                continue
            if not stat.S_ISREG(fd_stat.st_mode):
                continue
            path = link.split(" (deleted)", 1)[0]
            if any(path == root or path.startswith(root + "/") for root in tmp_roots):
                raise NotAdmissibleError(
                    f"fd {fd_name} points to rollback-unsafe tmp file: {link}")

    def _snapshot_fds(self, pid: int) -> list:
        """Snapshot all seekable regular-file fds (> 2) of the process.
        Returns a list of FdSnapshot.  Called after admission passes."""
        snapshots = []
        try:
            fd_entries = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            return snapshots
        for fd_name in fd_entries:
            if not fd_name.isdigit():
                continue
            fd = int(fd_name)
            if fd <= 2:
                continue
            try:
                fd_stat = os.stat(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if not stat.S_ISREG(fd_stat.st_mode):
                continue
            # Read offset and flags from /proc/pid/fdinfo/N.
            try:
                with open(f"/proc/{pid}/fdinfo/{fd}") as fh:
                    offset = 0
                    flags = 0
                    for ln in fh:
                        if ln.startswith("pos:"):
                            offset = int(ln.split()[1])
                        elif ln.startswith("flags:"):
                            flags = int(ln.split()[1], 8)
            except OSError:
                continue
            snapshots.append(FdSnapshot(
                fd=fd, dev=fd_stat.st_dev, ino=fd_stat.st_ino,
                offset=offset, flags=flags))
        return snapshots

    def _restore_fds(self, pid: int, snapshots: list) -> None:
        """Restore fd offsets/flags after the baseline is resumed.

        A candidate shares each open file description with the baseline (COW
        fork copies the fd TABLE, not the descriptions), so any lseek or
        fcntl it performed drifted the baseline's fd as well.  For each
        drifted fd we obtain a duplicate via pidfd_getfd — which refers to
        the SAME open file description — and lseek/F_SETFL the snapshot
        values back onto it.

        Fail-closed: an fd whose drift cannot be verified or restored raises
        FdRestoreError, so the epoch's caller learns the rollback was NOT
        lossless instead of silently resuming a corrupted baseline.
        Admission guarantees pidfd support whenever regular fds are present,
        so a failure here is genuinely exceptional.
        """
        if not snapshots:
            return
        try:
            pidfd = _pidfd_open(pid)
        except OSError as e:
            raise FdRestoreError(f"pidfd_open({pid}) failed: {e}")
        errors = []
        try:
            for snap in snapshots:
                try:
                    fd_stat = os.stat(f"/proc/{pid}/fd/{snap.fd}")
                except OSError:
                    errors.append(
                        f"fd {snap.fd} closed by candidate "
                        f"(was dev={snap.dev} ino={snap.ino})")
                    continue
                if fd_stat.st_dev != snap.dev or fd_stat.st_ino != snap.ino:
                    errors.append(
                        f"fd {snap.fd} now points to a different file "
                        f"(dev={fd_stat.st_dev} ino={fd_stat.st_ino} vs "
                        f"snapshot dev={snap.dev} ino={snap.ino})")
                    continue
                cur_offset = cur_flags = None
                try:
                    with open(f"/proc/{pid}/fdinfo/{snap.fd}") as fh:
                        for ln in fh:
                            if ln.startswith("pos:"):
                                cur_offset = int(ln.split()[1])
                            elif ln.startswith("flags:"):
                                cur_flags = int(ln.split()[1], 8)
                except OSError as e:
                    errors.append(f"fd {snap.fd}: cannot read fdinfo: {e}")
                    continue
                if cur_offset is None or cur_flags is None:
                    errors.append(f"fd {snap.fd}: incomplete fdinfo")
                    continue
                if cur_offset == snap.offset and cur_flags == snap.flags:
                    continue
                # Drifted — restore via the shared open file description.
                try:
                    dupfd = _pidfd_getfd(pidfd, snap.fd)
                except OSError as e:
                    errors.append(f"fd {snap.fd}: pidfd_getfd failed: {e}")
                    continue
                try:
                    if cur_offset != snap.offset:
                        os.lseek(dupfd, snap.offset, os.SEEK_SET)
                    if cur_flags != snap.flags:
                        # F_SETFL can only change the file-status flags.
                        setfl_mask = (os.O_APPEND | os.O_NONBLOCK
                                      | getattr(os, "O_DIRECT", 0)
                                      | getattr(os, "O_NOATIME", 0)
                                      | getattr(os, "O_ASYNC", 0))
                        fcntl.fcntl(dupfd, fcntl.F_SETFL,
                                    (cur_flags & ~setfl_mask)
                                    | (snap.flags & setfl_mask))
                except OSError as e:
                    errors.append(f"fd {snap.fd}: restore failed: {e}")
                else:
                    self._log(f"  fd {snap.fd} restored: offset "
                              f"{cur_offset}->{snap.offset}, flags "
                              f"0{cur_flags:o}->0{snap.flags:o}")
                finally:
                    os.close(dupfd)
        finally:
            os.close(pidfd)
        if errors:
            raise FdRestoreError(
                "baseline fd state could not be fully restored: "
                + "; ".join(errors))

    def _kill_descendants(self, pid: int) -> None:
        """Recursively SIGKILL all descendant processes of *pid* (best-effort).
        Used during reject to clean up background jobs the candidate started.
        """
        try:
            with open(f"/proc/{pid}/task/{pid}/children") as fh:
                children = fh.read().split()
        except OSError:
            return
        for child_str in children:
            if not child_str.isdigit():
                continue
            child = int(child_str)
            self._kill_descendants(child)   # depth-first
            try:
                os.kill(child, signal.SIGKILL)
            except OSError:
                pass
            self._reap(child)

    def _clear_pending_signals(self, pid: int) -> None:
        """Verify that reject did not leave pending signals on the baseline.

        Pending signals cannot be cleared from userspace without ptrace.  Since
        they would be delivered after resume and are therefore unrollbackable,
        the only safe recovery behavior is fail-closed: raise
        PendingSignalError so the caller tears down the session instead of
        trusting a lossy rollback.
        """
        try:
            with open(f"/proc/{pid}/status") as fh:
                for ln in fh:
                    if ln.startswith("SigPnd:") or ln.startswith("ShdPnd:"):
                        parts = ln.split()
                        if len(parts) >= 2:
                            val = int(parts[1], 16)
                            if val != 0:
                                raise PendingSignalError(
                                    f"baseline pid {pid} has pending signals "
                                    f"({ln.split(':')[0].strip()}): 0x{val:x}")
        except PendingSignalError:
            raise
        except (OSError, ValueError) as e:
            raise PendingSignalError(
                f"cannot verify pending-signal state for baseline pid {pid}: {e}")

    def _setns_mount(self, pid: int) -> None:
        fd = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        try:
            if _libc.setns(fd, os.CLONE_NEWNS) != 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e), f"/proc/{pid}/ns/mnt")
        finally:
            os.close(fd)

    def _namespace_copy_worker(self, pid: int, snapshot_dir: str,
                               restore: bool) -> None:
        # The snapshot lives in the HOST mount namespace while the tmp state to
        # copy lives in the session's.  Pin the snapshot directory as an fd
        # BEFORE setns (the fd keeps its mount alive), then fchdir back onto it
        # afterwards: setns(CLONE_NEWNS) resets both root and cwd to the new
        # namespace's root, so after the fchdir absolute paths resolve in the
        # session's namespace and relative paths in the host snapshot -- exactly
        # the split this copy needs.  Addressing the snapshot through
        # /proc/<ppid>/root instead would depend on /proc still being the host's
        # procfs and on ppid still being the proxy; the pinned fd depends on
        # neither.
        snap_fd = os.open(snapshot_dir, os.O_RDONLY | os.O_DIRECTORY)
        self._setns_mount(pid)
        try:
            os.fchdir(snap_fd)
        finally:
            os.close(snap_fd)
        tmp_paths = ("/tmp", "/dev/shm", "/var/tmp", "/run")

        def _skip_entry(dirpath, name):
            """True if `name` under `dirpath` must not be copied or removed.

            Covers two cases with one check:
              - a real mount point (st_dev differs from its parent), and
              - an entry that cannot even be stat'd, which is exactly what a
                fail-closed FUSE mount looks like (EIO).

            os.path.ismount() is unusable here: it catches the lstat error and
            returns False, so a fail-closed ShadowFS mount would be mistaken for
            an ordinary directory -- snapshot would recurse into it (EIO) and
            restore would try to unlink it (EISDIR). Both directions must use
            THIS check, or the two get out of sync.
            """
            full = os.path.join(dirpath, name)
            try:
                return os.lstat(full).st_dev != os.lstat(dirpath).st_dev
            except OSError:
                return True

        if restore:
            for p in tmp_paths:
                src = p.lstrip("/")          # relative -> host snapshot
                if not os.path.isdir(src):
                    continue
                os.makedirs(p, exist_ok=True)
                for name in os.listdir(p):
                    target = os.path.join(p, name)
                    if _skip_entry(p, name):
                        continue
                    if os.path.isdir(target) and not os.path.islink(target):
                        shutil.rmtree(target)
                    else:
                        try:
                            os.unlink(target)
                        except FileNotFoundError:
                            pass
                for name in os.listdir(src):
                    s = os.path.join(src, name)
                    d = os.path.join(p, name)
                    if os.path.isdir(s) and not os.path.islink(s):
                        shutil.copytree(s, d, symlinks=True)
                    else:
                        shutil.copy2(s, d, follow_symlinks=False)
        else:
            # Skip nested mount points at any depth. Critical for the ShadowFS
            # FUSE mount when it lives under /tmp: ShadowFS is fail-closed and
            # attributes access by cgroup, and this worker runs in the
            # ORCHESTRATOR's cgroup, which has no active epoch -- so recursing
            # into it returns EIO and the whole snapshot (hence begin_epoch)
            # fails. Snapshotting it would be wrong anyway: ShadowFS versions
            # its own content per epoch, so copying it here would be duplicate,
            # conflicting bookkeeping.
            def _skip_mounts(dirpath, names):
                return {n for n in names if _skip_entry(dirpath, n)}

            for p in tmp_paths:
                if not os.path.isdir(p):
                    continue
                dst = p.lstrip("/")          # relative -> host snapshot
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(p, dst, symlinks=True, ignore=_skip_mounts,
                                ignore_dangling_symlinks=True)

    def _run_namespace_copy(self, pid: int, snapshot_dir: str,
                            restore: bool) -> None:
        child = os.fork()
        if child == 0:
            try:
                self._namespace_copy_worker(pid, snapshot_dir, restore)
                os._exit(0)
            except Exception as e:  # noqa: BLE001
                sys.stderr.write(f"[proxy] tmp-state {'restore' if restore else 'snapshot'} failed: {e}\n")
                os._exit(126)
        _, status = os.waitpid(child, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise RuntimeError("epoch tmp-state restore failed" if restore
                               else "epoch tmp-state snapshot failed")

    def _snapshot_epoch_tmp_state(self, sess) -> str:
        snap = tempfile.mkdtemp(prefix=f"shadow-tmp-{sess.id}-")
        try:
            self._run_namespace_copy(sess.live_pid, snap, restore=False)
        except Exception:
            shutil.rmtree(snap, ignore_errors=True)
            raise
        return snap

    def _restore_epoch_tmp_state(self, sess, snapshot_dir: str) -> None:
        self._run_namespace_copy(sess.live_pid, snapshot_dir, restore=True)

    def _discard_epoch_tmp_snapshot(self, sess) -> None:
        snap = getattr(sess, "tmp_snapshot_dir", None)
        if snap:
            shutil.rmtree(snap, ignore_errors=True)
            sess.tmp_snapshot_dir = None

    # ---- session lifecycle -------------------------------------------------
    def open_session(self, cgroup_name=None):
        """Launch a bash session inside a fresh monitored cgroup. Returns sid."""
        sid = uuid.uuid4().hex[:8]
        cgroup_name = cgroup_name or f"shadow-session-{sid}"
        # cgroupfs write restriction (issue #2): the cgroup name must be a single
        # benign path component so the session's cgroup can never escape the
        # managed cgroup root (no "/", "..", leading dot, etc.). This bounds both
        # the makedirs below and the cgroup_id we hand to ShadowProc.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", cgroup_name):
            raise ValueError(f"invalid cgroup name (must be a single benign "
                             f"path component): {cgroup_name!r}")
        sess = _Session(sid, cgroup_name, self.cgroup_root)

        os.makedirs(sess.cgroup_path, exist_ok=True)
        # Register the cgroup with ShadowProc's eBPF (monitored). bash can start
        # here because the mmap hook exempts its read-only loader mappings.
        self.client.call("add_cgroup", cgroup_path=sess.cgroup_path)

        # Fresh FIFO + log. Hold the FIFO open O_RDWR so the shell never sees
        # EOF and our writes never block.
        os.makedirs(os.path.dirname(sess.fifo_path), exist_ok=True)
        for p in (sess.fifo_path, sess.log_path):
            try:
                os.remove(p)
            except OSError:
                pass
        os.mkfifo(sess.fifo_path)
        # O_CLOEXEC so the held write end does not leak into bash across exec().
        sess.fifo_wfd = os.open(sess.fifo_path, os.O_RDWR | os.O_CLOEXEC)

        # Launch order is load-bearing.  Everything privileged the child needs
        # to build its speculation domain -- unshare(CLONE_NEWNS), the tmpfs/bind
        # covers, the read-only remounts -- happens BEFORE the parent moves it
        # into the monitored cgroup.  ShadowProc treats a monitored cgroup as
        # MODE_SPECULATIVE by default, i.e. every hooked operation is fenced
        # (SIGSTOP + notify), and `unshare` IS hooked, so a child that set up its
        # domain from inside the cgroup would be frozen mid-setup and never reach
        # exec -- the guard deadlocking its own setup.  The child therefore
        # reports "domain ready" over a reverse pipe, the parent enrolls it in the
        # cgroup, and only then does the child exec the shell -- from that instant
        # on every effect the workload attempts is genuinely fenced.
        stdin_fd = os.open(sess.fifo_path, os.O_RDONLY | os.O_CLOEXEC)   # won't block: writer open
        log_fd = os.open(sess.log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o644)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        # Reverse channel: child -> parent, "speculation domain is built".
        domain_r, domain_w = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:  # child
            os.close(ready_w)
            os.close(domain_r)
            try:
                # Become a session leader with no controlling terminal BEFORE
                # anything else: the speculation domain must not inherit the
                # orchestrator's ctty.  Terminal state is not rollback-safe,
                # and admission (correctly) rejects baselines that hold one.
                os.setsid()
                # Phase: SpeculationDomainLauncher — create a closed mount
                # namespace before exec.  This must happen BEFORE dup2 so
                # the namespace is established while we still have full
                # capability.  The fds (stdin_fd, log_fd) are inherited
                # across unshare and will be dup2'd onto 0/1/2 afterwards.
                #
                # If isolation is required and fails, the child exits 126
                # (distinct from 127 = exec failure) so the parent can
                # diagnose the cause.
                if self._domain_launcher.require_isolation:
                    self._domain_launcher.setup_in_child()
                else:
                    try:
                        self._domain_launcher.setup_in_child()
                    except OSError as e:
                        sys.stderr.write(
                            f"[proxy] WARNING: domain isolation failed: {e}"
                            " — continuing without isolation\n")
                # Domain is built; it is now safe to be enrolled in the
                # monitored cgroup.
                os.write(domain_w, b"1")
                os.close(domain_w)
                token = os.read(ready_r, 1)
                os.close(ready_r)
                if token != b"1":
                    os._exit(126)
                os.dup2(stdin_fd, 0)
                os.dup2(log_fd, 1)
                os.dup2(log_fd, 2)
                # Close every other inherited fd before exec.  When the proxy is
                # driven in-process there is nothing to leak, but when it runs
                # inside the Orchestrator the fork() inherits the accepted
                # control-connection socket (and possibly the listening socket).
                # A live socket fd on the baseline is not snapshot-safe, so
                # admission control would reject every epoch with "socket fd N".
                # closerange is used rather than scanning /proc/self/fd so this
                # stays correct in a mount namespace whose /proc is not ours; the
                # leaked fds are always low, and the range is capped so a huge
                # RLIMIT_NOFILE can't make this slow.
                try:
                    _maxfd = os.sysconf("SC_OPEN_MAX")
                    if _maxfd < 0 or _maxfd > 65536:
                        _maxfd = 65536
                except (ValueError, OSError):
                    _maxfd = 4096
                os.closerange(3, _maxfd)
                os.execvp("bash", ["bash", "--norc"])
            except OSError as e:
                # Domain setup failure (unshare, mount, etc.).
                sys.stderr.write(f"[proxy] domain isolation failed: {e}\n")
                os._exit(126)
            except Exception:  # noqa: BLE001 — child must not return
                os._exit(127)
        os.close(ready_r)
        os.close(domain_w)
        try:
            # The child must have finished building its speculation domain
            # before we move it into the monitored cgroup; otherwise the fence
            # stops it mid-setup.  A bounded wait keeps a wedged child from
            # hanging the caller forever; EOF means the child died reporting
            # failure.
            r, _, _ = select.select([domain_r], [], [], 15.0)
            token = os.read(domain_r, 1) if r else b""
            if token != b"1":
                raise RuntimeError(
                    "session shell failed to build its speculation domain"
                    + (" (timed out)" if not r else ""))
            with open(os.path.join(sess.cgroup_path, "cgroup.procs"), "w") as f:
                f.write(str(pid))
            os.write(ready_w, b"1")
        except Exception:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            raise
        finally:
            os.close(ready_w)
            os.close(domain_r)
            os.close(stdin_fd)
            os.close(log_fd)

        sess.live_pid = pid
        time.sleep(0.5)
        if self._proc_state(pid) is None:
            # Distinguish domain-isolation failure (126) from exec failure
            # (127) so the caller gets an actionable error message.
            try:
                _, status = os.waitpid(pid, os.WNOHANG)
                if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 126:
                    raise RuntimeError(
                        "bash failed to start: speculation domain isolation "
                        "failed (requires CAP_SYS_ADMIN for mount namespace). "
                        "Run as root or set require_isolation=False.")
            except ChildProcessError:
                pass
            raise RuntimeError("bash failed to start in cgroup")

        self.sessions[sid] = sess
        self._log(f"session {sid}: bash live (pid {pid}) in cgroup {sess.cgroup_id}")
        return sid

    def close_session(self, sid):
        sess = self.sessions.pop(sid, None)
        if not sess:
            return
        # Kill everything left in the cgroup (live shell, any candidate/baseline).
        try:
            with open(os.path.join(sess.cgroup_path, "cgroup.procs")) as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln.isdigit():
                        try:
                            os.kill(int(ln), 9)
                        except OSError:
                            pass
                        self._reap(int(ln))
        except OSError:
            pass
        self._discard_epoch_tmp_snapshot(sess)
        if sess.fifo_wfd is not None:
            try:
                os.close(sess.fifo_wfd)
            except OSError:
                pass
        # Release the eBPF cgroup slot so the daemon can reclaim it. Without this
        # every session permanently consumes one of the 64 cgroup_map slots.
        try:
            self.client.call("remove_cgroup", cgroup_path=sess.cgroup_path)
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
        for p in (sess.fifo_path, sess.log_path):
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(sess.cgroup_path)
        except OSError:
            pass
        self._log(f"session {sid}: closed")

    # ---- command execution -------------------------------------------------
    def _recover_from_timeout(self, sess) -> None:
        """Restore the session shell to a clean read() boundary after a
        command timeout.

        Without this, the timed-out command keeps running inside the shell:
        every subsequent command queues behind it and also times out
        (cascading failure), and the lingering child makes the session
        permanently not-admissible for speculative epochs.

        Recovery: SIGKILL the entire descendant tree of the live shell
        (the timed-out command and anything it spawned), then wait for
        bash to reap it, execute the queued sentinel echo, and settle
        back into pipe_read.
        """
        live = sess.live_pid
        self._kill_descendants(live)
        # bash reaps the killed child, runs the queued `echo sentinel`,
        # and returns to read().  Wait for that boundary so the next
        # command starts from a clean state.
        if not self._wait_wchan_read(live, timeout=2.0):
            self._log(f"session {sess.id}: WARNING — shell did not settle "
                      f"after timeout recovery (pid {live})")

    def run(self, sid, command, timeout=10.0):
        """Feed one command to the current live shell and return its stdout.

        Works both between epochs (on the committed shell) and inside an epoch
        (on the speculative candidate) — the caller doesn't need to care which.

        Output is released IMMEDIATELY in both cases, including for speculative
        in-epoch commands. The agent may therefore act on speculative output
        before the epoch is finalized; that is deliberate (external synchrony):
        the agent's context is INTERNAL state and may advance optimistically,
        while externally-visible effects stay gated by the epoch. If the epoch
        is later rejected, reject() drops the segment from the canonical
        transcript and the agent's turn is wasted — the misspeculation cost.
        """
        sess = self.sessions[sid]
        sentinel = f"__SHADOW_DONE_{next(self._sentinel_ids)}__"
        n0 = len(self._loglines(sess))
        self._feed(sess, command)
        self._feed(sess, f"echo {sentinel}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            lines = self._loglines(sess)
            if sentinel in lines[n0:]:
                idx = lines.index(sentinel, n0)
                out = "\n".join(lines[n0:idx])
                # Same path in and out of an epoch: record the output tagged with
                # the epoch that produced it (None outside an epoch) and hand it
                # straight back to the caller.
                sess.transcript.append((sess.epoch_id, out))
                return out
            time.sleep(0.05)
        self._recover_from_timeout(sess)
        raise TimeoutError(f"command timed out: {command!r}")

    def get_output(self, sid):
        """Return the session's transcript.

        With optimistic release this is the running transcript: output from
        committed epochs, non-speculative commands, and any epoch currently in
        flight. Entries of a REJECTED epoch are removed by reject(), so a
        rejected epoch never remains in the transcript.
        """
        sess = self.sessions[sid]
        return "\n".join(text for _epoch, text in sess.transcript)

    def peek_epoch_output(self, sid):
        """Return the transcript that WOULD become committed for the currently
        active epoch: everything recorded so far, including the in-flight
        epoch's entries. Used by the orchestrator to snapshot the committed
        result durably at the file-layer commit decision point (so a crash
        before finalize_commit still yields a deterministic result on recovery).
        Returns "" for an unknown session.

        Value-identical to the pre-optimistic-release version, which computed
        committed_output + epoch_buffer: the in-flight epoch's output is now
        recorded in place and tagged instead of held in a side buffer.
        """
        sess = self.sessions.get(sid)
        if sess is None:
            return ""
        return "\n".join(text for _epoch, text in sess.transcript)

    # ---- speculative epoch -------------------------------------------------
    def begin_epoch(self, sid, retries=3):
        """Freeze the live shell as baseline and fork+resume a speculative
        candidate. After this returns, run()/commit()/reject() act on the epoch.

        Phase 4: performs admission control, freezes the baseline, rejects
        rollback-unsafe tmp regular-file fds, and snapshots fd/tmp state at the
        stopped epoch boundary. If the process is not admissible (multi-threaded,
        has children, writable MAP_SHARED, pending signals, unsafe tmp fds, or
        non-regular fds), raises NotAdmissibleError so the caller can degrade to
        non-speculative mode.
        """
        sess = self.sessions[sid]
        if sess.epoch is not None:
            raise RuntimeError("an epoch is already active for this session")

        # Phase 4: admission check — verify the baseline is snapshot-safe before
        # creating a candidate. Then freeze it and take fd/tmp snapshots at the
        # same stopped epoch boundary.
        self._admit_for_versioning(sess.live_pid)
        self.client.call("freeze_by_cgroup", cgroup_id=sess.cgroup_id)
        # From here until the epoch is actually established, EVERY failure exit
        # must thaw: the freeze above stopped the whole cgroup, so bailing out
        # frozen wedges the session permanently (all later session_run calls
        # would just time out). The success path returns from inside the try and
        # deliberately leaves the BASELINE frozen -- that is the epoch invariant.
        try:
            if not self._wait_state_T(sess.live_pid):
                raise RuntimeError("live shell never reached stopped state")
            # State T confirmed — a brief settle delay suffices (was 150ms).
            time.sleep(0.02)
            self._reject_tmp_regular_fds(sess.live_pid)
            fd_snapshots = self._snapshot_fds(sess.live_pid)
            tmp_snapshot = self._snapshot_epoch_tmp_state(sess)

            last_err = None
            for attempt in range(1, retries + 1):
                try:
                    # Frozen original is the baseline; fork the speculative candidate.
                    resp = self.client.call("begin_speculative", pid=sess.live_pid)
                    pids = resp.get("pids") or []
                    if not pids:
                        raise RuntimeError("begin_speculative returned no candidate pid")
                    candidate = pids[0]
                    baseline = sess.live_pid
                    # Resume the candidate ARMED (no allow-map pass): it becomes the
                    # live shell but its first external effect is intercepted and
                    # frozen. Using resume_candidate (plain SIGCONT) instead of
                    # resume_pid is what stops the candidate from silently bypassing
                    # the fence for the whole epoch. Authorized effects are released
                    # only after finalization (commit -> full release).
                    self.client.call("resume_candidate", pid=candidate)
                    # Wait for the candidate to land back in its read() boundary
                    # (was a blind time.sleep(0.3); now event-driven via wchan).
                    self._wait_wchan_read(candidate, timeout=1.0)
                    sess.epoch = {"baseline": baseline, "candidate": candidate,
                                  "fd_snapshots": fd_snapshots,
                                  "tmp_snapshot": tmp_snapshot}
                    sess.tmp_snapshot_dir = tmp_snapshot
                    sess.live_pid = candidate
                    # Tag subsequent output with this epoch so reject() can drop
                    # exactly its entries. Output itself is released to the caller
                    # immediately (see run()).
                    sess._epoch_seq += 1
                    sess.epoch_id = f"e{sess._epoch_seq}"
                    self._log(f"session {sid}: epoch begun — baseline(frozen)={baseline} "
                              f"candidate(live)={candidate}")
                    return
                except (RuntimeError, TimeoutError) as e:
                    last_err = e
                    self._log(f"session {sid}: begin_epoch attempt {attempt} failed: {e}")
                    time.sleep(0.1)
            shutil.rmtree(tmp_snapshot, ignore_errors=True)
            raise RuntimeError(f"begin_epoch failed after {retries} attempts: {last_err}")
        except BaseException:
            self._thaw_after_failed_begin(sess)
            raise

    def _thaw_after_failed_begin(self, sess) -> None:
        """Undo the begin_epoch freeze when the epoch could not be established.

        freeze_by_cgroup stops the WHOLE session cgroup. If begin_epoch then
        bails out without thawing, the session's shell stays frozen forever and
        every later session_run just times out -- one transient failure kills the
        session. Best-effort: a thaw failure is logged, never masks the original
        error.
        """
        try:
            self.client.call("continue_by_cgroup", cgroup_id=sess.cgroup_id)
            self._log(f"session {sess.id}: begin_epoch failed — thawed cgroup "
                      f"{sess.cgroup_id} so the session stays usable")
        except Exception as e:  # noqa: BLE001
            self._log(f"session {sess.id}: WARNING — could not thaw after failed "
                      f"begin_epoch: {e} (session may be stuck frozen)")

    def commit(self, sid):
        """Accept the candidate as canonical; discard the frozen baseline.

        This is the single-caller convenience path (used by the demo/tests). The
        orchestrator drives commit as TWO phases so it can insert the ShadowFS
        finalize gate between them: quiesce_for_commit() (reversible) then
        finalize_commit() (destructive). Keep the two in lock-step here.
        """
        self.quiesce_for_commit(sid)
        self.finalize_commit(sid)

    def quiesce_for_commit(self, sid):
        """REVERSIBLE commit phase 1: bring the candidate to a stopped
        read()-boundary. Discards nothing — if the caller (orchestrator) then
        finds ShadowFS cannot finalize, the epoch can still be rejected and the
        pristine baseline resumed. No baseline is destroyed here.
        """
        sess = self.sessions[sid]
        if sess.epoch is None:
            raise RuntimeError("no active epoch to commit")
        # Quiesce the candidate to a stopped read()-boundary first (the proven
        # commit flow acts on a frozen candidate, then continues it).
        # release_fence_vfork=True: commit 路径解冻是必然结局，允许为解开
        # vfork-D 死锁提前恢复围栏冻结的子进程（reject 路径则绝不）。
        self._quiesce_epoch(sess, release_fence_vfork=True)

    def finalize_commit(self, sid):
        """DESTRUCTIVE commit phase 2: discard the frozen baseline, keep the
        candidate as canonical, and release the buffered speculative transcript.

        MUST only be called after the file layer (ShadowFS) has finalized: this
        discards the baseline (commit_pid) and can no longer be rolled back.
        """
        sess = self.sessions[sid]
        if sess.epoch is None:
            raise RuntimeError("no active epoch to commit")
        candidate = sess.epoch["candidate"]
        baseline = sess.epoch["baseline"]
        # Phase 4: detect candidate exit before commit.  If the candidate died,
        # we cannot keep it as canonical — raise so the caller can handle the
        # inconsistency (the FS layer is already finalized at this point).
        if self._proc_state(candidate) is None:
            self._reap(candidate)
            raise RuntimeError(
                f"candidate {candidate} exited before finalize_commit")
        self.client.call("commit_pid", pid=candidate)
        self._reap(baseline)
        # The candidate is still frozen at its boundary — resume it as canonical.
        self.client.call("continue_pid", pid=candidate)
        sess.live_pid = candidate            # unchanged: candidate stays live
        sess.epoch = None
        self._discard_epoch_tmp_snapshot(sess)
        # The epoch's output was already released to the caller as it was
        # produced; commit just makes it canonical. Retag its entries as
        # canonical (epoch None) so a later epoch's reject can never mistake
        # them for speculative.
        sess.transcript = [(None, text) if epoch == sess.epoch_id else (epoch, text)
                           for epoch, text in sess.transcript]
        sess.epoch_id = None
        # Wait for the candidate to settle back into read() (was 200ms blind).
        self._wait_wchan_read(candidate, timeout=1.0)
        self._log(f"session {sid}: COMMIT — candidate {candidate} is now canonical "
                  f"(baseline {baseline} discarded)")

    def reject(self, sid):
        """Discard the candidate; resume the pristine baseline (lossless).

        Phase 4: after the baseline is resumed, restores fd offsets/flags
        from the snapshot via pidfd_getfd (fail-closed: raises FdRestoreError
        if any fd cannot be restored, in which case the rollback is lossy and
        the session must not be trusted), kills any descendant processes the
        candidate started, and fail-closed verifies that the resumed baseline
        has no pending signals.
        """
        sess = self.sessions[sid]
        if sess.epoch is None:
            raise RuntimeError("no active epoch to reject")
        candidate = sess.epoch["candidate"]
        baseline = sess.epoch["baseline"]
        fd_snapshots = sess.epoch.get("fd_snapshots", [])
        tmp_snapshot = sess.epoch.get("tmp_snapshot")
        # Quiesce the candidate to a stopped read()-boundary first: this mirrors
        # the proven rollback flow (the candidate is frozen before it is
        # discarded), and avoids killing it while it is actively blocked in the
        # pipe read() it shares (COW) with the baseline.
        self._quiesce_epoch(sess)
        # Kill any descendant processes the candidate started (background jobs,
        # subshells) BEFORE discarding the candidate so they don't outlive the
        # epoch.
        self._kill_descendants(candidate)
        resp = self.client.call("reject_pid", pid=baseline)
        self._reap(candidate)
        # pids[0] is the canonical pid from now on (the baseline). reject_pid may
        # resume it, so immediately stop the cgroup again before restoring fd/tmp
        # state; the caller must not observe a half-restored namespace.
        pids = resp.get("pids") or [baseline]
        sess.live_pid = pids[0]
        self.client.call("freeze_by_cgroup", cgroup_id=sess.cgroup_id)
        if not self._wait_state_T(sess.live_pid, timeout=3.0):
            try:
                os.kill(sess.live_pid, signal.SIGSTOP)
            except OSError:
                pass
            self._wait_state_T(sess.live_pid, timeout=1.0)
        # Phase 4: restore fd state and tmp state while the baseline is stopped.
        self._restore_fds(sess.live_pid, fd_snapshots)
        if tmp_snapshot:
            try:
                self._restore_epoch_tmp_state(sess, tmp_snapshot)
            except Exception as e:  # noqa: BLE001
                # Option C: tmp restore is idempotent and retriable, so on
                # failure we thaw and proceed rather than leaving the session
                # frozen forever. The baseline's /tmp may be stale, but that is
                # recoverable (the session is still usable and a subsequent
                # epoch can still succeed). Compare _clear_pending_signals: THAT
                # failure is NOT idempotent and must stay fail-closed (frozen).
                self._log(f"session {sid}: WARNING — tmp-state restore failed "
                          f"({e}), proceeding with stale /tmp (session still "
                          f"usable, next epoch will re-snapshot)")
        sess.epoch = None
        self._clear_pending_signals(sess.live_pid)
        self.client.call("continue_pid", pid=sess.live_pid)
        # Drop this epoch's entries from the transcript: from the baseline's
        # point of view the epoch never happened. The caller already received
        # that output (optimistic release), so the agent's turn that consumed it
        # is wasted — that is the misspeculation cost. What matters is that the
        # transcript no longer claims it as canonical.
        if sess.epoch_id is not None:
            sess.transcript = [(epoch, text) for epoch, text in sess.transcript
                               if epoch != sess.epoch_id]
            sess.epoch_id = None
        self._discard_epoch_tmp_snapshot(sess)
        # Wait for the baseline to settle back into read() (was 200ms blind).
        self._wait_wchan_read(sess.live_pid, timeout=1.0)
        self._log(f"session {sid}: REJECT — discarded candidate {candidate}, "
                  f"resumed pristine baseline {sess.live_pid}")

    def _quiesce_epoch(self, sess, release_fence_vfork=False):
        """Bring the speculative candidate to a stopped read()-boundary (state T).

        Both the proven reject (Scenario 8) and commit (Scenario 12) flows make
        the commit/reject decision on a *stopped* candidate. freeze_by_cgroup
        stops the candidate (and skips the frozen baseline, which is a tracked
        versioning baseline).

        release_fence_vfork: 仅 commit 路径传 True —— 允许 ShadowProc 为解开
        vfork-D 死锁提前恢复围栏冻结的子进程（commit 后解冻本就是必然结局）；
        reject 路径保持 False，绝不放出被否决 epoch 的未决外部效应。
        """
        candidate = sess.epoch["candidate"]
        try:
            self.client.call("freeze_by_cgroup", cgroup_id=sess.cgroup_id,
                             release_fence_vfork=release_fence_vfork)
        except RuntimeError:
            pass
        if not self._wait_state_T(candidate, timeout=3.0):
            # Fallback: stop the candidate directly.
            try:
                os.kill(candidate, signal.SIGSTOP)
            except OSError:
                pass
            self._wait_state_T(candidate, timeout=1.0)
        # State T confirmed; minimal settle (was 100ms).
        time.sleep(0.01)


# ──────────────────────────── Self-contained demo ──────────────────────────
def _demo(proxy):
    """Prove the session_id abstraction: the agent mutates state speculatively,
    then either COMMITs (state persists) or REJECTs (state is losslessly
    restored) — all without ever touching a pid.
    """
    ok = True
    sid = proxy.open_session()
    try:
        proxy.run(sid, "export SHADOW_VAR=ORIGINAL")
        base = proxy.run(sid, "echo VAL=$SHADOW_VAR")
        print(f"  baseline state:        {base}")

        # ── Epoch 1: speculative mutation → REJECT (expect lossless rollback) ──
        print("\n  ── Epoch 1: mutate speculatively, then REJECT ──")
        proxy.begin_epoch(sid)
        proxy.run(sid, "export SHADOW_VAR=MODIFIED_BY_AGENT")
        in_epoch = proxy.run(sid, "echo VAL=$SHADOW_VAR")
        print(f"  inside epoch (candidate): {in_epoch!r} (pending, not released)")
        proxy.reject(sid)
        after_reject = proxy.run(sid, "echo VAL=$SHADOW_VAR")
        print(f"  after REJECT:          {after_reject}")
        # Speculative output is held pending: in-epoch run() returns None (the
        # agent must not read speculative output before finalization).
        ok &= (in_epoch is None
               and after_reject.strip() == "VAL=ORIGINAL")

        # ── Epoch 2: speculative mutation → COMMIT (expect state persists) ──
        print("\n  ── Epoch 2: mutate speculatively, then COMMIT ──")
        proxy.begin_epoch(sid)
        proxy.run(sid, "export SHADOW_VAR=COMMITTED_VALUE")
        proxy.commit(sid)
        after_commit = proxy.run(sid, "echo VAL=$SHADOW_VAR")
        print(f"  after COMMIT:          {after_commit}")
        ok &= (after_commit.strip() == "VAL=COMMITTED_VALUE")

        # ── Commit-gated output: the released transcript must contain the
        #    COMMITTED epoch's output but NEVER the REJECTED epoch's output ──
        transcript = proxy.get_output(sid)
        gate_ok = ("MODIFIED_BY_AGENT" not in transcript
                   and "VAL=COMMITTED_VALUE" in transcript)
        print(f"\n  committed transcript gate: "
              f"{'OK' if gate_ok else 'FAILED'} "
              f"(rejected output absent, committed output present)")
        ok &= gate_ok

        print()
        if ok:
            print("  \033[1;32m✓ SESSION PROXY OK: reject was lossless, commit persisted "
                  "— agent used only session_id\033[0m")
        else:
            print("  \033[1;31m✗ SESSION PROXY CHECK FAILED\033[0m")
    finally:
        proxy.close_session(sid)
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="ShadowProc Session Proxy")
    ap.add_argument("--sock", required=True, help="ShadowProc Unix socket path")
    ap.add_argument("--cgroup-root", default="/sys/fs/cgroup")
    ap.add_argument("--cgroup-exec", default=None,
                    help="path to cgroup_exec helper (default: demo/test_programs/cgroup_exec)")
    ap.add_argument("--demo", action="store_true", help="run the built-in commit/reject demo")
    ap.add_argument("--shadowfs-mount", default=None,
                    help="Path where ShadowFS FUSE is mounted (for domain isolation)")
    ap.add_argument("--backing-dir", default=None,
                    help="ShadowFS backing directory to block (colon-separated list)")
    ap.add_argument("--no-isolation", action="store_true",
                    help="Disable mount namespace isolation (NOT recommended for production)")
    args = ap.parse_args(argv)

    backing_dir = args.backing_dir.split(":") if args.backing_dir else None
    proxy = SessionProxy(args.sock, cgroup_root=args.cgroup_root,
                         cgroup_exec=args.cgroup_exec,
                         shadowfs_mount=args.shadowfs_mount,
                         backing_dir=backing_dir,
                         require_isolation=not args.no_isolation)
    if args.demo:
        return _demo(proxy)
    ap.error("nothing to do: pass --demo (this module is primarily a library)")


if __name__ == "__main__":
    sys.exit(main())
