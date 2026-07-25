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

        # 8. Remount root as read-only — blocks writes to ALL host paths.
        #    ShadowFS (FUSE) and cgroup2 are separate mounts, unaffected.
        _mount("", "/", None, _MS_REMOUNT | _MS_RDONLY)

        # 9. Remount /proc, /sys and cgroupfs as read-only to block procfs,
        #    sysfs and cgroup-controller escape vectors.  Candidate processes
        #    must not be able to move/freeze/kill domain-external processes by
        #    writing cgroupfs; the trusted parent performs cgroup placement.
        #    When the path is a mount point the remount is mandatory — a
        #    silently skipped remount would leave those vectors writable.
        for p in ("/proc", "/sys", "/sys/fs/cgroup"):
            if os.path.ismount(p):
                _mount("", p, None, _MS_REMOUNT | _MS_RDONLY)

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
class _Session:
    def __init__(self, session_id, cgroup_name, cgroup_root):
        self.id = session_id
        self.cgroup_name = cgroup_name
        self.cgroup_id = "/" + cgroup_name                     # ShadowProc form
        self.cgroup_path = os.path.join(cgroup_root, cgroup_name)
        self.fifo_path = f"/tmp/shadow-session-{session_id}.fifo"
        self.log_path = f"/tmp/shadow-session-{session_id}.log"
        self.fifo_wfd = None        # held-open write end (keeps FIFO from EOF)
        self.live_pid = None        # current canonical pid (agent never sees it)
        self.epoch = None           # {"baseline": pid, "candidate": pid} or None
        self.tmp_snapshot_dir = None # host-side snapshot of namespace tmp state
        # Commit-gated output. `committed_output` is the durable transcript that
        # is safe to release externally (get_output). `epoch_buffer` holds the
        # SPECULATIVE output produced during the current epoch; it is merged
        # into committed_output on commit and dropped on reject.
        self.committed_output = []
        self.epoch_buffer = []


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
        parent_root = f"/proc/{os.getppid()}/root"
        host_snapshot = parent_root + snapshot_dir
        self._setns_mount(pid)
        tmp_paths = ("/tmp", "/dev/shm", "/var/tmp", "/run")
        if restore:
            for p in tmp_paths:
                src = os.path.join(host_snapshot, p.lstrip("/"))
                if not os.path.isdir(src):
                    continue
                os.makedirs(p, exist_ok=True)
                for name in os.listdir(p):
                    target = os.path.join(p, name)
                    if os.path.ismount(target):
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
            os.makedirs(host_snapshot, exist_ok=True)
            for p in tmp_paths:
                if not os.path.isdir(p):
                    continue
                dst = os.path.join(host_snapshot, p.lstrip("/"))
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(p, dst, symlinks=True, ignore_dangling_symlinks=True)

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
        for p in (sess.fifo_path, sess.log_path):
            try:
                os.remove(p)
            except OSError:
                pass
        os.mkfifo(sess.fifo_path)
        # O_CLOEXEC so the held write end does not leak into bash across exec().
        sess.fifo_wfd = os.open(sess.fifo_path, os.O_RDWR | os.O_CLOEXEC)

        # Launch bash after the trusted parent has placed the child pid into
        # the monitored cgroup. The child waits on a pipe before creating its
        # read-only mount namespace; this avoids the old cgroup_exec ordering
        # where /sys/fs/cgroup was remounted read-only before cgroup.procs was
        # written, causing EROFS/EPERM and a failed shell launch.
        stdin_fd = os.open(sess.fifo_path, os.O_RDONLY | os.O_CLOEXEC)   # won't block: writer open
        log_fd = os.open(sess.log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o644)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:  # child
            os.close(ready_w)
            try:
                # Wait until the trusted parent has written this child PID into
                # cgroup.procs. Only then may the child remount cgroupfs
                # read-only inside its private namespace.
                token = os.read(ready_r, 1)
                os.close(ready_r)
                if token != b"1":
                    os._exit(126)
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
                os.dup2(stdin_fd, 0)
                os.dup2(log_fd, 1)
                os.dup2(log_fd, 2)
                os.execvp("bash", ["bash", "--norc"])
            except OSError as e:
                # Domain setup failure (unshare, mount, etc.).
                sys.stderr.write(f"[proxy] domain isolation failed: {e}\n")
                os._exit(126)
            except Exception:  # noqa: BLE001 — child must not return
                os._exit(127)
        os.close(ready_r)
        try:
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
    def run(self, sid, command, timeout=10.0):
        """Feed one command to the current live shell and return its stdout.

        Works both between epochs (on the committed shell) and inside an epoch
        (on the speculative candidate) — the caller doesn't need to care which.

        Output is commit-gated. Output produced OUTSIDE an epoch is canonical
        and returned immediately. Output produced INSIDE an epoch is SPECULATIVE
        and is NOT returned to the caller (the paper keeps the tool call
        pending: the agent must not read speculative output before
        finalization). It is buffered and released to the committed transcript
        on commit / discarded on reject. In-epoch calls therefore return None.
        See get_output().
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
                if sess.epoch is not None:
                    # Speculative: hold pending commit and DO NOT release it to
                    # the caller before finalization.
                    sess.epoch_buffer.append(out)
                    return None
                sess.committed_output.append(out)  # canonical: release now
                return out
            time.sleep(0.05)
        raise TimeoutError(f"command timed out: {command!r}")

    def get_output(self, sid):
        """Return the session's COMMITTED transcript (commit-gated).

        This is the only output safe to release externally: it contains output
        from committed epochs and non-speculative commands, but NEVER output
        from an epoch that is still in flight or was rejected. It mirrors the
        orchestrator's commit-gated output buffer, applied per speculative epoch.
        """
        sess = self.sessions[sid]
        return "\n".join(sess.committed_output)

    def peek_epoch_output(self, sid):
        """Return the transcript that WOULD become committed for the currently
        active epoch: the durable committed transcript PLUS the in-flight
        epoch_buffer, joined as text. Used by the orchestrator to snapshot the
        committed result durably at the file-layer commit decision point (so a
        crash before finalize_commit still yields a deterministic result on
        recovery). Returns "" for an unknown session.
        """
        sess = self.sessions.get(sid)
        if sess is None:
            return ""
        return "\n".join(sess.committed_output + sess.epoch_buffer)

    # ---- speculative epoch -------------------------------------------------
    def begin_epoch(self, sid, retries=3):
        """Freeze the live shell as baseline and fork+resume a speculative
        candidate. After this returns, run()/commit()/reject() act on the epoch.

        Phase 4: performs admission control and fd snapshot before freezing
        so the baseline can be losslessly restored on reject.  If the process
        is not admissible (multi-threaded, has children, writable MAP_SHARED,
        pending signals, or non-regular fds), raises NotAdmissibleError so the
        caller can degrade to non-speculative mode.
        """
        sess = self.sessions[sid]
        if sess.epoch is not None:
            raise RuntimeError("an epoch is already active for this session")

        # Phase 4: admission check — verify the baseline is snapshot-safe before
        # creating a candidate. Then freeze it and take fd/tmp snapshots at the
        # same stopped epoch boundary.
        self._admit_for_versioning(sess.live_pid)
        self.client.call("freeze_by_cgroup", cgroup_id=sess.cgroup_id)
        if not self._wait_state_T(sess.live_pid):
            raise RuntimeError("live shell never reached stopped state")
        time.sleep(0.15)
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
                time.sleep(0.3)
                sess.epoch = {"baseline": baseline, "candidate": candidate,
                              "fd_snapshots": fd_snapshots,
                              "tmp_snapshot": tmp_snapshot}
                sess.tmp_snapshot_dir = tmp_snapshot
                sess.live_pid = candidate
                self._log(f"session {sid}: epoch begun — baseline(frozen)={baseline} "
                          f"candidate(live)={candidate}")
                return
            except (RuntimeError, TimeoutError) as e:
                last_err = e
                self._log(f"session {sid}: begin_epoch attempt {attempt} failed: {e}")
                time.sleep(0.3)
        shutil.rmtree(tmp_snapshot, ignore_errors=True)
        raise RuntimeError(f"begin_epoch failed after {retries} attempts: {last_err}")

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
        self._quiesce_epoch(sess)

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
        # Release the speculative transcript: the epoch's output is now canonical.
        sess.committed_output.extend(sess.epoch_buffer)
        sess.epoch_buffer = []
        time.sleep(0.2)                      # let it settle back into read()
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
            self._restore_epoch_tmp_state(sess, tmp_snapshot)
        sess.epoch = None
        self._clear_pending_signals(sess.live_pid)
        self.client.call("continue_pid", pid=sess.live_pid)
        # Discard the speculative transcript: from the baseline's point of view
        # the epoch never happened, so its output is never released.
        sess.epoch_buffer = []
        self._discard_epoch_tmp_snapshot(sess)
        time.sleep(0.2)                      # let the baseline settle back into read()
        self._log(f"session {sid}: REJECT — discarded candidate {candidate}, "
                  f"resumed pristine baseline {sess.live_pid}")

    def _quiesce_epoch(self, sess):
        """Bring the speculative candidate to a stopped read()-boundary (state T).

        Both the proven reject (Scenario 8) and commit (Scenario 12) flows make
        the commit/reject decision on a *stopped* candidate. freeze_by_cgroup
        stops the candidate (and skips the frozen baseline, which is a tracked
        versioning baseline).
        """
        candidate = sess.epoch["candidate"]
        try:
            self.client.call("freeze_by_cgroup", cgroup_id=sess.cgroup_id)
        except RuntimeError:
            pass
        if not self._wait_state_T(candidate, timeout=3.0):
            # Fallback: stop the candidate directly.
            try:
                os.kill(candidate, signal.SIGSTOP)
            except OSError:
                pass
            self._wait_state_T(candidate, timeout=1.0)
        time.sleep(0.1)


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
