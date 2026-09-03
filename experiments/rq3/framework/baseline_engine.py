#!/usr/bin/env python3
"""overlayfs + CRIU epoch engine for the RQ3 baseline experiment.

Implements the same epoch lifecycle the Penumbra orchestrator provides
(begin_epoch → session_run → commit/rollback) on top of two vanilla
kernel mechanisms:

  File-state isolation    overlayfs: upperdir is the speculative scratch
                          layer, lowerdir is the committed state (the analog
                          of ShadowFS's orig + staging).
  Process-state snapshot  CRIU: begin_epoch dumps the session process
                          (checkpoint), rollback restores it.

Phase mapping (Penumbra → baseline):
  begin_epoch   → criu dump --leave-running of the session process
  session_run   → command executed (bash -c) against the merged overlay view
  commit        → promote upperdir entries into lowerdir (whiteouts
                  honored), discard CRIU images, reset upperdir
  rollback      → kill + criu restore of the session process, discard
                  upperdir (and with it every speculative file change)

The per-phase costs are timed with the same Timer used by the Penumbra
harness so the resulting WorkloadResult is directly comparable.

Requires: root, criu(1), overlayfs support. Does NOT require any Penumbra
daemon — this is a standalone vanilla-system baseline.
"""

import os
import shutil
import signal
import stat
import subprocess
import time

from .timing import Timer

# Unique argv[0] marker for the sleeper process, used to (re)locate its
# PID after a CRIU restore.
SLEEPER_ARGV0 = "rq3-criu-sleeper"

# Directory names inside the engine root
DIR_LOWER = "lower"
DIR_UPPER = "upper"
DIR_WORK = "work"
DIR_MNT = "mnt"
DIR_CRIU = "criu-images"


def default_memhold_bin() -> str:
    """Locate the w10_memhold benchmark ($RQ3_MEMHOLD_BIN overrides)."""
    return os.environ.get("RQ3_MEMHOLD_BIN") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "benchmarks", "bin", "w10_memhold")


def sleeper_payload(mem_bytes: int = 0, memhold_bin: str = None) -> str:
    """Bash snippet whose exec'd process is the checkpointable session.

    Default: `sleep infinity` (an empty session process). With mem_bytes > 0
    (W10): w10_memhold pre-faults exactly that much anonymous memory and
    parks — the session-resident payload CRIU must dump and restore, the
    analog of the shell variable the Penumbra harness parks in its session
    bash (harness.session_mem_setup_command).
    """
    if mem_bytes <= 0:
        return f"exec -a {SLEEPER_ARGV0} sleep infinity"
    if memhold_bin is None:
        memhold_bin = default_memhold_bin()
    return f"exec -a {SLEEPER_ARGV0} {memhold_bin} {int(mem_bytes)}"


def _proc_rss_bytes(pid: int) -> int:
    """Current VmRSS of `pid` in bytes (0 when unreadable)."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def find_criu_binary():
    """Locate the criu executable.

    Search order:
      1. $CRIU_BIN (explicit override)
      2. Source-built binary in third_party/ (Ubuntu 24.04 noble has NO
         criu package in its repos, so we build from source there — see
         third_party/build_criu.sh)
      3. $PATH
    Returns None when not found.
    """
    env_bin = os.environ.get("CRIU_BIN")
    if env_bin:
        return env_bin if os.path.isfile(env_bin) and os.access(
            env_bin, os.X_OK) else None
    # Source build layout: third_party/criu-<ver>/criu/criu
    third_party = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "third_party")
    if os.path.isdir(third_party):
        for entry in sorted(os.listdir(third_party), reverse=True):
            if entry.startswith("criu-"):
                cand = os.path.join(third_party, entry, "criu", "criu")
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return cand
    return shutil.which("criu")


# ─── Pure helpers (unit-testable without root) ───────────────────────────────

def is_whiteout(path: str) -> bool:
    """True if `path` is an overlayfs whiteout (char device 0:0)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISCHR(st.st_mode) and st.st_rdev == 0


def promote_upper_to_lower(upper: str, lower: str):
    """Merge the overlayfs upperdir into the lowerdir (commit).

    Regular files/dirs/symlinks in upper are copied over the corresponding
    lower path; whiteouts (char 0:0) delete the lower path — this mirrors
    ShadowFS's tombstone-on-commit semantics for files removed inside an
    epoch. Opaque-directory xattrs are not interpreted (none of the RQ3
    workloads rmdir a merged directory; harness-level teardowns operate on
    the lowerdir directly, outside the overlay).
    """
    for root, dirs, files in os.walk(upper):
        rel = os.path.relpath(root, upper)
        dst_root = lower if rel == "." else os.path.join(lower, rel)
        os.makedirs(dst_root, exist_ok=True)
        for name in dirs + files:
            src = os.path.join(root, name)
            dst = os.path.join(dst_root, name)
            if is_whiteout(src):
                # The epoch deleted this path: propagate the deletion.
                if os.path.isdir(dst) and not os.path.islink(dst):
                    shutil.rmtree(dst, ignore_errors=True)
                elif os.path.lexists(dst):
                    os.unlink(dst)
                continue
            st = os.lstat(src)
            if stat.S_ISDIR(st.st_mode):
                if os.path.lexists(dst) and not os.path.isdir(dst):
                    # Upper replaced a lower file/symlink with a directory.
                    if os.path.isdir(dst) and not os.path.islink(dst):
                        shutil.rmtree(dst, ignore_errors=True)
                    else:
                        os.unlink(dst)
                os.makedirs(dst, exist_ok=True)
                continue
            # File or symlink: replace whatever the lower layer has.
            if os.path.isdir(dst) and not os.path.islink(dst):
                shutil.rmtree(dst, ignore_errors=True)
            elif os.path.lexists(dst):
                os.unlink(dst)
            if os.path.islink(src):
                os.symlink(os.readlink(src), dst)
            else:
                shutil.copy2(src, dst)


def build_run_command(command: str, cpu_pin=None,
                      commands: list = None, pin_once: bool = False) -> list:
    """Build the argv for one epoch run phase, mirroring the Penumbra
    harness's CPU-pinning policy:

    - single command:  bash -c "taskset -c N <cmd>"      (per-run pin)
    - command list, pin_once=False: caller runs each entry separately,
      each gets its own per-run taskset prefix (same as Penumbra default)
    - command list, pin_once=True: ONE bash -c 'set -e; c1; c2; ...' with
      a single outer taskset — affinity is inherited by every child, which
      matches Penumbra's epoch-level pin (no per-command wrapper cost)
    """
    if commands is not None and pin_once:
        script = "set -e; " + "; ".join(commands)
        argv = ["bash", "-c", script]
        if cpu_pin is not None:
            argv = ["taskset", "-c", str(cpu_pin)] + argv
        return argv
    if cpu_pin is not None:
        return ["bash", "-c", f"taskset -c {cpu_pin} {command}"]
    return ["bash", "-c", command]


# ─── Engine ──────────────────────────────────────────────────────────────────

class BaselineEngineError(RuntimeError):
    """An overlayfs/CRIU mechanism call failed."""


class OverlayCriuEngine:
    """One isolated session: overlayfs mount + a checkpointable process.

    Lifecycle:
        setup()                    create the directory tree (no mount)
        session_open()             mount overlayfs, spawn the sleeper
        timed_begin_epoch()        CRIU dump (snapshot)          [timed]
        timed_run(...)             run command in merged view    [timed]
        timed_commit()             promote + reset               [timed]
        timed_rollback()           restore + reset               [timed]
        recover_failed_epoch()     untimed reset after a failed run
        session_close()            kill sleeper, unmount
        teardown()                 remove the whole directory tree
    """

    def __init__(self, root: str, verbose: bool = True,
                 criu_bin: str = None):
        self.root = os.path.abspath(root)
        self.lower = os.path.join(self.root, DIR_LOWER)
        self.upper = os.path.join(self.root, DIR_UPPER)
        self.work = os.path.join(self.root, DIR_WORK)
        self.mnt = os.path.join(self.root, DIR_MNT)
        self.imgdir = os.path.join(self.root, DIR_CRIU)
        self.verbose = verbose
        self.criu_bin = criu_bin or find_criu_binary()
        self._sleeper_pid = None
        self._sleeper_child = None      # Popen handle while it is our child
        # W10: session-resident payload the sleeper must carry (bytes).
        # 0 = plain `sleep infinity` sleeper (every other workload).
        self.sleeper_mem_bytes = 0

    def log(self, msg: str):
        if self.verbose:
            print(f"  [baseline] {msg}", flush=True)

    # ─── lifecycle ────────────────────────────────────────────────────────

    def setup(self):
        """Create the engine directory tree. Idempotent."""
        for d in (self.lower, self.upper, self.work, self.mnt, self.imgdir):
            os.makedirs(d, exist_ok=True)

    def teardown(self):
        """Remove the engine directory tree entirely."""
        self.session_close()
        shutil.rmtree(self.root, ignore_errors=True)

    def session_open(self):
        """Mount the overlay and start the checkpointable session process."""
        self._mount()
        self._spawn_sleeper()

    def session_close(self):
        """Kill the session process and unmount."""
        try:
            self._kill_sleeper()
        finally:
            self._umount()

    # ─── overlayfs plumbing ───────────────────────────────────────────────

    def _mount(self):
        r = subprocess.run(
            ["mount", "-t", "overlay", "overlay",
             "-o", f"lowerdir={self.lower},upperdir={self.upper},"
                   f"workdir={self.work}",
             self.mnt],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise BaselineEngineError(f"overlayfs mount failed: {r.stderr.strip()}")

    def _umount(self):
        for attempt in range(3):
            r = subprocess.run(["umount", self.mnt],
                               capture_output=True, text=True)
            if r.returncode == 0:
                return
            time.sleep(0.2)
        # Lazy fallback: detach even if something still holds a reference.
        subprocess.run(["umount", "-l", self.mnt], capture_output=True)

    def _reset_upper(self):
        """Drop the speculative layer: unmount, wipe upper/work, remount.

        Both commit and rollback end with this so the next epoch starts
        from a clean merged view of the (possibly promoted) lowerdir.
        """
        self._umount()
        shutil.rmtree(self.upper, ignore_errors=True)
        shutil.rmtree(self.work, ignore_errors=True)
        os.makedirs(self.upper, exist_ok=True)
        os.makedirs(self.work, exist_ok=True)
        self._mount()

    def refresh(self):
        """Re-export the lowerdir through the merged view.

        setup_fn() writes input files directly into the lowerdir (the
        analog of Penumbra's setup writing into the orig backing store,
        which is immediately visible through FUSE). A live overlayfs does
        NOT reliably reflect behind-the-mount lowerdir changes (negative
        dentry caching), so the mount is rebuilt after every setup. This
        is untimed setup cost, exactly like Penumbra's file creation.
        """
        self._reset_upper()

    # ─── sleeper process (process-state payload) ──────────────────────────

    def _spawn_sleeper(self):
        # exec -a gives the process a unique argv[0] so the restored PID can
        # be found again after criu restore re-parents it to init.
        if self.sleeper_mem_bytes:
            memhold_bin = default_memhold_bin()
            if not (os.path.isfile(memhold_bin)
                    and os.access(memhold_bin, os.X_OK)):
                raise BaselineEngineError(
                    f"w10_memhold not found/executable: {memhold_bin} "
                    "(run make in experiments/rq3/benchmarks)")
        self._sleeper_child = subprocess.Popen(
            ["bash", "-c", sleeper_payload(self.sleeper_mem_bytes)],
            cwd=self.root,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
        self._sleeper_pid = self._sleeper_child.pid
        # fork → exec bash → bash startup → exec sleep is NOT instantaneous:
        # /proc/<pid>/cmdline briefly shows "bash" or "" (mid-exec), which
        # _sleeper_alive() would misread as "not the sleeper". Wait until
        # the marker argv[0] is visible; a real spawn failure (bash exec
        # error → early exit) is caught by poll().
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if self._sleeper_child.poll() is not None:
                raise BaselineEngineError(
                    "sleeper exited during startup "
                    f"(rc={self._sleeper_child.returncode})")
            if self._sleeper_alive():
                break
            time.sleep(0.001)
        else:
            raise BaselineEngineError("sleeper did not become ready within 10s")
        if self.sleeper_mem_bytes:
            # The payload must be RESIDENT before we return: criu dumps
            # whatever RSS exists at dump time, so returning mid-touch would
            # make the snapshot size (and every epoch cost) depend on spawn
            # timing instead of the requested axis.
            deadline = time.monotonic() + 60.0
            while time.monotonic() < deadline:
                if self._sleeper_child.poll() is not None:
                    raise BaselineEngineError(
                        "memhold sleeper exited while touching its payload "
                        f"(rc={self._sleeper_child.returncode})")
                if _proc_rss_bytes(self._sleeper_pid) >= self.sleeper_mem_bytes:
                    return
                time.sleep(0.002)
            raise BaselineEngineError(
                "sleeper RSS never reached the requested payload "
                f"({self.sleeper_mem_bytes} bytes)")

    def _sleeper_alive(self) -> bool:
        pid = self._sleeper_pid
        if pid is None:
            return False
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                return f.read().split(b"\x00")[0].decode(
                    "utf-8", "replace") == SLEEPER_ARGV0
        except (FileNotFoundError, ProcessLookupError):
            return False

    def _kill_sleeper(self):
        pid = self._sleeper_pid
        if pid is None:
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if self._sleeper_child is not None:
            # Original child of ours: reap it so it does not linger as a
            # zombie (a zombie keeps its /proc entry alive).
            try:
                self._sleeper_child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            self._sleeper_child = None
        else:
            # Restored process is NOT our child: poll /proc until gone.
            # 1ms poll: the SIGKILLed sleeper lingers as a zombie until its
            # (init) parent reaps it, so the first check virtually always
            # still sees it — the old 50ms granularity added a fixed ~50ms
            # to EVERY shared-session rollback phase (measured 61ms shared
            # vs 11.6ms fresh, where the sleeper is always our child and
            # gets reaped via wait()), inflating the baseline's rollback
            # numbers ~2x against Penumbra.
            deadline = time.time() + 5
            while time.time() < deadline and os.path.exists(f"/proc/{pid}"):
                time.sleep(0.001)
        self._sleeper_pid = None

    def _find_sleeper_pid(self, expected_pid) -> int:
        """Locate the sleeper PID after a restore (same PID in the common
        case; /proc scan as fallback)."""
        if expected_pid is not None:
            try:
                with open(f"/proc/{expected_pid}/cmdline", "rb") as f:
                    argv0 = f.read().split(b"\x00")[0].decode(
                        "utf-8", "replace")
                if argv0 == SLEEPER_ARGV0:
                    return expected_pid
            except (FileNotFoundError, ProcessLookupError):
                pass
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as f:
                    argv0 = f.read().split(b"\x00")[0].decode(
                        "utf-8", "replace")
                if argv0 == SLEEPER_ARGV0:
                    return int(entry)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        raise BaselineEngineError(
            f"sleeper process not found after restore (marker {SLEEPER_ARGV0})")

    # ─── CRIU checkpoint/restore ──────────────────────────────────────────

    def _run_criu(self, args, timeout=120) -> subprocess.CompletedProcess:
        if not self.criu_bin:
            raise BaselineEngineError(
                "criu binary not found — build it with: "
                "sudo bash experiments/rq3/third_party/build_criu.sh "
                "(Ubuntu 24.04 noble has no criu package in apt)")
        cmd = [self.criu_bin] + args
        try:
            return subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout)
        except FileNotFoundError as e:
            raise BaselineEngineError(
                f"criu binary not found at {self.criu_bin!r} — rebuild "
                "with: sudo bash experiments/rq3/third_party/build_criu.sh"
            ) from e

    def timed_begin_epoch(self) -> int:
        """CRIU-checkpoint the session process. Returns elapsed ns."""
        # Untimed: clear images left over from a previous epoch.
        shutil.rmtree(self.imgdir, ignore_errors=True)
        os.makedirs(self.imgdir, exist_ok=True)
        if not self._sleeper_alive():
            raise BaselineEngineError("sleeper process died before dump")
        with Timer() as t:
            r = self._run_criu([
                "dump", "-t", str(self._sleeper_pid),
                "--images-dir", self.imgdir,
                "--leave-running",
                # verbosity is an optional_argument in criu's getopt table:
                # the value must be attached with '=' (--verbosity 2 leaves
                # the "2" as a stray positional → "excessive parameter").
                "--verbosity=2",
                "--log-file", os.path.join(self.imgdir, "dump.log"),
            ])
        if r.returncode != 0:
            raise BaselineEngineError(
                f"criu dump failed (rc={r.returncode}): "
                f"{self._criu_error(self.imgdir, 'dump.log', r)}")
        return t.elapsed_ns

    def _criu_error(self, imgdir, logfile, proc) -> str:
        tail = (proc.stderr or "").strip()[-300:]
        try:
            with open(os.path.join(imgdir, logfile), errors="replace") as f:
                lines = f.read().strip().splitlines()
                tail = (tail + " | log: " + "; ".join(lines[-5:])).strip()
        except OSError:
            pass
        return tail

    def timed_run(self, argv: list, timeout: float = 60.0):
        """Run one command (argv list) against the merged view.

        Returns (returncode, output, elapsed_ns) where output is stdout +
        stderr concatenated. cwd is the merged mount, matching the Penumbra
        session's working directory semantics.

        Both streams are returned because the Penumbra session log captures
        them merged (session_proxy dup2's the log fd onto fd 1 AND fd 2), so
        its verify_fn regexes run against the combined text. The W10
        benchmark deliberately prints its "total=N writes=M" metadata to
        stderr — capturing stdout only made every W10 sample fail verify.
        """
        with Timer() as t:
            try:
                proc = subprocess.run(
                    argv, cwd=self.mnt, capture_output=True, text=True,
                    timeout=timeout)
                rc = proc.returncode
                out = (proc.stdout or "") + (proc.stderr or "")
            except subprocess.TimeoutExpired:
                rc, out = 124, ""
        return rc, out, t.elapsed_ns

    def timed_commit(self) -> int:
        """Promote upperdir → lowerdir, discard the checkpoint, reset upper.
        Returns elapsed ns."""
        with Timer() as t:
            promote_upper_to_lower(self.upper, self.lower)
            shutil.rmtree(self.imgdir, ignore_errors=True)
            self._reset_upper()
        return t.elapsed_ns

    def timed_rollback(self) -> int:
        """Restore the session process from the checkpoint and discard the
        speculative file state. Returns elapsed ns."""
        with Timer() as t:
            old_pid = self._sleeper_pid
            self._kill_sleeper()
            r = self._run_criu([
                "restore",
                "--images-dir", self.imgdir,
                "-d",  # detach: restored process keeps running
                "--verbosity=2",
                "--log-file", os.path.join(self.imgdir, "restore.log"),
            ])
            if r.returncode != 0:
                raise BaselineEngineError(
                    f"criu restore failed (rc={r.returncode}): "
                    f"{self._criu_error(self.imgdir, 'restore.log', r)}")
            self._sleeper_pid = self._find_sleeper_pid(old_pid)
            self._sleeper_child = None
            self._reset_upper()
        return t.elapsed_ns

    def recover_failed_epoch(self):
        """Untimed recovery after a failed run phase: drop the speculative
        layer so the next epoch starts clean (the sleeper was never killed,
        so no process restore is needed)."""
        try:
            self._reset_upper()
        except BaselineEngineError as e:
            self.log(f"recovery failed: {e}")
