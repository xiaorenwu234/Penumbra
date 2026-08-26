#!/usr/bin/env python3
"""Boot (or attach to) the four Penumbra daemons from Python.

``penumbra.start()`` ends up here. Either an orchestrator is already listening —
then we attach and own nothing — or we launch ShadowFS, ShadowProc, the optional
ShadowObserve, and the orchestrator itself, in that order, waiting for each
socket before moving on.

Only processes this supervisor started are ever stopped by it.
"""

from __future__ import annotations

import atexit
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

from .client import OrchestratorClient, PenumbraError
from .config import PenumbraConfig

#: Same logger the rest of the package uses; runtime.py configures it from
#: PENUMBRA_LOG at import time.
logger = logging.getLogger("penumbra")


class StartupError(PenumbraError):
    """A daemon failed to start, or the environment cannot support one."""


@dataclass
class _Daemon:
    name: str
    process: subprocess.Popen
    log_path: str
    sock_path: Optional[str] = None


def _log_tail(path: str, lines: int = 20) -> str:
    try:
        with open(path, "r", errors="replace") as handle:
            return "".join(handle.readlines()[-lines:]).strip()
    except OSError:
        return "<no log>"


def _wait_for_socket(path: str, timeout: float, daemon: _Daemon) -> None:
    """Wait for a daemon's socket, failing fast if the daemon dies first."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return
        if daemon.process.poll() is not None:
            raise StartupError(
                f"{daemon.name} exited with code {daemon.process.returncode} "
                f"before creating {path}\n--- {daemon.log_path} ---\n"
                f"{_log_tail(daemon.log_path)}")
        time.sleep(0.1)
    raise StartupError(
        f"{daemon.name} did not create {path} within {timeout}s\n"
        f"--- {daemon.log_path} ---\n{_log_tail(daemon.log_path)}")


def _is_mounted(path: str) -> bool:
    try:
        with open("/proc/mounts", "r") as handle:
            return any(len(parts) >= 2 and parts[1] == path
                       for parts in (line.split() for line in handle))
    except OSError:
        return False


def _mount_responds(path: str) -> bool:
    """True if the mount at ``path`` still has a server answering.

    A FUSE mount whose daemon died stays listed in /proc/mounts but every
    syscall against it fails (ENOTCONN, or EACCES for a non-root caller).
    """
    try:
        os.stat(path)
        return True
    except OSError:
        return False


class Supervisor:
    """Owns the daemon processes started for one :class:`PenumbraConfig`."""

    def __init__(self, config: PenumbraConfig):
        self.config = config
        self.daemons: List[_Daemon] = []
        self.attached = False
        self._started = False
        self._atexit_registered = False

    # ── lifecycle ────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._started or self.attached

    def start(self) -> None:
        if self.running:
            return
        cfg = self.config
        client = OrchestratorClient(cfg.orch_sock, timeout=cfg.request_timeout)

        if cfg.attach_if_running and client.is_listening():
            self.attached = True
            return
        if not cfg.autostart:
            raise StartupError(
                f"no orchestrator is listening on {cfg.orch_sock} and "
                f"autostart is disabled. Start the stack manually or pass "
                f"autostart=True.")

        self._preflight()
        cfg.ensure_dirs()
        if cfg.clean_state:
            self._clean_state()
        self._clear_stale_sockets()

        try:
            self._start_shadowfs()
            self._start_shadowproc()
            self._start_shadowobserve()
            self._start_orchestrator()
        except BaseException:
            # A half-started stack leaves a FUSE mount and eBPF programs
            # behind; unwind before surfacing the failure.
            self.stop()
            raise

        if not client.wait_until_listening(cfg.start_timeout):
            log_path = os.path.join(cfg.log_dir, "orchestrator.log")
            self.stop()
            raise StartupError(
                f"orchestrator is not answering on {cfg.orch_sock}\n"
                f"--- {log_path} ---\n{_log_tail(log_path)}")

        self._started = True
        if cfg.stop_on_exit and not self._atexit_registered:
            atexit.register(self.stop)
            self._atexit_registered = True

    def stop(self) -> None:
        """Stop the daemons we started (attached stacks are left alone)."""
        if self.attached:
            self.attached = False
            return
        for daemon in reversed(self.daemons):
            self._terminate(daemon)
        self.daemons.clear()
        if _is_mounted(self.config.workspace):
            subprocess.run(["umount", "-l", self.config.workspace],
                           check=False, capture_output=True)
        self._clear_stale_sockets()
        self._started = False

    def _terminate(self, daemon: _Daemon) -> None:
        proc = daemon.process
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        except OSError:
            pass

    # ── preflight ────────────────────────────────────────────────────────

    def _preflight(self) -> None:
        cfg = self.config
        if os.geteuid() != 0:
            raise StartupError(
                "starting the Penumbra stack requires root (FUSE mount, eBPF "
                "LSM programs, cgroup writes). Run the agent under sudo, or "
                "start the daemons separately and let penumbra.start() attach "
                f"to {cfg.orch_sock}.")
        missing = cfg.missing_binaries()
        if missing:
            raise StartupError(
                "missing component binaries: " + ", ".join(missing) +
                "\nBuild them first: (cd ShadowFS && go build -o shadowfs .); "
                "(cd ShadowProc && cargo build --release); "
                "ShadowObserve: cmake+make in ShadowObserve/build")
        if not os.path.isdir(cfg.cgroup_root):
            raise StartupError(f"cgroup root {cfg.cgroup_root} does not exist "
                               f"(cgroup v2 is required)")
        # Check this BEFORE ensure_dirs(): a leftover FUSE mount makes even
        # os.makedirs(exist_ok=True) fail with a baffling FileExistsError,
        # because mkdir reports EEXIST while isdir() on a stale mount is False.
        if _is_mounted(cfg.workspace):
            stale = not _mount_responds(cfg.workspace)
            what = ("a STALE mount left over from a killed/crashed run"
                    if stale else "already a live mount point")
            raise StartupError(
                f"{cfg.workspace} is {what}.\n"
                f"A FUSE mount outlives the process that created it, so it must "
                f"be removed before starting again:\n"
                f"    sudo umount -l {cfg.workspace}\n"
                f"Alternatively point penumbra.start(workspace=...) somewhere "
                f"else." + ("" if stale else
                            "\nIf another Penumbra stack is running, attach to "
                            "it instead (autostart=False)."))

    def _clean_state(self) -> None:
        cfg = self.config
        if _is_mounted(cfg.workspace):
            raise StartupError(
                f"refusing to clean state while {cfg.workspace} is still "
                f"mounted; unmount it first")
        for path in (cfg.staging_dir, cfg.backing_dir):
            shutil.rmtree(path, ignore_errors=True)
            os.makedirs(path, exist_ok=True)

    def _clear_stale_sockets(self) -> None:
        cfg = self.config
        for path in (cfg.orch_sock, cfg.shadowfs_sock, cfg.shadowproc_sock,
                     cfg.shadowobserve_sock):
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass

    # ── individual daemons ───────────────────────────────────────────────

    def _spawn(self, name: str, argv: List[str],
               sock_path: Optional[str] = None,
               cwd: Optional[str] = None) -> _Daemon:
        log_path = os.path.join(self.config.log_dir, f"{name}.log")
        log_file = open(log_path, "ab", buffering=0)
        try:
            process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=log_file,
                stderr=subprocess.STDOUT, start_new_session=True, cwd=cwd)
        finally:
            log_file.close()
        daemon = _Daemon(name=name, process=process, log_path=log_path,
                         sock_path=sock_path)
        self.daemons.append(daemon)
        return daemon

    def _start_shadowfs(self) -> None:
        cfg = self.config
        if _is_mounted(cfg.workspace):
            raise StartupError(
                f"{cfg.workspace} is already a mount point. Unmount it "
                f"(umount -l {cfg.workspace}) or choose another workspace.")
        daemon = self._spawn("shadowfs", [
            cfg.shadowfs_bin,
            "-staging", cfg.staging_dir,
            "-sock", cfg.shadowfs_sock,
            "-allow-other",
            cfg.workspace,
            cfg.backing_dir,
        ], sock_path=cfg.shadowfs_sock)
        _wait_for_socket(cfg.shadowfs_sock, cfg.start_timeout, daemon)
        deadline = time.time() + cfg.start_timeout
        while not _is_mounted(cfg.workspace):
            if time.time() > deadline:
                raise StartupError(
                    f"ShadowFS did not mount {cfg.workspace} within "
                    f"{cfg.start_timeout}s\n--- {daemon.log_path} ---\n"
                    f"{_log_tail(daemon.log_path)}")
            time.sleep(0.1)
        self._reclaim_orphan_epochs(daemon.log_path)

    def _reclaim_orphan_epochs(self, log_path: str) -> None:
        """Roll back epochs ShadowFS recovered from a previous run.

        An epoch left neither committed nor rolled back stays the current
        version of every file it touched. A new epoch that so much as reads such
        a file inherits a read-from dependency on it and cannot finalize before
        it does, so commits hang until the orchestrator's poll times out — and
        each failure leaves another orphan, compounding silently.

        Rolling them back discards only their uncommitted writes; already
        committed data in the backing store survives (unlike clean_state, which
        wipes everything). This runs only when we started ShadowFS ourselves,
        never when attaching to a stack someone else owns.
        """
        cfg = self.config
        if not cfg.reclaim_orphan_epochs:
            return
        match = re.search(r"state recovered: (\d+) epochs",
                          _log_tail(log_path, lines=50))
        if not match or match.group(1) == "0":
            return
        # ShadowFS speaks the same newline-delimited JSON protocol as the
        # orchestrator, so the same client works against its socket.
        fs = OrchestratorClient(cfg.shadowfs_sock, timeout=cfg.request_timeout)
        try:
            infos = fs.request("list_agents").get("agents_info") or []
        except PenumbraError as exc:
            logger.warning("could not list ShadowFS epochs (%s); orphans from "
                           "a previous run may block commits", exc)
            return
        # Finalizing/Finalized must NOT take a normal rollback: ShadowFS allows
        # only completion or retry from those states.
        stale = [i for i in infos
                 if i.get("state") in ("speculative", "authorized_pending")]
        held = [i for i in infos
                if i.get("state") in ("finalizing", "finalized")]
        for info in stale:
            epoch_id = info.get("epoch_id") or ""
            try:
                fs.request_ok("rollback_epoch", epoch_id=epoch_id)
                logger.info("rolled back orphan epoch %s (state=%s) left by a "
                            "previous run", epoch_id, info.get("state"))
            except PenumbraError as exc:
                # A rollback cascades to dependents, so an epoch later in this
                # list may already be gone. That is success, not failure.
                logger.debug("orphan epoch %s not rolled back: %s",
                             epoch_id, exc)
        if held:
            logger.warning(
                "%d recovered epoch(s) are mid-finalization or finalized and "
                "cannot be rolled back safely; if commits still hang, start "
                "with clean_state=True to discard all state: %s",
                len(held), ", ".join(f"{i.get('epoch_id')}({i.get('state')})"
                                     for i in held))

    def _start_shadowproc(self) -> None:
        cfg = self.config
        daemon = self._spawn("shadowproc", [
            cfg.shadowproc_bin, "--sock", cfg.shadowproc_sock,
        ], sock_path=cfg.shadowproc_sock)
        _wait_for_socket(cfg.shadowproc_sock, cfg.start_timeout, daemon)

    def _start_shadowobserve(self) -> None:
        cfg = self.config
        if not cfg.observe_available():
            if cfg.require_observe:
                raise StartupError(
                    f"ShadowObserve binary not found: {cfg.shadowobserve_bin}")
            return
        daemon = self._spawn("shadowobserve", [
            cfg.shadowobserve_bin, "--sock", cfg.shadowobserve_sock,
        ], sock_path=cfg.shadowobserve_sock)
        try:
            _wait_for_socket(cfg.shadowobserve_sock, cfg.start_timeout, daemon)
        except StartupError:
            if cfg.require_observe:
                raise
            # Observation is optional: keep the stack usable without it.
            self._terminate(daemon)
            self.daemons.remove(daemon)

    def _start_orchestrator(self) -> None:
        cfg = self.config
        argv = [
            cfg.python_bin, cfg.orchestrator_script,
            "--shadowfs-sock", cfg.shadowfs_sock,
            "--shadowproc-sock", cfg.shadowproc_sock,
            "--listen", cfg.orch_sock,
            "--shadowfs-mount", cfg.workspace,
            "--backing-dir", f"{cfg.backing_dir}:{cfg.staging_dir}",
        ]
        if os.path.exists(cfg.shadowobserve_sock):
            argv += ["--shadowobserve-sock", cfg.shadowobserve_sock]
        # cwd = project root so the orchestrator resolves policy.policy_ir.
        daemon = self._spawn("orchestrator", argv, sock_path=cfg.orch_sock,
                             cwd=cfg.project_root)
        _wait_for_socket(cfg.orch_sock, cfg.start_timeout, daemon)

    # ── diagnostics ──────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "attached": self.attached,
            "started": self._started,
            "workspace": self.config.workspace,
            "workspace_mounted": _is_mounted(self.config.workspace),
            "orch_sock": self.config.orch_sock,
            "daemons": [
                {"name": d.name, "pid": d.process.pid,
                 "alive": d.process.poll() is None, "log": d.log_path}
                for d in self.daemons
            ],
        }
