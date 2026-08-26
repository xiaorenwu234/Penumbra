#!/usr/bin/env python3
"""Configuration for the Penumbra LangChain integration.

Every path and socket the four daemons need lives here, so callers can boot the
whole stack with ``penumbra.start()`` and override only what differs.

Environment variables (all optional) mirror the field names with a
``PENUMBRA_`` prefix, e.g. ``PENUMBRA_ORCH_SOCK``, ``PENUMBRA_WORKSPACE``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import List, Optional

#: Repository root (the checkout that contains ShadowFS/, ShadowProc/, ...).
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_DEFAULT_RUN_DIR = "/tmp/penumbra"


def _env(name: str, default):
    return os.environ.get(f"PENUMBRA_{name.upper()}", default)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(f"PENUMBRA_{name.upper()}")
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(f"PENUMBRA_{name.upper()}")
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class PenumbraConfig:
    """Where the daemons live, where they listen, and what they guard.

    The three directories form the ShadowFS overlay:
      * ``workspace`` – the FUSE mount guarded tools must write through;
      * ``backing_dir`` – the real (lower) directory promoted to on commit;
      * ``staging_dir`` – copy-up/WAL area, an implementation detail.
    """

    # ── Component binaries / entry points ────────────────────────────────
    project_root: str = PROJECT_ROOT
    shadowfs_bin: str = field(default_factory=lambda: _env(
        "shadowfs_bin", os.path.join(PROJECT_ROOT, "ShadowFS", "shadowfs")))
    shadowproc_bin: str = field(default_factory=lambda: _env(
        "shadowproc_bin", os.path.join(PROJECT_ROOT, "ShadowProc", "target",
                                       "release", "shadow-proc")))
    shadowobserve_bin: str = field(default_factory=lambda: _env(
        "shadowobserve_bin", os.path.join(PROJECT_ROOT, "ShadowObserve",
                                          "build", "observ_daemon")))
    orchestrator_script: str = field(default_factory=lambda: _env(
        "orchestrator_script", os.path.join(PROJECT_ROOT, "orchestrator",
                                            "shadow_orchestrator.py")))
    python_bin: str = field(default_factory=lambda: _env("python_bin", "python3"))

    # ── Sockets ──────────────────────────────────────────────────────────
    orch_sock: str = field(default_factory=lambda: _env(
        "orch_sock", os.path.join(_DEFAULT_RUN_DIR, "orch.sock")))
    shadowfs_sock: str = field(default_factory=lambda: _env(
        "shadowfs_sock", os.path.join(_DEFAULT_RUN_DIR, "shadowfs.sock")))
    shadowproc_sock: str = field(default_factory=lambda: _env(
        "shadowproc_sock", os.path.join(_DEFAULT_RUN_DIR, "shadowproc.sock")))
    shadowobserve_sock: str = field(default_factory=lambda: _env(
        "shadowobserve_sock", os.path.join(_DEFAULT_RUN_DIR, "observe.sock")))

    # ── Guarded filesystem ───────────────────────────────────────────────
    workspace: str = field(default_factory=lambda: _env(
        "workspace", os.path.join(_DEFAULT_RUN_DIR, "workspace")))
    backing_dir: str = field(default_factory=lambda: _env(
        "backing_dir", os.path.join(_DEFAULT_RUN_DIR, "backing")))
    staging_dir: str = field(default_factory=lambda: _env(
        "staging_dir", os.path.join(_DEFAULT_RUN_DIR, "staging")))

    # ── Process / cgroup ─────────────────────────────────────────────────
    cgroup_root: str = field(default_factory=lambda: _env(
        "cgroup_root", "/sys/fs/cgroup"))
    cgroup_prefix: str = field(default_factory=lambda: _env(
        "cgroup_prefix", "penumbra"))
    log_dir: str = field(default_factory=lambda: _env(
        "log_dir", os.path.join(_DEFAULT_RUN_DIR, "logs")))

    # ── Behaviour ────────────────────────────────────────────────────────
    #: Default agent identity; the orchestrator serializes one agent's tool
    #: calls across all of its sessions.
    agent_id: str = field(default_factory=lambda: _env("agent_id", "langchain-agent"))
    #: Launch the daemons when no orchestrator is already listening.
    autostart: bool = field(default_factory=lambda: _env_bool("autostart", True))
    #: Reuse an orchestrator that is already listening on ``orch_sock``.
    attach_if_running: bool = field(
        default_factory=lambda: _env_bool("attach_if_running", True))
    #: ShadowObserve is optional; missing binary is tolerated when False.
    require_observe: bool = field(
        default_factory=lambda: _env_bool("require_observe", False))
    #: Fail closed. When True a guarded tool that cannot be executed under
    #: monitoring raises instead of silently running unmonitored.
    strict: bool = field(default_factory=lambda: _env_bool("strict", True))
    #: Stop daemons we started when the interpreter exits.
    stop_on_exit: bool = field(default_factory=lambda: _env_bool("stop_on_exit", True))
    #: Wipe backing/staging state on start (fresh overlay for a new run).
    clean_state: bool = field(default_factory=lambda: _env_bool("clean_state", False))
    #: Roll back epochs ShadowFS recovers from a previous run. Such orphans are
    #: neither committed nor rolled back, and they block every later commit that
    #: touches the same files. Only applies to stacks we start ourselves.
    reclaim_orphan_epochs: bool = field(
        default_factory=lambda: _env_bool("reclaim_orphan_epochs", True))

    # ── Timeouts (seconds) ───────────────────────────────────────────────
    start_timeout: float = 30.0
    request_timeout: float = 180.0
    command_timeout: float = 60.0
    tool_timeout: float = field(
        default_factory=lambda: _env_float("tool_timeout", 300.0))
    #: How long to keep retrying a commit that came back "authorized_pending"
    #: (policy accepted, epoch kept fenced, file layer still finalizing while
    #: the orchestrator's background loop settles the dependency group).
    commit_retry_timeout: float = 30.0

    def __post_init__(self) -> None:
        # Normalize so cgroup/FS attribution comparisons are string-stable.
        for name in ("workspace", "backing_dir", "staging_dir", "log_dir",
                     "cgroup_root"):
            setattr(self, name, os.path.abspath(getattr(self, name)))

    # ── Helpers ──────────────────────────────────────────────────────────

    def replace(self, **kwargs) -> "PenumbraConfig":
        """Return a copy with fields overridden (validated by __post_init__)."""
        return replace(self, **kwargs)

    @property
    def socket_dirs(self) -> List[str]:
        return sorted({os.path.dirname(p) for p in (
            self.orch_sock, self.shadowfs_sock, self.shadowproc_sock,
            self.shadowobserve_sock) if os.path.dirname(p)})

    def ensure_dirs(self) -> None:
        for path in (self.workspace, self.backing_dir, self.staging_dir,
                     self.log_dir, *self.socket_dirs):
            os.makedirs(path, exist_ok=True)

    def workspace_path(self, relative: str) -> str:
        """A path inside the guarded FUSE mount (what tools should write to)."""
        return os.path.join(self.workspace, relative.lstrip("/"))

    def backing_path(self, relative: str) -> str:
        """The same file in the backing store (what a commit promotes to)."""
        return os.path.join(self.backing_dir, relative.lstrip("/"))

    def cgroup_path(self, cgroup_id: str) -> str:
        """Absolute cgroupfs path for an orchestrator cgroup_id ("/name")."""
        return os.path.join(self.cgroup_root, cgroup_id.lstrip("/"))

    def observe_available(self) -> bool:
        return os.path.isfile(self.shadowobserve_bin) and \
            os.access(self.shadowobserve_bin, os.X_OK)

    def missing_binaries(self) -> List[str]:
        """Required binaries that are absent or not executable."""
        missing = []
        for path in (self.shadowfs_bin, self.shadowproc_bin):
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                missing.append(path)
        if not os.path.isfile(self.orchestrator_script):
            missing.append(self.orchestrator_script)
        if self.require_observe and not self.observe_available():
            missing.append(self.shadowobserve_bin)
        return missing


DEFAULT_CONFIG = PenumbraConfig
