#!/usr/bin/env python3
"""Penumbra — speculative execution + policy control for LangChain agents.

Two lines to put your agent's tools under monitoring::

    import penumbra
    penumbra.start(policy=MyPolicy())          # boot (or attach to) the stack

    @penumbra.guard()                           # annotate a tool → monitored
    @tool
    def write_report(path: str, body: str) -> str:
        ...

Every ``@penumbra.guard()``-annotated tool call becomes a speculative epoch:
its filesystem and process effects are held back, your :class:`PolicyGenerator`
inspects a fixed-shape :class:`PolicyRequest`, and returns a fixed-shape
:class:`PolicyDecision` — ``allow`` (commit under typed rules) or ``deny`` (roll
back losslessly). Override one method, annotate your tools, done.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from .client import (OrchestratorClient, OrchestratorError,
                     OrchestratorUnavailable, PenumbraError)
from .config import PenumbraConfig
from .guard import GuardSpec, GuardedResult, guard_spec, is_guarded, make_guard
from .policy import (ALLOW, DENY, AllowAllPolicy, DenyAllPolicy, EffectRule,
                     FunctionPolicyGenerator, LLMPolicyGenerator,
                     ObservedCommand, PolicyDecision, PolicyGenerationError,
                     PolicyGenerator, PolicyRequest, PolicyViolation,
                     WorkspacePolicy, allow, deny, filesystem_rules,
                     shell_plumbing_rules)
from .runtime import (GuardError, MODE_AUTO, MODE_FORK, MODE_INLINE, MODE_SHELL,
                      PenumbraRuntime, ToolExecutionError)
from .supervisor import StartupError

__version__ = "0.1.0"

# ── the process-wide default runtime ─────────────────────────────────────

_runtime: Optional[PenumbraRuntime] = None
_runtime_lock = threading.Lock()


def get_runtime() -> PenumbraRuntime:
    """The default runtime, created on first use.

    ``@guard()`` calls this lazily at tool-invocation time, so tools may be
    decorated at import time before :func:`start` is called.
    """
    global _runtime
    with _runtime_lock:
        if _runtime is None:
            _runtime = PenumbraRuntime()
        return _runtime


def start(policy: Any = None, config: Optional[PenumbraConfig] = None,
          **overrides) -> PenumbraRuntime:
    """Boot the Penumbra stack (or attach to a running one) and return it.

    This is the one-liner. Call it once near the top of your agent script::

        penumbra.start(policy=MyPolicy(), workspace="/srv/agent-workspace")

    Args:
        policy: A :class:`PolicyGenerator` subclass/instance, or a function
            ``(PolicyRequest) -> PolicyDecision``. Defaults to
            :class:`WorkspacePolicy` (filesystem effects inside the workspace).
        config: A fully-built :class:`PenumbraConfig`. When omitted, one is
            built from environment variables and ``**overrides``.
        **overrides: Individual :class:`PenumbraConfig` fields to override,
            e.g. ``workspace=...``, ``agent_id=...``, ``autostart=False``.

    Returns:
        The started :class:`PenumbraRuntime` (also stored as the default).
    """
    global _runtime
    with _runtime_lock:
        if config is None:
            config = PenumbraConfig(**overrides) if overrides else PenumbraConfig()
        elif overrides:
            config = config.replace(**overrides)
        if _runtime is None:
            _runtime = PenumbraRuntime(config=config, policy=policy)
        else:
            _runtime.config = config
            if policy is not None:
                _runtime.set_policy(policy)
        _runtime.start()
        return _runtime


def stop() -> None:
    """Stop the default runtime and any daemons it started."""
    global _runtime
    with _runtime_lock:
        if _runtime is not None:
            _runtime.stop()


def set_policy(policy: Any) -> None:
    """Replace the default runtime's policy generator."""
    get_runtime().set_policy(policy)


def status() -> Dict[str, Any]:
    """A snapshot of daemon and session state."""
    return get_runtime().status()


def run(command: str, timeout: Optional[float] = None,
        check: bool = True) -> str:
    """Run a shell command inside the current guarded epoch (see runtime.run)."""
    return get_runtime().run(command, timeout=timeout, check=check)


def workspace_path(relative: str = "") -> str:
    """A path inside the guarded workspace mount."""
    return get_runtime().workspace_path(relative)


def epoch(tool_name: str = "manual", **kwargs):
    """Open a speculative epoch by hand (context manager). See runtime.epoch."""
    return get_runtime().epoch(tool_name=tool_name, **kwargs)


# ── the annotation, bound to the default runtime ─────────────────────────

guard = make_guard(get_runtime)


def wrap_tools(tools: List[Any], **guard_kwargs) -> List[Any]:
    """Guard a whole list of tools at once (e.g. before building an agent).

    ::

        tools = penumbra.wrap_tools([write_file, run_query])
        agent = create_agent(model=llm, tools=tools)

    Tools already guarded are passed through untouched.
    """
    wrapped = []
    for tool in tools:
        wrapped.append(tool if is_guarded(tool) else guard(tool, **guard_kwargs))
    return wrapped


__all__ = [
    "__version__",
    # entry points
    "start", "stop", "status", "run", "epoch", "workspace_path",
    "guard", "wrap_tools", "set_policy", "get_runtime",
    # config / runtime
    "PenumbraConfig", "PenumbraRuntime",
    # policy authoring
    "PolicyGenerator", "PolicyRequest", "PolicyDecision", "EffectRule",
    "ObservedCommand", "WorkspacePolicy", "AllowAllPolicy", "DenyAllPolicy",
    "FunctionPolicyGenerator", "LLMPolicyGenerator", "allow", "deny",
    "filesystem_rules", "shell_plumbing_rules", "ALLOW", "DENY",
    # results / introspection
    "GuardedResult", "GuardSpec", "is_guarded", "guard_spec",
    # modes
    "MODE_FORK", "MODE_SHELL", "MODE_INLINE", "MODE_AUTO",
    # errors
    "PenumbraError", "PolicyViolation", "PolicyGenerationError",
    "GuardError", "ToolExecutionError", "StartupError",
    "OrchestratorError", "OrchestratorUnavailable",
]
