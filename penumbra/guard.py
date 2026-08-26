#!/usr/bin/env python3
"""``@penumbra.guard()`` — the one annotation that puts a tool under monitoring.

Works on three shapes, so decorator order never matters:

    @penumbra.guard()              @tool                     tool = guard(tool)
    @tool                          @penumbra.guard()
    def f(...): ...                 def f(...): ...

Async tools are supported: the epoch bracket runs in a worker thread, so the
event loop is not blocked while the orchestrator commits.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, Dict, Optional, Sequence

from .policy import PolicyLike
from .runtime import MODE_SHELL, GuardedResult, PenumbraRuntime

#: Attribute marking an object as guarded (used by wrap_tools / introspection).
GUARD_ATTR = "__penumbra_guard__"


class GuardSpec:
    """The annotation's parameters, attached to the wrapped callable."""

    def __init__(self, mode: str, policy: Optional[PolicyLike],
                 agent_id: Optional[str], paths: Sequence[str],
                 metadata: Optional[Dict[str, Any]], timeout: Optional[float],
                 raise_on_deny: bool, tool_name: str):
        self.mode = mode
        self.policy = policy
        self.agent_id = agent_id
        self.paths = tuple(paths)
        self.metadata = dict(metadata or {})
        self.timeout = timeout
        self.raise_on_deny = raise_on_deny
        self.tool_name = tool_name

    def as_dict(self) -> Dict[str, Any]:
        return {"mode": self.mode, "agent_id": self.agent_id,
                "paths": list(self.paths), "metadata": self.metadata,
                "timeout": self.timeout, "raise_on_deny": self.raise_on_deny,
                "tool_name": self.tool_name,
                "policy": type(self.policy).__name__ if self.policy else None}


def make_guard(runtime_getter: Callable[[], PenumbraRuntime]) -> Callable:
    """Build the ``guard`` decorator bound to a runtime accessor.

    The accessor is called lazily, at tool-invocation time, so decorating a
    module-level tool before ``penumbra.start()`` is fine.
    """

    def guard(target: Any = None, *,
              mode: str = MODE_SHELL,
              policy: Optional[PolicyLike] = None,
              agent_id: Optional[str] = None,
              paths: Sequence[str] = (),
              metadata: Optional[Dict[str, Any]] = None,
              timeout: Optional[float] = None,
              raise_on_deny: bool = True,
              name: str = "",
              return_result: bool = False) -> Any:
        """Put a tool under speculative execution and policy control.

        Args:
            mode: How the body runs.

                ``"shell"`` (the default) treats the return value as the shell
                command(s) to run in the guarded session. This is the only mode
                that works end-to-end on a real kernel stack, so the body must
                BUILD a command rather than perform the effect itself, and must
                quote every interpolated value with :func:`shlex.quote`.

                ``"fork"`` executes the body in a child process inside the
                monitored cgroup. It deadlocks against the process fence as
                soon as the body produces a governed effect: ShadowProc SIGSTOPs
                every process in the cgroup that it has not already admitted,
                and the child then waits for an authorization that waits for the
                policy, which waits for the body. Use it only for bodies that
                produce no governed effects.

                ``"inline"`` runs the body in this process, bracketed by the
                epoch but monitored only for what it does through
                :func:`penumbra.run`. This process is not in the managed
                cgroup, so touching the workspace directly fails with EIO.

                ``"auto"`` picks ``fork`` when privileges allow, and therefore
                inherits the deadlock above; it is no longer the default.
            policy: Per-tool policy generator; defaults to the runtime's.
            agent_id: Override the owning agent for this tool.
            paths: Paths the tool intends to touch. Passed to the policy as
                ``declared_paths``; the default policy denies anything outside
                the guarded workspace.
            metadata: Free-form data forwarded to the policy and journaled.
            timeout: Seconds allowed for the body.
            raise_on_deny: Raise :class:`PolicyViolation` when the policy denies
                (the default). ``False`` returns a :class:`GuardedResult`
                describing the rollback instead.
            name: Tool name reported to the policy (defaults to the function or
                LangChain tool name).
            return_result: Return the full :class:`GuardedResult` instead of the
                tool's own value.
        """

        def decorate(obj: Any) -> Any:
            spec = GuardSpec(mode=mode, policy=policy, agent_id=agent_id,
                             paths=paths, metadata=metadata, timeout=timeout,
                             raise_on_deny=raise_on_deny,
                             tool_name=name or _infer_name(obj))
            if _is_base_tool(obj):
                return _guard_base_tool(obj, spec, runtime_getter,
                                        return_result)
            return _guard_callable(obj, spec, runtime_getter, return_result)

        if target is None:
            return decorate
        return decorate(target)

    return guard


# ── plain callables ──────────────────────────────────────────────────────

def _guard_callable(fn: Callable, spec: GuardSpec,
                    runtime_getter: Callable[[], PenumbraRuntime],
                    return_result: bool) -> Callable:
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            def body(*inner_args, **inner_kwargs):
                # The epoch bracket is synchronous; run the coroutine to
                # completion inside it so its effects stay inside the epoch.
                return asyncio.run(fn(*inner_args, **inner_kwargs))

            body.__name__ = getattr(fn, "__name__", spec.tool_name)
            body.__doc__ = fn.__doc__
            return await asyncio.to_thread(
                _invoke, runtime_getter(), body, spec, args, kwargs,
                return_result)

        setattr(async_wrapper, GUARD_ATTR, spec)
        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return _invoke(runtime_getter(), fn, spec, args, kwargs, return_result)

    setattr(wrapper, GUARD_ATTR, spec)
    return wrapper


def _invoke(runtime: PenumbraRuntime, fn: Callable, spec: GuardSpec,
            args, kwargs, return_result: bool) -> Any:
    return runtime.guarded_call(
        fn, tool_name=spec.tool_name, args=tuple(args), kwargs=dict(kwargs),
        mode=spec.mode, policy=spec.policy, agent_id=spec.agent_id,
        declared_paths=spec.paths, metadata=spec.metadata,
        timeout=spec.timeout, raise_on_deny=spec.raise_on_deny,
        return_result=return_result)


# ── LangChain BaseTool instances ─────────────────────────────────────────

def _is_base_tool(obj: Any) -> bool:
    """True for a LangChain tool instance, without importing langchain eagerly."""
    try:
        from langchain_core.tools import BaseTool
    except Exception:  # noqa: BLE001 - langchain is an optional dependency
        return False
    return isinstance(obj, BaseTool)


def _infer_name(obj: Any) -> str:
    return getattr(obj, "name", None) or getattr(obj, "__name__", "tool")


def _guard_base_tool(tool: Any, spec: GuardSpec,
                     runtime_getter: Callable[[], PenumbraRuntime],
                     return_result: bool) -> Any:
    """Wrap a LangChain tool's underlying function(s) in the epoch bracket.

    The tool object itself is preserved (name, description, args schema, and
    everything the agent's prompt depends on); only execution is redirected.
    """
    guarded = tool.model_copy() if hasattr(tool, "model_copy") else tool.copy()
    description = getattr(tool, "description", "") or ""

    original_func = getattr(guarded, "func", None)
    original_coroutine = getattr(guarded, "coroutine", None)
    if original_func is None and original_coroutine is None:
        # A BaseTool subclass implementing _run directly.
        return _guard_run_methods(guarded, spec, runtime_getter, description)

    if original_func is not None:
        def guarded_func(*args, **kwargs):
            return _invoke_tool(runtime_getter(), original_func, spec,
                                args, kwargs, description, return_result)

        functools.update_wrapper(guarded_func, original_func)
        object.__setattr__(guarded, "func", guarded_func)

    if original_coroutine is not None:
        async def guarded_coroutine(*args, **kwargs):
            def body(*inner_args, **inner_kwargs):
                return asyncio.run(original_coroutine(*inner_args,
                                                      **inner_kwargs))

            body.__name__ = spec.tool_name
            return await asyncio.to_thread(
                _invoke_tool, runtime_getter(), body, spec, args, kwargs,
                description, return_result)

        object.__setattr__(guarded, "coroutine", guarded_coroutine)

    setattr(guarded, GUARD_ATTR, spec)
    return guarded


def _guard_run_methods(tool: Any, spec: GuardSpec,
                       runtime_getter: Callable[[], PenumbraRuntime],
                       description: str) -> Any:
    """Guard a BaseTool subclass that implements ``_run`` itself."""
    original_run = tool._run

    def guarded_run(*args, **kwargs):
        # run_manager is a LangChain callback handle, not tool input: keep it
        # out of the policy request but still pass it through.
        return _invoke_tool(runtime_getter(), original_run, spec, args, kwargs,
                            description, False)

    object.__setattr__(tool, "_run", guarded_run)
    setattr(tool, GUARD_ATTR, spec)
    return tool


def _invoke_tool(runtime: PenumbraRuntime, fn: Callable, spec: GuardSpec,
                 args, kwargs, description: str, return_result: bool) -> Any:
    scrubbed = {k: v for k, v in kwargs.items() if k != "run_manager"}
    return runtime.guarded_call(
        fn, tool_name=spec.tool_name, tool_description=description,
        args=tuple(args), kwargs=dict(kwargs), mode=spec.mode,
        policy=spec.policy, agent_id=spec.agent_id,
        declared_paths=spec.paths,
        metadata={**spec.metadata, "tool_input": _summarize(scrubbed)},
        timeout=spec.timeout, raise_on_deny=spec.raise_on_deny,
        return_result=return_result)


def _summarize(kwargs: Dict[str, Any], limit: int = 400) -> str:
    text = ", ".join(f"{k}={v!r}" for k, v in sorted(kwargs.items()))
    return text[:limit]


def is_guarded(obj: Any) -> bool:
    """True when ``obj`` has already been wrapped by :func:`guard`."""
    return getattr(obj, GUARD_ATTR, None) is not None


def guard_spec(obj: Any) -> Optional[GuardSpec]:
    return getattr(obj, GUARD_ATTR, None)


__all__ = ["make_guard", "GuardSpec", "GuardedResult", "is_guarded",
           "guard_spec", "GUARD_ATTR"]
