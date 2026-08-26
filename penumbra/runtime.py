#!/usr/bin/env python3
"""The runtime that turns a tool call into a speculative epoch.

One guarded tool call maps onto one epoch:

    session_begin_epoch → run the tool body → policy → session_resolve_epoch

``allow`` promotes the epoch's filesystem changes and installs the typed policy;
``deny`` rolls process and filesystem state back losslessly. Nothing about the
tool body needs to know this happened.
"""

from __future__ import annotations

import json
import logging
import os
import pickle
import select
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from .client import OrchestratorClient, OrchestratorError, PenumbraError
from .config import PenumbraConfig
from .policy import (ALLOW, DENY, ObservedCommand, PolicyDecision,
                     PolicyGenerationError, PolicyGenerator, PolicyLike,
                     PolicyRequest, PolicyViolation, WorkspacePolicy,
                     coerce_policy)
from .supervisor import Supervisor

#: Progress/diagnostic log. Silent by default (library convention). Turn it on
#: with PENUMBRA_LOG=info|debug, or configure the "penumbra" logger yourself.
#: Useful because an epoch can look hung while it is really just waiting on a
#: slow policy model or on a fenced command inside the session.
logger = logging.getLogger("penumbra")


def _configure_logging_from_env() -> None:
    level = os.environ.get("PENUMBRA_LOG", "").strip().upper()
    if not level or logger.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[penumbra %(relativeCreated)7.0fms] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level, logging.INFO))


_configure_logging_from_env()

#: Execution modes for a guarded tool body.
#:
#: WARNING about MODE_FORK: placing a freshly forked child into the managed
#: cgroup deadlocks against the process fence on a real kernel stack. Once
#: ShadowProc fences an unauthorized effect it SIGSTOPs every process in that
#: cgroup that is not already in its tracked set, which is exactly what such a
#: child is. It then waits for a SIGCONT that cannot come: it waits for
#: authorization, authorization waits for the policy, and the policy waits for
#: the tool body to finish. Prefer MODE_SHELL, whose command runs in the live
#: shell the orchestrator already admitted and resumed.
MODE_FORK = "fork"      # run in a child process inside the session's cgroup
MODE_SHELL = "shell"     # the body returns shell command(s) run in the session
MODE_INLINE = "inline"   # run in this process, bracketed by the epoch
MODE_AUTO = "auto"       # fork when possible, else inline (strict=False only);
                         # NOT the default -- it inherits MODE_FORK's deadlock
MODES = (MODE_FORK, MODE_SHELL, MODE_INLINE, MODE_AUTO)


class GuardError(PenumbraError):
    """A guarded call could not be executed under monitoring."""


class ToolExecutionError(PenumbraError):
    """The tool body itself failed inside a guarded epoch."""


@dataclass
class GuardedResult:
    """What a guarded call produced, and what happened to its effects."""

    value: Any = None
    tool_name: str = ""
    decision: str = ALLOW
    committed: bool = False
    reason: str = ""
    session_id: str = ""
    epoch_id: str = ""
    cgroup_id: str = ""
    mode: str = MODE_FORK
    commands: List[ObservedCommand] = field(default_factory=list)
    output: str = ""
    duration_s: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name, "decision": self.decision,
            "committed": self.committed, "reason": self.reason,
            "session_id": self.session_id, "epoch_id": self.epoch_id,
            "cgroup_id": self.cgroup_id, "mode": self.mode,
            "commands": [c.as_dict() for c in self.commands],
            "duration_s": round(self.duration_s, 4),
        }


def _child_wait_state(pid: int) -> str:
    """Describe where a stuck guarded child is blocked, for the timeout message.

    ``/proc/<pid>/wchan`` names the kernel function the task sleeps in, which
    distinguishes the cases that actually matter here: blocked on the FUSE
    workspace, fenced by the process layer, or deadlocked on a Python lock
    inherited from the forking thread.
    """
    parts = []
    for name, path in (("state", f"/proc/{pid}/stat"),
                       ("wchan", f"/proc/{pid}/wchan")):
        try:
            with open(path) as handle:
                raw = handle.read().strip()
        except OSError:
            continue
        if name == "state":
            # "pid (comm) S ..." -- comm may contain spaces/parens, so take the
            # field after the last ')'.
            tail = raw.rsplit(")", 1)[-1].split()
            if tail:
                parts.append(f"state={tail[0]}")
        elif raw:
            parts.append(f"wchan={raw}")
    return ", ".join(parts) or f"pid {pid}: no /proc info"


def _is_commit_pending(exc: OrchestratorError) -> bool:
    """True if a failed commit is really "not yet", with the epoch left intact.

    The orchestrator answers ``decision="authorized_pending"`` when the policy
    was accepted but the file layer has not finalized (the dependency group is
    still settling). It keeps the epoch fenced and intact and expects a retry.
    """
    response = getattr(exc, "response", None) or {}
    if response.get("decision") == "authorized_pending":
        return True
    return "kept intact for retry" in str(response.get("message", ""))


@dataclass
class _Session:
    session_id: str
    cgroup_id: str
    agent_id: str


@dataclass
class _EpochContext:
    """The epoch currently open on this thread."""

    session: _Session
    epoch_id: str
    tool_name: str
    mode: str
    commands: List[ObservedCommand] = field(default_factory=list)


class PenumbraRuntime:
    """Owns the daemons, the sessions, and the epoch bracket.

    Usually there is exactly one, created by :func:`penumbra.start`.
    """

    def __init__(self, config: Optional[PenumbraConfig] = None,
                 policy: Optional[PolicyLike] = None):
        self.config = config or PenumbraConfig()
        self.policy: PolicyGenerator = coerce_policy(policy) or WorkspacePolicy()
        self.supervisor = Supervisor(self.config)
        self.client = OrchestratorClient(self.config.orch_sock,
                                         timeout=self.config.request_timeout)
        self._sessions: Dict[Tuple[str, int], _Session] = {}
        self._sessions_lock = threading.Lock()
        self._local = threading.local()
        self._start_lock = threading.Lock()

    # ── lifecycle ────────────────────────────────────────────────────────

    @property
    def started(self) -> bool:
        return self.supervisor.running

    def start(self) -> "PenumbraRuntime":
        """Boot the stack (or attach to a running one). Idempotent."""
        with self._start_lock:
            if not self.supervisor.running:
                self.supervisor.start()
                self.client = OrchestratorClient(
                    self.config.orch_sock, timeout=self.config.request_timeout)
        return self

    def stop(self) -> None:
        """Close our sessions, then stop any daemon we started."""
        with self._sessions_lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            try:
                self.client.session_close(session.session_id)
            except PenumbraError:
                pass
        self.supervisor.stop()

    def status(self) -> Dict[str, Any]:
        info = self.supervisor.status()
        info["policy"] = type(self.policy).__name__
        with self._sessions_lock:
            info["sessions"] = [s.session_id for s in self._sessions.values()]
        return info

    def set_policy(self, policy: PolicyLike) -> None:
        self.policy = coerce_policy(policy) or WorkspacePolicy()

    def _require_started(self) -> None:
        if not self.supervisor.running:
            # Attaching is cheap and makes "forgot to call start()" work when a
            # stack is already up; a genuinely missing stack still fails here.
            self.start()

    # ── sessions ─────────────────────────────────────────────────────────

    def session_for(self, agent_id: Optional[str] = None) -> _Session:
        """A long-lived session for this (agent, thread) pair, created on demand.

        Keyed by thread as well as agent so two threads never interleave
        commands on one shell. Calls of the SAME agent stay serialized by the
        orchestrator's per-agent barrier, which is the intended semantics: one
        agent is one causal chain.
        """
        self._require_started()
        aid = agent_id or self.config.agent_id
        key = (aid, threading.get_ident())
        with self._sessions_lock:
            session = self._sessions.get(key)
            if session is not None:
                return session
        name = f"{self.config.cgroup_prefix}-{uuid.uuid4().hex[:8]}"
        resp = self.client.session_open(agent_id=aid, cgroup_name=name)
        session = _Session(session_id=resp["session_id"],
                           cgroup_id=resp.get("cgroup_id", ""), agent_id=aid)
        with self._sessions_lock:
            self._sessions[key] = session
        return session

    def close_session(self, agent_id: Optional[str] = None) -> None:
        aid = agent_id or self.config.agent_id
        key = (aid, threading.get_ident())
        with self._sessions_lock:
            session = self._sessions.pop(key, None)
        if session is not None:
            try:
                self.client.session_close(session.session_id)
            except PenumbraError:
                pass

    # ── the current epoch (thread-local) ─────────────────────────────────

    @property
    def _epoch_stack(self) -> List[_EpochContext]:
        stack = getattr(self._local, "epochs", None)
        if stack is None:
            stack = []
            self._local.epochs = stack
        return stack

    @property
    def current_epoch(self) -> Optional[_EpochContext]:
        stack = self._epoch_stack
        return stack[-1] if stack else None

    def run(self, command: str, timeout: Optional[float] = None,
            check: bool = True) -> str:
        """Run a shell command inside the guarded session, speculatively.

        Only valid while an epoch is open (i.e. inside a guarded tool). The
        command runs in the monitored cgroup, so its effects are part of the
        epoch and are committed or rolled back with it.
        """
        epoch = self.current_epoch
        if epoch is None:
            raise GuardError(
                "penumbra.run() is only valid inside a guarded tool call. "
                "Decorate the tool with @penumbra.guard() first.")
        logger.info("session_run: %s", command)
        run_started = time.time()
        resp = self.client.session_run(
            epoch.session.session_id, command,
            timeout=timeout if timeout is not None else self.config.command_timeout)
        output = resp.get("output", "")
        exit_code = int(resp.get("exit_code", 0))
        logger.info("session_run done: exit=%d (%.1fs) %d bytes out",
                    exit_code, time.time() - run_started, len(output))
        epoch.commands.append(ObservedCommand(command=command,
                                              exit_code=exit_code,
                                              output=output))
        if check and exit_code != 0:
            raise ToolExecutionError(
                f"command exited {exit_code}: {command!r}\n{output}")
        return output

    def workspace_path(self, relative: str = "") -> str:
        """A path inside the guarded workspace mount."""
        return self.config.workspace_path(relative) if relative \
            else self.config.workspace

    # ── the epoch bracket ────────────────────────────────────────────────

    def guarded_call(self, fn: Callable[..., Any], *,
                     tool_name: str = "",
                     tool_description: str = "",
                     args: Tuple[Any, ...] = (),
                     kwargs: Optional[Dict[str, Any]] = None,
                     mode: str = MODE_SHELL,
                     policy: Optional[PolicyLike] = None,
                     agent_id: Optional[str] = None,
                     declared_paths: Sequence[str] = (),
                     metadata: Optional[Dict[str, Any]] = None,
                     timeout: Optional[float] = None,
                     raise_on_deny: bool = True,
                     return_result: bool = False) -> Any:
        """Execute ``fn`` as one speculative epoch and resolve it by policy."""
        kwargs = dict(kwargs or {})
        tool_name = tool_name or getattr(fn, "__name__", "tool")
        generator = coerce_policy(policy) or self.policy

        # A guarded tool that calls another guarded tool joins the open epoch:
        # opening a second one would block on this agent's own barrier.
        if self.current_epoch is not None:
            return self._run_nested(fn, tool_name, args, kwargs, mode,
                                    return_result)

        self._require_started()
        session = self.session_for(agent_id)
        resolved_mode = self._resolve_mode(mode)
        started = time.time()

        logger.info("epoch begin: tool=%s agent=%s mode=%s",
                    tool_name, session.agent_id, resolved_mode)
        begin = self.client.session_begin_epoch(session.session_id,
                                                session.agent_id)
        epoch = _EpochContext(session=session, epoch_id=begin.get("epoch_id", ""),
                              tool_name=tool_name, mode=resolved_mode)
        self._epoch_stack.append(epoch)

        value: Any = None
        failed = False
        error = ""
        try:
            try:
                logger.info("executing tool body (%s)", resolved_mode)
                value = self._execute(fn, args, kwargs, resolved_mode, epoch,
                                      timeout)
                logger.info("tool body finished")
            except ToolExecutionError as exc:
                failed, error = True, str(exc)
                logger.debug("tool body failed: %s", error)
            except Exception as exc:  # noqa: BLE001 - the policy decides
                failed, error = True, f"{type(exc).__name__}: {exc}"
                logger.debug("tool body raised: %s", error)

            request = PolicyRequest(
                tool_name=tool_name,
                tool_description=tool_description or (fn.__doc__ or "").strip(),
                agent_id=session.agent_id,
                session_id=session.session_id,
                epoch_id=epoch.epoch_id,
                cgroup_id=session.cgroup_id,
                args=tuple(_jsonable(list(args))),
                kwargs=_jsonable(kwargs),
                mode=resolved_mode,
                workspace=self.config.workspace,
                declared_paths=tuple(declared_paths),
                commands=tuple(epoch.commands),
                violations=tuple(self.client.drain_violations(session.cgroup_id)),
                failed=failed,
                error=error,
                metadata=dict(metadata or {}),
            )
            try:
                logger.info("generating policy for %s via %s…", tool_name,
                            type(generator).__name__)
                policy_started = time.time()
                decision = generator.decide(request)
                logger.info("policy decided: %s (%.1fs) — %s", decision.decision,
                            time.time() - policy_started, decision.reason)
            except Exception as exc:  # noqa: BLE001
                # Policy GENERATION failed (e.g. an LLM policy returned
                # garbage, or a rule set does not compile). Fail closed: roll
                # the epoch back so its effects never leak, then surface it.
                logger.warning("policy generation failed, rolling back: %s", exc)
                self._safe_rollback(session)
                if isinstance(exc, PenumbraError):
                    raise
                raise PolicyGenerationError(
                    f"policy generation for tool {tool_name!r} failed; the "
                    f"epoch was rolled back: {exc}") from exc
            result = self._resolve(session, epoch, decision, request, value,
                                   started)
            logger.info("epoch resolved: tool=%s committed=%s", tool_name,
                        result.committed)
        finally:
            self._epoch_stack.pop()

        if not result.committed and raise_on_deny:
            if failed:
                raise ToolExecutionError(
                    f"tool {tool_name!r} failed and its effects were rolled "
                    f"back: {error}")
            raise PolicyViolation(tool_name, result.reason, request)
        if return_result:
            return result
        return result.value

    def _run_nested(self, fn, tool_name, args, kwargs, mode,
                    return_result) -> Any:
        """Run a guarded body inside an already-open epoch (no new resolution)."""
        epoch = self.current_epoch
        resolved_mode = self._resolve_mode(mode)
        value = self._execute(fn, args, kwargs, resolved_mode, epoch, None)
        if return_result:
            return GuardedResult(value=value, tool_name=tool_name,
                                 decision=ALLOW, committed=False,
                                 reason="nested call: resolved by the outer tool",
                                 session_id=epoch.session.session_id,
                                 epoch_id=epoch.epoch_id,
                                 cgroup_id=epoch.session.cgroup_id,
                                 mode=resolved_mode,
                                 commands=list(epoch.commands))
        return value

    def _resolve(self, session: _Session, epoch: _EpochContext,
                 decision: PolicyDecision, request: PolicyRequest,
                 value: Any, started: float) -> GuardedResult:
        """Apply the policy's decision to the epoch."""
        result = GuardedResult(
            value=value, tool_name=request.tool_name, decision=decision.decision,
            reason=decision.reason, session_id=session.session_id,
            epoch_id=epoch.epoch_id, cgroup_id=session.cgroup_id,
            mode=epoch.mode, commands=list(epoch.commands))
        if decision.decision == DENY:
            self.client.session_resolve_epoch(
                session.session_id, session.agent_id, DENY,
                policy_metadata=decision.policy_metadata(request))
            result.committed = False
            result.value = None
            result.duration_s = time.time() - started
            return result
        try:
            resp = self._resolve_allow_with_retry(session, decision, request)
        except OrchestratorError as exc:
            # Fail closed: an epoch that could not be committed must not be
            # left open. Roll it back, then surface the original failure.
            self._safe_rollback(session)
            if _is_commit_pending(exc):
                detail = (getattr(exc, "response", None) or {}).get(
                    "finalize_err", "")
                hint = f" [ShadowFS finalize_err: {detail}]" if detail else ""
                raise PenumbraError(
                    f"commit of tool {request.tool_name!r} was authorized but "
                    f"the file layer never finalized{hint}; the epoch was "
                    f"rolled back. The orchestrator polls ShadowFS for up to "
                    f"30s per attempt, so this means finalization is stuck, "
                    f"not merely slow — check "
                    f"{os.path.join(self.config.log_dir, 'shadowfs.log')} for "
                    f"'BeginFinalize' / 'tryPromoteAll'. Original: {exc}") from exc
            raise PenumbraError(
                f"commit of tool {request.tool_name!r} failed and the epoch was "
                f"rolled back: {exc}") from exc
        result.committed = True
        result.output = resp.get("stdout", "") or ""
        result.duration_s = time.time() - started
        return result

    def _resolve_allow_with_retry(self, session: _Session,
                                  decision: PolicyDecision,
                                  request: PolicyRequest) -> Dict[str, Any]:
        """Commit an allowed epoch, retrying while the file layer finalizes.

        A commit can answer ``authorized_pending``: the policy was accepted and
        the epoch is kept fenced and INTACT, but the file layer has not
        finalized yet because the dependency group is still settling. The
        orchestrator parks it for its background retry loop and expects the
        client to retry the resolve — rolling back here would throw away a
        commit that is about to succeed.
        """
        allowed_ops = decision.allowed_ops()
        policy_metadata = decision.policy_metadata(request)
        deadline = time.time() + self.config.commit_retry_timeout
        delay = 0.2
        attempt = 0
        while True:
            attempt += 1
            try:
                return self.client.session_resolve_epoch(
                    session.session_id, session.agent_id, ALLOW,
                    allowed_ops=allowed_ops, policy_metadata=policy_metadata)
            except OrchestratorError as exc:
                if not _is_commit_pending(exc):
                    raise
                remaining = deadline - time.time()
                if remaining <= 0:
                    # Note: the orchestrator itself polls ShadowFS for up to
                    # 30s inside EACH resolve call, so one attempt usually
                    # consumes the whole budget. Retrying only helps when the
                    # orchestrator's background loop settles the group between
                    # calls; a genuinely stuck finalize will not recover.
                    logger.warning(
                        "commit still pending after %d attempt(s) spanning "
                        "%.0fs; giving up", attempt,
                        self.config.commit_retry_timeout)
                    raise
                logger.info("commit pending (file layer finalizing), retry "
                            "%d in %.1fs…", attempt + 1, delay)
                time.sleep(min(delay, remaining))
                delay = min(delay * 2, 2.0)

    def _safe_rollback(self, session: _Session) -> None:
        try:
            self.client.session_rollback_epoch(session.session_id,
                                               session.agent_id)
        except PenumbraError:
            pass

    # ── execution modes ──────────────────────────────────────────────────

    def _resolve_mode(self, mode: str) -> str:
        mode = (mode or MODE_SHELL).strip().lower()
        if mode not in MODES:
            raise GuardError(f"unknown guard mode {mode!r}; expected one of "
                             f"{', '.join(MODES)}")
        if mode != MODE_AUTO:
            if mode == MODE_FORK and not self._can_fork():
                raise GuardError(
                    "mode='fork' needs root and a writable cgroup root so the "
                    "tool body can join the monitored cgroup. Use mode='shell' "
                    "or mode='inline', or run as root.")
            return mode
        if self._can_fork():
            return MODE_FORK
        if self.config.strict:
            raise GuardError(
                "cannot run the tool body under process-layer monitoring "
                "(fork mode needs root). Refusing to run it unmonitored "
                "because config.strict is set; pass mode='shell'/'inline' "
                "explicitly to acknowledge the weaker guarantee.")
        return MODE_INLINE

    def _can_fork(self) -> bool:
        return os.geteuid() == 0 and hasattr(os, "fork") and \
            os.access(self.config.cgroup_root, os.W_OK)

    def _execute(self, fn: Callable[..., Any], args: Tuple[Any, ...],
                 kwargs: Dict[str, Any], mode: str, epoch: _EpochContext,
                 timeout: Optional[float]) -> Any:
        if mode == MODE_INLINE:
            return fn(*args, **kwargs)
        if mode == MODE_SHELL:
            return self._execute_shell(fn, args, kwargs, timeout)
        return self._execute_fork(fn, args, kwargs, epoch, timeout)

    def _execute_shell(self, fn, args, kwargs, timeout) -> str:
        """The body returns the command(s) to run inside the guarded session."""
        produced = fn(*args, **kwargs)
        if produced is None:
            return ""
        commands = [produced] if isinstance(produced, str) else list(produced)
        outputs = []
        for command in commands:
            if not isinstance(command, str):
                raise GuardError(
                    f"mode='shell' expects the tool to return a command string "
                    f"or a list of them; got {type(command).__name__}")
            outputs.append(self.run(command, timeout=timeout))
        return "\n".join(o.rstrip("\n") for o in outputs if o)

    def _execute_fork(self, fn, args, kwargs, epoch: _EpochContext,
                      timeout: Optional[float]) -> Any:
        """Run the body in a child process joined to the session's cgroup.

        The child's file writes are attributed to the session cgroup, so the
        epoch's commit/rollback covers them, and its external effects hit the
        same eBPF fence as the session shell.

        The child is forked from a possibly multi-threaded interpreter: it only
        does cgroup placement, the tool body, and one pipe write. A body that
        waits on a lock held by another thread at fork time would hang, so the
        timeout is enforced by the parent.
        """
        cgroup_procs = os.path.join(
            self.config.cgroup_path(epoch.session.cgroup_id), "cgroup.procs")
        if not os.path.exists(cgroup_procs):
            raise GuardError(
                f"session cgroup {cgroup_procs} does not exist; cannot place "
                f"the tool body under monitoring")
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:  # ── child ──
            code = 1
            try:
                os.close(read_fd)
                with open(cgroup_procs, "w") as handle:
                    handle.write(str(os.getpid()))
                if os.path.isdir(self.config.workspace):
                    os.chdir(self.config.workspace)
                payload = pickle.dumps(("ok", fn(*args, **kwargs)))
                code = 0
            except BaseException as exc:  # noqa: BLE001
                try:
                    payload = pickle.dumps(
                        ("err", f"{type(exc).__name__}: {exc}"))
                except BaseException:  # noqa: BLE001
                    payload = pickle.dumps(("err", "tool body failed"))
            try:
                os.write(write_fd, payload)
                os.close(write_fd)
            except OSError:
                pass
            os._exit(code)

        # ── parent ──
        os.close(write_fd)
        budget = timeout if timeout is not None else self.config.tool_timeout
        deadline = time.time() + budget
        chunks = []
        timed_out = False
        stuck = ""
        try:
            # select() rather than a plain blocking read: the child is forked
            # from a multi-threaded interpreter (LangGraph runs tools on a
            # thread pool), so its body can deadlock on a lock that was held at
            # fork time. A blocking read would then hang the parent forever and
            # the deadline below would never be reached.
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    timed_out = True
                    break
                ready, _, _ = select.select([read_fd], [], [],
                                            min(remaining, 0.5))
                if not ready:
                    continue
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            if timed_out:
                stuck = _child_wait_state(pid)
            os.close(read_fd)
            status = self._reap(pid, deadline)
        if timed_out:
            raise ToolExecutionError(
                f"guarded tool body did not finish within {budget:.0f}s and "
                f"was killed ({stuck})")
        payload = b"".join(chunks)
        if not payload:
            raise ToolExecutionError(
                f"guarded tool body produced no result (child exit status "
                f"{status}); it may have been fenced or killed")
        kind, data = pickle.loads(payload)
        if kind == "err":
            raise ToolExecutionError(str(data))
        return data

    def _reap(self, pid: int, deadline: float) -> int:
        """Wait for the child, killing it if it outlives the deadline."""
        while True:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                return status
            if time.time() > deadline:
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
                _, status = os.waitpid(pid, 0)
                return status
            time.sleep(0.005)

    # ── manual epoch control ─────────────────────────────────────────────

    @contextmanager
    def epoch(self, tool_name: str = "manual",
              agent_id: Optional[str] = None,
              policy: Optional[PolicyLike] = None,
              metadata: Optional[Dict[str, Any]] = None
              ) -> Iterator[_EpochContext]:
        """Open an epoch by hand, for code that is not shaped like a tool.

        ::

            with runtime.epoch("migration") as ep:
                runtime.run("./migrate.sh")
            # policy ran at exit; effects are committed or rolled back
        """
        self._require_started()
        session = self.session_for(agent_id)
        begin = self.client.session_begin_epoch(session.session_id,
                                                session.agent_id)
        ctx = _EpochContext(session=session, epoch_id=begin.get("epoch_id", ""),
                            tool_name=tool_name, mode=MODE_SHELL)
        self._epoch_stack.append(ctx)
        started = time.time()
        failed, error = False, ""
        try:
            yield ctx
        except Exception as exc:  # noqa: BLE001
            failed, error = True, f"{type(exc).__name__}: {exc}"
            raise
        finally:
            generator = coerce_policy(policy) or self.policy
            request = PolicyRequest(
                tool_name=tool_name, agent_id=session.agent_id,
                session_id=session.session_id, epoch_id=ctx.epoch_id,
                cgroup_id=session.cgroup_id, mode=MODE_SHELL,
                workspace=self.config.workspace,
                commands=tuple(ctx.commands),
                violations=tuple(self.client.drain_violations(session.cgroup_id)),
                failed=failed, error=error, metadata=dict(metadata or {}))
            try:
                decision = generator.decide(request)
                self._resolve(session, ctx, decision, request, None, started)
            finally:
                self._epoch_stack.pop()


def _jsonable(value: Any) -> Any:
    """Best-effort JSON normalization so a PolicyRequest stays serializable."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        if isinstance(value, dict):
            return {str(k): _jsonable(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_jsonable(v) for v in value]
        return repr(value)
