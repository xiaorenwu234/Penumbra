#!/usr/bin/env python3
"""Policy generation: the one piece users are expected to write themselves.

A guarded tool call is a speculative epoch. Before its effects become visible,
Penumbra asks a :class:`PolicyGenerator` one question with a fixed shape:

    PolicyRequest  →  generate()  →  PolicyDecision

``PolicyRequest`` is what was observed (tool identity, arguments, commands run,
fenced effects). ``PolicyDecision`` is ``allow`` plus the typed effect rules to
install, or ``deny`` to roll the epoch back losslessly. Subclass
:class:`PolicyGenerator`, override :meth:`generate`, done — the rest of the
integration never changes.

Rules are compiled with the project's own ``policy.policy_ir.PolicyIR``, so a
malformed rule set is rejected here rather than at the daemon boundary.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .client import PenumbraError

# The compiler lives in the repository root, not in this package.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from policy.policy_ir import CLASS_IDS, LEGACY_MAP, PolicyIR  # noqa: E402

ALLOW = "allow"
DENY = "deny"

#: Filesystem operations, as named by the shared effect schema.
FILESYSTEM_OPS: Tuple[str, ...] = (
    "OPEN", "WRITE", "CREATE", "DELETE", "RENAME", "LINK", "SYMLINK",
    "TRUNCATE", "CHMOD", "CHOWN", "MKDIR", "RMDIR",
)

#: Effects a shell session needs in order to hand its transcript back. Without
#: these an otherwise-legitimate epoch is fenced at its first write to the
#: session pipe and never releases its output.
SHELL_PLUMBING_OPS: Tuple[str, ...] = ("WRITE_OUT", "PIPE_WRITE", "UNIX_WRITE")


class PolicyViolation(PenumbraError):
    """The policy denied the tool call; its effects were rolled back."""

    def __init__(self, tool_name: str, reason: str,
                 request: Optional["PolicyRequest"] = None):
        self.tool_name = tool_name
        self.reason = reason
        self.request = request
        super().__init__(f"policy denied tool {tool_name!r}: {reason}")


class PolicyGenerationError(PenumbraError):
    """The generator returned something unusable, or its rules do not compile."""


# ── the fixed input shape ────────────────────────────────────────────────

@dataclass(frozen=True)
class ObservedCommand:
    """One command the tool call ran inside the guarded session."""

    command: str
    exit_code: int = 0
    output: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"command": self.command, "exit_code": self.exit_code,
                "output": self.output}


@dataclass(frozen=True)
class PolicyRequest:
    """Everything a policy may base its decision on. Deterministic and JSON-able.

    Attributes:
        tool_name: The guarded tool's name (LangChain tool name when wrapped).
        tool_description: The tool's docstring/description, if any.
        agent_id: Owning agent; the orchestrator serializes one agent's calls.
        session_id / epoch_id / cgroup_id: Handles for this speculative epoch.
        args / kwargs: The tool call's arguments, JSON-normalized.
        mode: How the body was executed — "fork", "shell" or "inline".
        workspace: The guarded ShadowFS mount tools must write through.
        declared_paths: Paths the ``@guard(paths=...)`` annotation declared.
        commands: Commands observed inside the epoch (shell mode).
        violations: Process-layer effects that were fenced during the epoch.
        failed: True when the tool body raised (``error`` holds the message).
        metadata: Free-form annotation metadata from ``@guard(metadata=...)``.
    """

    tool_name: str
    tool_description: str = ""
    agent_id: str = ""
    session_id: str = ""
    epoch_id: str = ""
    cgroup_id: str = ""
    args: Tuple[Any, ...] = ()
    kwargs: Mapping[str, Any] = field(default_factory=dict)
    mode: str = "fork"
    workspace: str = ""
    declared_paths: Tuple[str, ...] = ()
    commands: Tuple[ObservedCommand, ...] = ()
    violations: Tuple[Mapping[str, Any], ...] = ()
    failed: bool = False
    error: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["args"] = list(self.args)
        data["declared_paths"] = list(self.declared_paths)
        data["commands"] = [c.as_dict() for c in self.commands]
        data["violations"] = [dict(v) for v in self.violations]
        return data

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.as_dict(), indent=indent, ensure_ascii=False,
                          default=str)

    # Convenience predicates policies tend to want.

    def paths_outside_workspace(self) -> List[str]:
        """Declared paths that are not inside the guarded workspace."""
        if not self.workspace:
            return list(self.declared_paths)
        root = os.path.abspath(self.workspace)
        outside = []
        for path in self.declared_paths:
            resolved = os.path.abspath(os.path.join(root, path)) \
                if not os.path.isabs(path) else os.path.abspath(path)
            if resolved != root and not resolved.startswith(root + os.sep):
                outside.append(path)
        return outside


# ── the fixed output shape ───────────────────────────────────────────────

@dataclass(frozen=True)
class EffectRule:
    """One typed effect rule: what operation, on what resource, allowed or not.

    ``event_type`` is a schema event name ("WRITE", "CONNECT", ...) or ``"*"``
    for any. ``path_pattern`` is an absolute path prefix (filesystem rules).
    ``endpoint`` carries fine-grained NETWORK/IPC/SIGNAL constraints.
    """

    event_type: str = "*"
    action: str = ALLOW
    path_pattern: str = ""
    endpoint: Optional[Mapping[str, Any]] = None

    def as_allowed_op(self) -> Dict[str, Any]:
        op: Dict[str, Any] = {
            "event_type": self.event_type,
            "action": self.action,
            "path_pattern": self.path_pattern,
        }
        if self.endpoint is not None:
            op["endpoint"] = dict(self.endpoint)
        return op


def allow(event_type: str = "*", path: str = "",
          endpoint: Optional[Mapping[str, Any]] = None) -> EffectRule:
    """An allow rule (shorthand)."""
    return EffectRule(event_type=event_type, action=ALLOW,
                      path_pattern=path, endpoint=endpoint)


def deny(event_type: str = "*", path: str = "",
         endpoint: Optional[Mapping[str, Any]] = None) -> EffectRule:
    """A deny rule (shorthand).

    Note the asymmetry the underlying model imposes: absence of an allow rule
    already denies. An explicit deny matters for endpoint-scoped exceptions and
    for documenting intent in the audit projection.
    """
    return EffectRule(event_type=event_type, action=DENY,
                      path_pattern=path, endpoint=endpoint)


def filesystem_rules(path: str,
                     operations: Sequence[str] = FILESYSTEM_OPS
                     ) -> List[EffectRule]:
    """Allow the given filesystem operations under one absolute path prefix."""
    return [allow(op, path) for op in operations]


def shell_plumbing_rules() -> List[EffectRule]:
    """Allow the session's own transcript plumbing (see SHELL_PLUMBING_OPS)."""
    return [allow(op) for op in SHELL_PLUMBING_OPS]


@dataclass
class PolicyDecision:
    """A policy's answer: commit under ``rules``, or roll back.

    ``rules`` is compiled into the typed PolicyIR that is BOTH audited against
    what the epoch did and installed as the prospective enforcement policy, so
    an empty allow set means "commit nothing but the plumbing" — usually a bug
    in the policy rather than a safe default.
    """

    decision: str = ALLOW
    rules: List[EffectRule] = field(default_factory=list)
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow_(cls, rules: Sequence[EffectRule], reason: str = "",
               metadata: Optional[Dict[str, Any]] = None) -> "PolicyDecision":
        return cls(decision=ALLOW, rules=list(rules), reason=reason,
                   metadata=dict(metadata or {}))

    # ``allow``/``deny`` read better at call sites; keep both spellings.
    allow = allow_

    @classmethod
    def deny_(cls, reason: str,
              metadata: Optional[Dict[str, Any]] = None) -> "PolicyDecision":
        return cls(decision=DENY, rules=[], reason=reason,
                   metadata=dict(metadata or {}))

    deny = deny_

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def allowed_ops(self) -> List[Dict[str, Any]]:
        """The orchestrator wire form of ``rules``."""
        return [r.as_allowed_op() for r in self.rules]

    def policy_metadata(self, request: Optional[PolicyRequest] = None
                        ) -> Dict[str, Any]:
        """Metadata attached to the journal record for auditability."""
        meta = {"reason": self.reason}
        meta.update(self.metadata)
        if request is not None:
            meta.setdefault("tool", request.tool_name)
            meta.setdefault("agent_id", request.agent_id)
        return meta

    def validate(self, tool_name: str = "") -> "PolicyDecision":
        """Normalize and compile the decision; raise if it cannot be enforced."""
        decision = (self.decision or "").strip().lower()
        if decision not in (ALLOW, DENY):
            raise PolicyGenerationError(
                f"policy for {tool_name or 'tool'} returned decision "
                f"{self.decision!r}; expected {ALLOW!r} or {DENY!r}")
        self.decision = decision
        if decision == DENY:
            if not self.reason:
                self.reason = "denied by policy"
            return self
        rules = []
        for rule in self.rules:
            if isinstance(rule, EffectRule):
                rules.append(rule)
            elif isinstance(rule, Mapping):
                rules.append(EffectRule(
                    event_type=rule.get("event_type", "*"),
                    action=rule.get("action", ALLOW),
                    path_pattern=rule.get("path_pattern", rule.get("path", "")),
                    endpoint=rule.get("endpoint")))
            else:
                raise PolicyGenerationError(
                    f"policy for {tool_name or 'tool'} returned a rule of type "
                    f"{type(rule).__name__}; expected EffectRule or dict")
        self.rules = rules
        if not rules:
            raise PolicyGenerationError(
                f"policy for {tool_name or 'tool'} allowed the call but "
                f"produced no rules. An allow decision must carry the typed "
                f"policy that authorizes the epoch's effects.")
        # Compile exactly as the orchestrator will, so a bad rule set fails
        # here (before any state is touched) instead of at commit time.
        try:
            PolicyIR.from_allowed_ops(self.allowed_ops()).to_proc_policy()
        except ValueError as exc:
            raise PolicyGenerationError(
                f"policy for {tool_name or 'tool'} does not compile: {exc}") from exc
        return self


# ── the overridable generator ────────────────────────────────────────────

class PolicyGenerator:
    """Base class for policy generation. Override :meth:`generate`.

    Example::

        class MyPolicy(PolicyGenerator):
            def generate(self, request: PolicyRequest) -> PolicyDecision:
                if request.failed:
                    return PolicyDecision.deny("tool raised")
                return PolicyDecision.allow(
                    filesystem_rules(request.workspace)
                    + shell_plumbing_rules(),
                    reason="workspace writes only")

        penumbra.start(policy=MyPolicy())
    """

    #: Applies only to tools whose name is in this set (None = all tools).
    tools: Optional[Sequence[str]] = None

    def generate(self, request: PolicyRequest) -> PolicyDecision:
        raise NotImplementedError(
            "subclass PolicyGenerator and implement generate(request)")

    def decide(self, request: PolicyRequest) -> PolicyDecision:
        """Call :meth:`generate` and validate its answer. Do not override."""
        decision = self.generate(request)
        if not isinstance(decision, PolicyDecision):
            raise PolicyGenerationError(
                f"{type(self).__name__}.generate() returned "
                f"{type(decision).__name__}; expected PolicyDecision")
        return decision.validate(request.tool_name)

    # Callable so a generator instance can be passed anywhere a function is.
    def __call__(self, request: PolicyRequest) -> PolicyDecision:
        return self.decide(request)


class FunctionPolicyGenerator(PolicyGenerator):
    """Adapts a plain ``def policy(request) -> PolicyDecision`` function."""

    def __init__(self, fn: Callable[[PolicyRequest], PolicyDecision]):
        self._fn = fn
        self.__name__ = getattr(fn, "__name__", "policy")

    def generate(self, request: PolicyRequest) -> PolicyDecision:
        return self._fn(request)


class WorkspacePolicy(PolicyGenerator):
    """Default policy: filesystem effects inside the workspace, nothing else.

    Allows every filesystem operation under the guarded ShadowFS mount (plus
    any extra prefixes given), allows the session's transcript plumbing, and
    denies the call outright when the tool body raised or when the annotation
    declared a path outside the workspace. Network, signal, privilege and other
    system effects are simply never allowed — under this model, absence of an
    allow rule is a denial.
    """

    def __init__(self, extra_paths: Sequence[str] = (),
                 deny_on_error: bool = True,
                 operations: Sequence[str] = FILESYSTEM_OPS):
        self.extra_paths = tuple(extra_paths)
        self.deny_on_error = deny_on_error
        self.operations = tuple(operations)

    def generate(self, request: PolicyRequest) -> PolicyDecision:
        if self.deny_on_error and request.failed:
            return PolicyDecision.deny(
                f"tool body failed: {request.error or 'unknown error'}")
        outside = request.paths_outside_workspace()
        if outside:
            return PolicyDecision.deny(
                f"declared paths outside the guarded workspace: {outside}")
        rules: List[EffectRule] = []
        for path in (request.workspace, *self.extra_paths):
            if path:
                rules.extend(filesystem_rules(path, self.operations))
        rules.extend(shell_plumbing_rules())
        return PolicyDecision.allow(
            rules, reason="workspace-scoped filesystem effects",
            metadata={"policy": type(self).__name__})


class AllowAllPolicy(PolicyGenerator):
    """Commit whatever the epoch did. For local experiments only."""

    def generate(self, request: PolicyRequest) -> PolicyDecision:
        return PolicyDecision.allow(
            [allow("*", "/")], reason="allow-all (development policy)",
            metadata={"policy": type(self).__name__})


class DenyAllPolicy(PolicyGenerator):
    """Roll every guarded call back. Useful for dry runs and tests."""

    def generate(self, request: PolicyRequest) -> PolicyDecision:
        return PolicyDecision.deny("deny-all (dry-run policy)",
                                   metadata={"policy": type(self).__name__})


# ── LLM-backed policy generation ─────────────────────────────────────────

#: Event tokens the schema accepts in a rule's ``event_type`` (plus "*").
VALID_EVENT_TOKENS: Tuple[str, ...] = tuple(sorted(LEGACY_MAP.keys()))

_DEFAULT_LLM_SYSTEM_PROMPT = (
    "You are a SECURITY POLICY ENGINE for an AI agent's tool calls. Each tool "
    "call already ran speculatively inside a sandbox; its filesystem and "
    "process effects are held back until you decide. Decide whether to COMMIT "
    "the effects (allow) or ROLL THEM BACK (deny), and if you allow, produce "
    "the exact typed rules that authorize what the call did — nothing more.\n"
    "Principles: least privilege; deny anything touching resources outside the "
    "agent's workspace; deny if the tool failed or its behavior looks unrelated "
    "to its stated purpose. When unsure, DENY."
)

# The output contract is kept SEPARATE from the system prompt and is always
# appended by build_prompt(). A caller-supplied system_prompt carries business
# security rules only, so overriding it can never drop the format contract —
# which the json_mode structured-output path depends on, because that mode only
# sets response_format={"type":"json_object"} and never shows the model the
# schema.
_OUTPUT_CONTRACT = (
    "Answer with a SINGLE JSON object and NOTHING else, matching:\n"
    '{"decision":"allow"|"deny","reason":"<short>",'
    '"rules":[{"event_type":"<TOKEN>","action":"allow"|"deny",'
    '"path_pattern":"/absolute/prefix","endpoint":{...optional...}}]}\n'
    'The "decision" field must be EXACTLY the lowercase string "allow" or '
    '"deny". Synonyms ("safe", "ok", "unsafe") and other languages are '
    "rejected and treated as a denial.\n"
    "For a deny decision, \"rules\" may be empty. For an allow decision, \"rules\" "
    "must list every effect to authorize (absence of an allow == denial). "
    "path_pattern must be an absolute path prefix for FILESYSTEM rules. "
    "endpoint is only for NETWORK/IPC/SIGNAL rules."
)


def _extract_json_object(text: str) -> str:
    """Pull the first JSON object out of a model reply (handles ``` fences)."""
    if not isinstance(text, str):
        raise PolicyGenerationError(f"model reply was {type(text).__name__}, "
                                    f"expected text")
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise PolicyGenerationError("no JSON object found in model reply")
    return text[start:end + 1]


# Cached Pydantic schema for LangChain's ``with_structured_output``. Built
# lazily so importing this package never requires pydantic; it is only needed
# when an LLM policy actually uses structured output.
_POLICY_DECISION_SCHEMA = None


def _policy_decision_schema():
    """Return (and cache) the Pydantic model describing a PolicyDecision.

    Mirrors the fixed output shape exactly, so a model bound with
    ``with_structured_output(schema)`` is FORCED (via function-calling / JSON
    mode) to emit a conforming object instead of free-form text that a prompt
    merely asks for.
    """
    global _POLICY_DECISION_SCHEMA
    if _POLICY_DECISION_SCHEMA is not None:
        return _POLICY_DECISION_SCHEMA
    from typing import List as _List, Literal as _Literal, Optional as _Optional
    from pydantic import BaseModel, Field

    class Endpoint(BaseModel):
        """Fine-grained NETWORK/IPC/SIGNAL constraint (all fields optional)."""
        family: _Optional[int] = Field(
            default=None, description="NETWORK: address family, e.g. 2 for AF_INET")
        addr: _Optional[int] = Field(
            default=None, description="NETWORK: IPv4 address as a host-order uint32")
        port: _Optional[int] = Field(
            default=None, description="NETWORK: destination port")
        ipc_type: _Optional[str] = Field(
            default=None, description="IPC: one of SHM, MSG, SEM, MQ, MMAP")
        target: _Optional[int] = Field(
            default=None, description="IPC: target key/id")
        target_cgroup: _Optional[int] = Field(
            default=None, description="SIGNAL: target cgroup id")

    class Rule(BaseModel):
        """One typed effect rule."""
        # A closed enum, not a free string: models otherwise invent plausible
        # tokens ("READ", "FILE_WRITE") that PolicyIR cannot compile, and the
        # whole decision then fails closed. With an enum, guided decoding /
        # function-calling cannot emit anything but a real token.
        event_type: _Literal[tuple(VALID_EVENT_TOKENS) + ("*",)] = Field(
            default="*",
            description=("Effect to authorize; one of the valid tokens "
                         "(WRITE, OPEN, CONNECT, ...) or '*' for any."))
        action: _Literal["allow", "deny"] = Field(default="allow")
        path_pattern: str = Field(
            default="",
            description="Absolute path prefix for FILESYSTEM rules, else empty.")
        endpoint: _Optional[Endpoint] = Field(
            default=None,
            description="Only for NETWORK/IPC/SIGNAL rules; omit otherwise.")

    class PolicyDecisionSchema(BaseModel):
        """Commit the epoch's effects under `rules`, or roll it back."""
        decision: _Literal["allow", "deny"] = Field(
            description="'allow' to commit, 'deny' to roll back losslessly.")
        reason: str = Field(default="", description="Short justification.")
        rules: _List[Rule] = Field(
            default_factory=list,
            description=("For allow: every effect to authorize (absence of an "
                         "allow == denial). For deny: leave empty."))

    _POLICY_DECISION_SCHEMA = PolicyDecisionSchema
    return _POLICY_DECISION_SCHEMA


# endpoint 只对这三类有意义；PolicyIR 拒绝其他类别带 endpoint 的规则。
_ENDPOINT_CLASS_IDS = frozenset(
    CLASS_IDS[name] for name in ("NETWORK", "IPC", "SIGNAL"))


def _endpoint_allowed(event_type: str) -> bool:
    """True if an endpoint is meaningful for this event_type."""
    entry = LEGACY_MAP.get(str(event_type).strip().upper())
    return bool(entry) and entry[0] in _ENDPOINT_CLASS_IDS


def _structured_to_dict(result: Any) -> Dict[str, Any]:
    """Normalize a structured-output result (pydantic model or dict) to a dict.

    Raises :class:`PolicyGenerationError` if the reply carries no usable
    ``decision``. Not every backend enforces the schema: when
    ``with_structured_output`` falls back to JSON mode it may hand back an
    unvalidated dict (empty, or missing fields). Raising here routes such a
    reply to the prompt+JSON fallback path instead of failing closed on a
    reply the model may well be able to produce in plain text.
    """
    if result is None:
        raise PolicyGenerationError("structured output returned None")
    if isinstance(result, Mapping):
        data = dict(result)
    elif hasattr(result, "model_dump"):      # pydantic v2
        data = result.model_dump()
    elif hasattr(result, "dict"):            # pydantic v1
        data = result.dict()
    else:
        raise PolicyGenerationError(
            f"cannot read structured output of type {type(result).__name__}")
    if not str(data.get("decision", "") or "").strip():
        raise PolicyGenerationError(
            f"structured output carried no decision field (got {data!r})")
    return data


class LLMPolicyGenerator(PolicyGenerator):
    """Ask a language model to produce the allow/deny decision.

    The input is still the fixed :class:`PolicyRequest`; the output is still a
    validated :class:`PolicyDecision`. Only the middle step — turning the
    request into a decision — is delegated to a model.

    Determinism / safety: a model is not deterministic, so this generator is
    strictly FAIL-CLOSED. Any of {model call raises, reply is not a conforming
    object, ``decision`` is missing/unknown, rules do not compile} becomes a
    DENY (when ``on_error='deny'``, the default) rather than a crash or an
    accidental allow. Run the model at temperature 0.

    Structured output: when a LangChain model is passed AND pydantic is
    available, the decision is obtained via ``model.with_structured_output(
    schema)`` — the model is FORCED (function-calling / JSON mode) to emit a
    schema-conforming object, which is far more reliable than asking for JSON
    in the prompt. If structured output is unavailable (a plain ``complete=``
    callable, a model without ``with_structured_output``, or pydantic missing)
    it transparently falls back to prompt + JSON parsing. Both paths are
    fail-closed.

    Wiring — pass ONE of:
      * ``model=`` a LangChain chat model / Runnable (anything with
        ``.invoke(prompt) -> message`` whose ``.content`` is the text), or
      * ``complete=`` a plain callable ``(prompt: str) -> str``.

    Example::

        from langchain_openai import ChatOpenAI
        policy = LLMPolicyGenerator(
            model=ChatOpenAI(model="qwen3-14b",
                             base_url="http://localhost:8000/v1",
                             api_key="EMPTY", temperature=0))
        penumbra.start(policy=policy)
    """

    def __init__(self, model: Any = None, *,
                 complete: Optional[Callable[[str], str]] = None,
                 system_prompt: Optional[str] = None,
                 on_error: str = DENY,
                 max_output_chars: int = 2000,
                 structured_output: bool = True,
                 structured_method: Optional[str] = None):
        if model is None and complete is None:
            raise PolicyGenerationError(
                "LLMPolicyGenerator needs either model= (a LangChain model) "
                "or complete= (a callable prompt->str)")
        self._model = model
        self._complete = complete
        self.system_prompt = system_prompt or _DEFAULT_LLM_SYSTEM_PROMPT
        if on_error not in (ALLOW, DENY):
            raise PolicyGenerationError("on_error must be 'deny' or 'allow'")
        self.on_error = on_error
        self.max_output_chars = max_output_chars
        self.structured_output = structured_output
        # Providers differ in which structured-output transport they accept, and
        # an unsupported one only fails at CALL time (HTTP 400), not at binding.
        # So keep an ordered candidate list and step through it at runtime.
        # Known cases: OpenAI accepts the default (json_schema); DeepSeek's
        # thinking models reject both json_schema ("response_format type is
        # unavailable") and function_calling ("Thinking mode does not support
        # this tool_choice"), leaving json_mode.
        self._method_candidates = ((structured_method,) if structured_method
                                   else (None, "function_calling", "json_mode"))
        self._method_index = 0
        self._structured = None
        self._structured_ready = False

    # ── prompt / model plumbing ──────────────────────────────────────────

    def build_prompt(self, request: PolicyRequest) -> str:
        """Render the request into the user turn. Override to customize."""
        commands = [
            {"command": c.command, "exit_code": c.exit_code,
             "output": (c.output or "")[:self.max_output_chars]}
            for c in request.commands
        ]
        payload = {
            "tool_name": request.tool_name,
            "tool_description": request.tool_description,
            "arguments": {"args": list(request.args),
                          "kwargs": dict(request.kwargs)},
            "workspace": request.workspace,
            "declared_paths": list(request.declared_paths),
            "paths_outside_workspace": request.paths_outside_workspace(),
            "commands": commands,
            "fenced_effects": [dict(v) for v in request.violations],
            "tool_failed": request.failed,
            "error": request.error,
            "metadata": dict(request.metadata),
        }
        return (
            f"{self.system_prompt}\n\n"
            f"{_OUTPUT_CONTRACT}\n\n"
            f"Valid event_type tokens: {', '.join(VALID_EVENT_TOKENS)}, or \"*\".\n\n"
            f"Tool call to judge (JSON):\n{json.dumps(payload, ensure_ascii=False, default=str)}\n\n"
            f"Respond with the policy JSON object only."
        )

    def _invoke_model(self, prompt: str) -> str:
        if self._complete is not None:
            return self._complete(prompt)
        model = self._model
        if hasattr(model, "invoke"):          # LangChain Runnable / chat model
            out = model.invoke(prompt)
            return getattr(out, "content", out)
        if callable(model):
            return model(prompt)
        raise PolicyGenerationError(
            f"don't know how to call model of type {type(model).__name__}; "
            f"pass complete= instead")

    def _get_structured(self):
        """Return a structured-output runnable for the current method, or None.

        Cached until :meth:`_next_structured_method` invalidates it. Binding
        failures step to the next candidate; exhausting them disables structured
        output so the generator falls back to prompt + JSON parsing.
        """
        if self._structured_ready:
            return self._structured
        self._structured_ready = True
        self._structured = None
        model = self._model
        if (not self.structured_output or model is None
                or not hasattr(model, "with_structured_output")):
            return None
        schema = _policy_decision_schema()
        while self._method_index < len(self._method_candidates):
            method = self._method_candidates[self._method_index]
            try:
                self._structured = (
                    model.with_structured_output(schema) if method is None
                    else model.with_structured_output(schema, method=method))
                return self._structured
            except Exception:  # noqa: BLE001 - try the next transport
                self._method_index += 1
        return None

    def _next_structured_method(self) -> bool:
        """Step to the next structured-output candidate. False when exhausted."""
        if self._method_index + 1 >= len(self._method_candidates):
            self._structured = None
            self._structured_ready = True
            return False
        self._method_index += 1
        self._structured_ready = False       # force a rebind
        return True

    @property
    def active_structured_method(self) -> Optional[str]:
        """Which structured-output transport is in use, if any."""
        if self._structured is None:
            return None
        return self._method_candidates[self._method_index] or "default"

    # ── the generator contract ───────────────────────────────────────────

    def generate(self, request: PolicyRequest) -> PolicyDecision:
        prompt = None
        last_error = ""
        while True:
            structured = self._get_structured()
            if structured is None:
                break
            if prompt is None:
                prompt = self.build_prompt(request)
            try:
                data = _structured_to_dict(structured.invoke(prompt))
            except Exception as exc:  # noqa: BLE001
                last_error = f"{type(exc).__name__}: {exc}"
                if self._next_structured_method():
                    continue      # this transport is unsupported; try the next
                break             # candidates exhausted -> text fallback
            return self._decision_from_json(data, request)
        note = f"structured output unusable ({last_error})" if last_error else ""
        return self._generate_text(request, note=note)

    def _generate_text(self, request: PolicyRequest,
                       note: str = "") -> PolicyDecision:
        """Prompt + JSON-parse fallback path."""
        try:
            raw = self._invoke_model(self.build_prompt(request))
            data = json.loads(_extract_json_object(raw))
        except Exception as exc:  # noqa: BLE001 - fail closed below
            suffix = f" ({note})" if note else ""
            return self._fallback(f"policy model call/parse failed: {exc}{suffix}")
        return self._decision_from_json(data, request)

    def _decision_from_json(self, data: Any,
                            request: PolicyRequest) -> PolicyDecision:
        if not isinstance(data, Mapping):
            return self._fallback("policy model reply was not a JSON object")
        decision = str(data.get("decision", "")).strip().lower()
        reason = str(data.get("reason", "") or "")
        meta = {"policy": type(self).__name__, "source": "llm",
                "transport": self.active_structured_method or "text"}
        if decision == DENY:
            return PolicyDecision.deny(reason or "denied by LLM policy",
                                       metadata=meta)
        if decision != ALLOW:
            return self._fallback(f"policy model returned decision "
                                  f"{decision!r}; expected allow/deny")
        rules: List[EffectRule] = []
        for raw_rule in data.get("rules") or []:
            if not isinstance(raw_rule, Mapping):
                return self._fallback("a rule from the model was not an object")
            event_type = str(raw_rule.get("event_type", "*"))
            endpoint = raw_rule.get("endpoint")
            if isinstance(endpoint, Mapping):
                # Structured output emits every optional field (as null); drop
                # them so PolicyIR's endpoint defaults apply and None never
                # reaches its integer validators.
                endpoint = {k: v for k, v in endpoint.items()
                            if v is not None} or None
            if endpoint is not None and not _endpoint_allowed(event_type):
                # Guided decoding likes to fill EVERY field, so models hand back
                # a zero-filled endpoint even on FILESYSTEM rules. Keeping it
                # would make PolicyIR reject the whole rule set ("endpoints are
                # only supported for NETWORK/IPC/SIGNAL rules") and fail closed
                # on an otherwise fine decision. It carries no meaning here.
                endpoint = None
            rules.append(EffectRule(
                event_type=event_type,
                action=str(raw_rule.get("action", ALLOW)).lower(),
                path_pattern=str(raw_rule.get("path_pattern",
                                              raw_rule.get("path", "")) or ""),
                endpoint=endpoint))
        candidate = PolicyDecision.allow(rules, reason=reason or "allowed by LLM",
                                         metadata=meta)
        # Compile now so a hallucinated/invalid rule set fails closed to DENY
        # instead of raising later at the daemon boundary.
        try:
            candidate.validate(request.tool_name)
        except PolicyGenerationError as exc:
            return self._fallback(f"LLM rules do not compile: {exc}")
        return candidate

    def _fallback(self, reason: str) -> PolicyDecision:
        """Fail-closed (or -open, if explicitly configured) fallback."""
        if self.on_error == ALLOW:
            # Only reachable when the caller opted into failing OPEN.
            return PolicyDecision.allow(
                [allow("*", "/")],
                reason=f"LLM policy error, failing open: {reason}",
                metadata={"policy": type(self).__name__, "failed_open": True})
        return PolicyDecision.deny(
            f"LLM policy could not decide, failing closed: {reason}",
            metadata={"policy": type(self).__name__, "failed_closed": True})


PolicyLike = Union[PolicyGenerator, Callable[[PolicyRequest], PolicyDecision]]


def coerce_policy(policy: Optional[PolicyLike]) -> Optional[PolicyGenerator]:
    """Accept a generator instance, a class, or a plain function."""
    if policy is None:
        return None
    if isinstance(policy, PolicyGenerator):
        return policy
    if isinstance(policy, type) and issubclass(policy, PolicyGenerator):
        return policy()
    if callable(policy):
        return FunctionPolicyGenerator(policy)
    raise PolicyGenerationError(
        f"cannot use {policy!r} as a policy: expected a PolicyGenerator "
        f"subclass/instance or a callable taking a PolicyRequest")
