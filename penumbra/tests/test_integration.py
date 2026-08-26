#!/usr/bin/env python3
"""Offline tests for the Penumbra LangChain integration.

These exercise the integration layer WITHOUT the real eBPF/FUSE stack: a fake
orchestrator implements the JSON-line API in-process, so the tests run as an
unprivileged user with no kernel dependencies. They verify the contract this
layer owns — policy compilation, the epoch bracket, allow/deny resolution, the
@guard annotation, and LangChain tool wrapping.

Run:
    python3 -m pytest penumbra/tests/test_integration.py -v
or:
    python3 penumbra/tests/test_integration.py
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import threading
import json

try:
    import pytest
except ImportError:  # pytest is optional; a minimal shim lets the file self-run
    pytest = None

_PKG_PARENT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _PKG_PARENT not in sys.path:
    sys.path.insert(0, _PKG_PARENT)

import penumbra
from penumbra import (AllowAllPolicy, DenyAllPolicy, EffectRule, PolicyDecision,
                      PolicyGenerator, PolicyRequest, PolicyViolation,
                      WorkspacePolicy, allow, filesystem_rules,
                      shell_plumbing_rules)
from penumbra.client import OrchestratorClient, PenumbraError
from penumbra.policy import PolicyGenerationError
from penumbra.runtime import MODE_INLINE, MODE_SHELL, PenumbraRuntime


# ── a fake orchestrator speaking the real JSON-line protocol ─────────────

class FakeOrchestrator:
    """In-process stand-in for shadow_orchestrator's socket API.

    Records every resolution so tests can assert what policy was installed and
    whether the epoch committed or rolled back.
    """

    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(sock_path)
        self._server.listen(16)
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._seq = 0
        self.resolutions = []       # list of dicts: {decision, allowed_ops, ...}
        self.runs = []              # commands seen via session_run
        self.sessions = {}
        #: >0 makes that many allow-commits answer "authorized_pending" first;
        #: -1 means always pending (see the commit-retry tests).
        self.pending_allows = 0
        self.lock = threading.Lock()

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop = True
        try:
            self._server.close()
        except OSError:
            pass

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._server.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def _handle(self, conn):
        try:
            stream = conn.makefile("rw", buffering=1)
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                req = json.loads(line)
                resp = self._dispatch(req)
                stream.write(json.dumps(resp) + "\n")
                stream.flush()
        except (OSError, ValueError):
            pass
        finally:
            conn.close()

    def _dispatch(self, req):
        action = req.get("action", "")
        with self.lock:
            if action == "session_open":
                self._seq += 1
                sid = f"sess{self._seq}"
                cgroup = "/" + (req.get("cgroup_name") or sid)
                self.sessions[sid] = {"cgroup_id": cgroup, "epoch": None,
                                      "transcript": ""}
                return {"status": "ok", "session_id": sid,
                        "cgroup_id": cgroup,
                        "agent_id": req.get("agent_id", "")}
            if action == "session_begin_epoch":
                sid = req["session_id"]
                self._seq += 1
                epoch = f"ep-{self._seq}"
                self.sessions[sid]["epoch"] = epoch
                return {"status": "ok", "epoch_id": epoch,
                        "cgroup_id": self.sessions[sid]["cgroup_id"]}
            if action == "session_run":
                sid = req["session_id"]
                self.runs.append(req["command"])
                out = f"[ran] {req['command']}"
                self.sessions[sid]["transcript"] += out + "\n"
                return {"status": "ok", "output": out, "exit_code": 0}
            if action == "session_resolve_epoch":
                sid = req["session_id"]
                decision = req.get("decision", "allow")
                # Mimic the real orchestrator's "authorized_pending": policy
                # accepted, epoch kept fenced and INTACT, file layer still
                # finalizing. Tests set pending_allows to exercise the retry.
                if decision == "allow" and self.pending_allows:
                    if self.pending_allows > 0:
                        self.pending_allows -= 1
                    return {"status": "error",
                            "decision": "authorized_pending",
                            "message": "file layer not finalized; epoch kept "
                                       "intact for retry"}
                self.resolutions.append({
                    "session_id": sid, "decision": decision,
                    "allowed_ops": req.get("allowed_ops"),
                    "policy_metadata": req.get("policy_metadata"),
                })
                self.sessions[sid]["epoch"] = None
                return {"status": "ok", "decision": decision,
                        "stdout": self.sessions[sid]["transcript"]}
            if action == "session_rollback_epoch":
                sid = req["session_id"]
                self.resolutions.append({"session_id": sid,
                                         "decision": "rollback"})
                self.sessions[sid]["epoch"] = None
                return {"status": "ok"}
            if action == "session_get_output":
                sid = req["session_id"]
                return {"status": "ok",
                        "output": self.sessions[sid]["transcript"]}
            if action == "session_close":
                self.sessions.pop(req["session_id"], None)
                return {"status": "ok"}
            if action == "session_list":
                return {"status": "ok", "sessions": list(self.sessions)}
            if action == "drain_violations":
                return {"status": "ok", "violations": []}
            if action == "list_agents":
                return {"status": "ok", "agents": []}
        return {"status": "error", "message": f"unknown action {action}"}


def _fixture(func):
    if pytest is not None:
        return pytest.fixture()(func)
    return func


@_fixture
def stack():
    """A runtime wired to a fake orchestrator; inline mode (no privileges)."""
    tmp = tempfile.mkdtemp(prefix="penumbra-test-")
    sock = os.path.join(tmp, "orch.sock")
    fake = FakeOrchestrator(sock)
    fake.start()

    workspace = os.path.join(tmp, "workspace")
    os.makedirs(workspace, exist_ok=True)
    config = penumbra.PenumbraConfig(
        orch_sock=sock, workspace=workspace, autostart=False,
        attach_if_running=True, strict=False, stop_on_exit=False)
    runtime = PenumbraRuntime(config=config, policy=WorkspacePolicy())
    runtime.start()  # attaches to the fake
    try:
        yield runtime, fake, config
    finally:
        runtime.stop()
        fake.stop()


# ── policy layer (no orchestrator needed) ────────────────────────────────

def test_policy_decision_compiles_valid_rules():
    decision = PolicyDecision.allow(
        filesystem_rules("/srv/work") + shell_plumbing_rules(),
        reason="ok")
    decision.validate("t")
    ops = decision.allowed_ops()
    assert any(op["event_type"] == "WRITE" for op in ops)
    assert all(op["action"] == "allow" for op in ops)


def test_policy_decision_rejects_empty_allow():
    with pytest.raises(PolicyGenerationError):
        PolicyDecision.allow([], reason="nothing").validate("t")


def test_policy_decision_rejects_uncompilable_rule():
    bad = PolicyDecision.allow([EffectRule(event_type="NO_SUCH_EVENT")])
    with pytest.raises(PolicyGenerationError):
        bad.validate("t")


def test_policy_request_paths_outside_workspace():
    req = PolicyRequest(tool_name="t", workspace="/srv/work",
                        declared_paths=("/srv/work/a.txt", "/etc/passwd"))
    assert req.paths_outside_workspace() == ["/etc/passwd"]


def test_workspace_policy_denies_outside_paths():
    pol = WorkspacePolicy()
    req = PolicyRequest(tool_name="t", workspace="/srv/work",
                        declared_paths=("/etc/shadow",))
    decision = pol.decide(req)
    assert decision.decision == "deny"


def test_workspace_policy_denies_failed_tool():
    pol = WorkspacePolicy()
    req = PolicyRequest(tool_name="t", workspace="/srv/work",
                        failed=True, error="boom")
    assert pol.decide(req).decision == "deny"


def test_function_policy_is_accepted():
    def my_policy(request: PolicyRequest) -> PolicyDecision:
        return PolicyDecision.allow([allow("WRITE", request.workspace)])

    runtime = PenumbraRuntime(policy=my_policy)
    assert runtime.policy.decide(
        PolicyRequest(tool_name="t", workspace="/w")).allowed


# ── the epoch bracket (against the fake orchestrator) ────────────────────

def test_guarded_call_commits_on_allow(stack):
    runtime, fake, config = stack

    def tool(name: str) -> str:
        return f"hello {name}"

    value = runtime.guarded_call(
        tool, tool_name="greet", args=("world",), mode=MODE_INLINE,
        policy=AllowAllPolicy())
    assert value == "hello world"
    assert fake.resolutions[-1]["decision"] == "allow"
    assert fake.resolutions[-1]["allowed_ops"]


def test_guarded_call_rolls_back_on_deny(stack):
    runtime, fake, config = stack

    def tool() -> str:
        return "should be discarded"

    with pytest.raises(PolicyViolation):
        runtime.guarded_call(tool, tool_name="t", mode=MODE_INLINE,
                             policy=DenyAllPolicy())
    assert fake.resolutions[-1]["decision"] == "deny"


def test_guarded_call_deny_returns_result_when_not_raising(stack):
    runtime, fake, config = stack
    result = runtime.guarded_call(
        lambda: 1, tool_name="t", mode=MODE_INLINE, policy=DenyAllPolicy(),
        raise_on_deny=False, return_result=True)
    assert result.committed is False
    assert result.decision == "deny"


def test_shell_mode_runs_commands_in_session(stack):
    runtime, fake, config = stack

    def tool() -> list:
        return ["echo one", "echo two"]

    out = runtime.guarded_call(tool, tool_name="sh", mode=MODE_SHELL,
                               policy=AllowAllPolicy())
    assert "echo one" in fake.runs and "echo two" in fake.runs
    assert "[ran] echo one" in out


def test_runtime_run_records_commands_for_policy(stack):
    runtime, fake, config = stack
    seen = {}

    def recording_policy(request: PolicyRequest) -> PolicyDecision:
        seen["commands"] = [c.command for c in request.commands]
        return PolicyDecision.allow([allow("*", "/")])

    def tool():
        runtime.run("ls -la")
        return "done"

    runtime.guarded_call(tool, tool_name="t", mode=MODE_INLINE,
                         policy=recording_policy)
    assert seen["commands"] == ["ls -la"]


def test_failed_tool_body_denies_and_raises(stack):
    runtime, fake, config = stack

    def tool():
        raise ValueError("kaboom")

    with pytest.raises(penumbra.ToolExecutionError):
        runtime.guarded_call(tool, tool_name="t", mode=MODE_INLINE,
                             policy=WorkspacePolicy())
    assert fake.resolutions[-1]["decision"] == "deny"


# ── the @guard annotation ────────────────────────────────────────────────

def test_guard_defaults_to_shell_mode(stack):
    """The default mode must be shell, the only one that works on a real stack.

    fork (and auto, which picks fork under root) deadlocks against the process
    fence: ShadowProc SIGSTOPs cgroup members it has not admitted, and the child
    then waits for an authorization that waits for the policy, which waits for
    the body. A tool annotated with a bare @guard() must therefore have its
    return value executed as a command in the session, not run in a child.
    """
    runtime, fake, config = stack
    penumbra._runtime = runtime  # noqa: SLF001 - test wiring

    @penumbra.guard(policy=AllowAllPolicy())
    def touch_note() -> str:
        """Bare @guard(): the body builds a command instead of doing the work."""
        return "echo built-by-default-mode"

    touch_note()
    assert fake.runs and fake.runs[-1] == "echo built-by-default-mode", fake.runs
    assert fake.resolutions[-1]["decision"] == "allow"
    # And the epoch was reported as shell, not fork/auto.
    metadata = fake.resolutions[-1]["policy_metadata"] or {}
    assert metadata.get("mode", "shell") == "shell", metadata


def test_guard_decorator_on_plain_function(stack):
    runtime, fake, config = stack
    guard = penumbra.guard  # bound to the DEFAULT runtime, so swap it in
    penumbra._runtime = runtime  # noqa: SLF001 - test wiring

    @guard(mode=MODE_INLINE, policy=AllowAllPolicy())
    def write_note(text: str) -> str:
        return text.upper()

    assert penumbra.is_guarded(write_note)
    assert write_note("hi") == "HI"
    assert fake.resolutions[-1]["decision"] == "allow"


def test_epoch_context_manager(stack):
    runtime, fake, config = stack
    with runtime.epoch("manual-batch", policy=AllowAllPolicy()):
        runtime.run("true")
    assert fake.resolutions[-1]["decision"] == "allow"
    assert "true" in fake.runs


# ── LLM-backed policy ────────────────────────────────────────────────────

def test_llm_policy_allow_parses_and_compiles():
    from penumbra import LLMPolicyGenerator

    def fake_model(prompt: str) -> str:
        # A well-behaved model: fenced JSON, valid rule.
        return ('```json\n{"decision":"allow","reason":"ok",'
                '"rules":[{"event_type":"WRITE","action":"allow",'
                '"path_pattern":"/srv/work"}]}\n```')

    pol = LLMPolicyGenerator(complete=fake_model)
    decision = pol.decide(PolicyRequest(tool_name="t", workspace="/srv/work"))
    assert decision.allowed
    assert decision.allowed_ops()[0]["event_type"] == "WRITE"


def test_llm_policy_deny_is_respected():
    from penumbra import LLMPolicyGenerator

    def fake_model(prompt: str) -> str:
        return '{"decision":"deny","reason":"looks malicious"}'

    pol = LLMPolicyGenerator(complete=fake_model)
    decision = pol.decide(PolicyRequest(tool_name="t", workspace="/w"))
    assert decision.decision == "deny"
    assert "malicious" in decision.reason


def test_llm_policy_fails_closed_on_garbage():
    from penumbra import LLMPolicyGenerator

    for reply in ("not json at all",
                  '{"decision":"allow","rules":[{"event_type":"BOGUS"}]}',
                  '{"decision":"maybe"}'):
        pol = LLMPolicyGenerator(complete=lambda p, r=reply: r)
        decision = pol.decide(PolicyRequest(tool_name="t", workspace="/w"))
        assert decision.decision == "deny", reply


def test_llm_policy_model_exception_fails_closed():
    from penumbra import LLMPolicyGenerator

    def boom(prompt: str) -> str:
        raise RuntimeError("model unreachable")

    pol = LLMPolicyGenerator(complete=boom)
    assert pol.decide(PolicyRequest(tool_name="t", workspace="/w")).decision == "deny"


def test_llm_policy_end_to_end_rollback(stack):
    runtime, fake, config = stack
    from penumbra import LLMPolicyGenerator

    pol = LLMPolicyGenerator(complete=lambda p: '{"decision":"deny","reason":"no"}')
    with pytest.raises(PolicyViolation):
        runtime.guarded_call(lambda: 1, tool_name="t", mode=MODE_INLINE,
                             policy=pol)
    assert fake.resolutions[-1]["decision"] == "deny"


# ── LLM structured output (needs pydantic; auto-skips if absent) ─────────

class _FakeStructuredRunnable:
    def __init__(self, payload):
        self.payload = payload

    def invoke(self, prompt):
        return self.payload


class _FakeStructuredModel:
    """Mimics a LangChain model exposing with_structured_output()."""

    def __init__(self, payload):
        self.payload = payload
        self.bound_schema = None

    def with_structured_output(self, schema, method=None):
        self.bound_schema = schema
        return _FakeStructuredRunnable(self.payload)

    def invoke(self, prompt):  # must NOT be reached when structured works
        raise AssertionError("text path used despite structured output")


def _pydantic_available():
    try:
        import pydantic  # noqa: F401
        return True
    except ImportError:
        return False


def test_llm_policy_structured_output_allow():
    if not _pydantic_available():
        return  # structured output requires pydantic; nothing to assert here
    from penumbra import LLMPolicyGenerator

    model = _FakeStructuredModel({
        "decision": "allow", "reason": "ok",
        "rules": [{"event_type": "WRITE", "action": "allow",
                   "path_pattern": "/srv/work"}]})
    pol = LLMPolicyGenerator(model=model)
    decision = pol.decide(PolicyRequest(tool_name="t", workspace="/srv/work"))
    assert decision.allowed
    assert decision.allowed_ops()[0]["event_type"] == "WRITE"
    assert model.bound_schema is not None  # with_structured_output was used


def test_llm_policy_structured_output_drops_null_endpoint_fields():
    if not _pydantic_available():
        return
    from penumbra import LLMPolicyGenerator

    # Structured output emits every optional endpoint field, most as null.
    model = _FakeStructuredModel({
        "decision": "allow", "reason": "net",
        "rules": [{"event_type": "CONNECT", "action": "allow",
                   "path_pattern": "",
                   "endpoint": {"family": 2, "addr": None, "port": 443,
                                "ipc_type": None, "target": None,
                                "target_cgroup": None}}]})
    pol = LLMPolicyGenerator(model=model)
    decision = pol.decide(PolicyRequest(tool_name="t", workspace="/w"))
    assert decision.allowed  # None fields dropped, so PolicyIR compiles it


def test_llm_policy_structured_output_deny():
    if not _pydantic_available():
        return
    from penumbra import LLMPolicyGenerator

    model = _FakeStructuredModel({"decision": "deny", "reason": "unsafe",
                                  "rules": []})
    pol = LLMPolicyGenerator(model=model)
    assert pol.decide(PolicyRequest(tool_name="t", workspace="/w")).decision == "deny"


def test_llm_policy_drops_endpoint_on_non_network_rule():
    """Guided decoding fills every field, even endpoints on FILESYSTEM rules.

    PolicyIR rejects those ("endpoints are only supported for NETWORK/IPC/
    SIGNAL rules"), which used to fail an otherwise valid allow closed.
    """
    if not _pydantic_available():
        return
    from penumbra import LLMPolicyGenerator

    model = _FakeStructuredModel({
        "decision": "allow", "reason": "in workspace",
        "rules": [{"event_type": "WRITE", "action": "allow",
                   "path_pattern": "/srv/work",
                   # zero-filled, not null - the null-only cleanup misses this
                   "endpoint": {"family": 10, "addr": 0, "port": 0,
                                "ipc_type": "file", "target": 0,
                                "target_cgroup": 0}}]})
    pol = LLMPolicyGenerator(model=model)
    decision = pol.decide(PolicyRequest(tool_name="t", workspace="/srv/work"))
    assert decision.allowed, decision.reason
    assert decision.rules[0].endpoint is None


def test_llm_policy_keeps_endpoint_on_network_rule():
    """The endpoint cleanup must not strip endpoints where they belong."""
    if not _pydantic_available():
        return
    from penumbra import LLMPolicyGenerator

    model = _FakeStructuredModel({
        "decision": "allow", "reason": "api call",
        "rules": [{"event_type": "CONNECT", "action": "allow",
                   "path_pattern": "",
                   "endpoint": {"family": 2, "port": 443}}]})
    pol = LLMPolicyGenerator(model=model)
    decision = pol.decide(PolicyRequest(tool_name="t", workspace="/w"))
    assert decision.allowed, decision.reason
    assert decision.rules[0].endpoint == {"family": 2, "port": 443}


def test_llm_policy_steps_through_structured_transports():
    """An unsupported transport only 400s at CALL time; step to the next one."""
    if not _pydantic_available():
        return
    from penumbra import LLMPolicyGenerator

    tried = []

    class _Runnable:
        def __init__(self, method):
            self.method = method

        def invoke(self, prompt):
            tried.append(self.method)
            if self.method != "json_mode":
                raise RuntimeError("400 unsupported response_format")
            return {"decision": "allow", "reason": "ok",
                    "rules": [{"event_type": "WRITE", "action": "allow",
                               "path_pattern": "/w"}]}

    class _Model:
        def with_structured_output(self, schema, method=None):
            return _Runnable(method)

        def invoke(self, prompt):
            raise AssertionError("text path used despite a working transport")

    pol = LLMPolicyGenerator(model=_Model())
    assert pol.decide(PolicyRequest(tool_name="t", workspace="/w")).allowed
    assert tried == [None, "function_calling", "json_mode"]
    assert pol.active_structured_method == "json_mode"


def test_llm_policy_empty_structured_reply_falls_back_to_text():
    """A schema-shaped but decision-less reply must not fail closed outright."""
    if not _pydantic_available():
        return
    from penumbra import LLMPolicyGenerator

    class _Runnable:
        def invoke(self, prompt):
            return {}          # JSON mode can hand back an unvalidated dict

    class _Model:
        def with_structured_output(self, schema, method=None):
            return _Runnable()

        def invoke(self, prompt):   # the text fallback must be reached
            return ('{"decision":"allow","reason":"text path",'
                    '"rules":[{"event_type":"WRITE","action":"allow",'
                    '"path_pattern":"/w"}]}')

    pol = LLMPolicyGenerator(model=_Model())
    decision = pol.decide(PolicyRequest(tool_name="t", workspace="/w"))
    assert decision.allowed
    assert decision.reason == "text path"


def test_llm_policy_output_contract_survives_custom_system_prompt():
    """json_mode never shows the model the schema, so the prompt must carry it."""
    from penumbra import LLMPolicyGenerator

    pol = LLMPolicyGenerator(complete=lambda p: "{}",
                             system_prompt="only my business rules")
    prompt = pol.build_prompt(PolicyRequest(tool_name="t", workspace="/w"))
    assert "only my business rules" in prompt
    assert '"decision":"allow"|"deny"' in prompt


def test_commit_retries_while_file_layer_finalizes(stack):
    """authorized_pending means "not yet", not "failed" — retry, don't roll back.

    The orchestrator keeps the epoch fenced and intact and settles the group in
    a background loop. Rolling back here would discard a commit about to land.
    """
    runtime, orch, config = stack
    orch.pending_allows = 2
    config.commit_retry_timeout = 10.0

    value = runtime.guarded_call(lambda: "done", tool_name="touch",
                                 mode=MODE_INLINE, policy=AllowAllPolicy())
    assert value == "done"                    # retried through both pendings
    assert orch.pending_allows == 0
    decisions = [r["decision"] for r in orch.resolutions]
    assert decisions == ["allow"]             # committed once, never rolled back
    assert "rollback" not in decisions


def test_commit_pending_forever_still_fails_closed(stack):
    """If the file layer never finalizes, give up and roll back (fail closed)."""
    runtime, orch, config = stack
    orch.pending_allows = -1                  # always pending
    config.commit_retry_timeout = 0.5         # keep the test quick

    try:
        runtime.guarded_call(lambda: "done", tool_name="touch",
                            mode=MODE_INLINE, policy=AllowAllPolicy())
        raise AssertionError("a never-finalizing commit was accepted")
    except PenumbraError as exc:
        assert "rolled back" in str(exc)
    assert [r["decision"] for r in orch.resolutions] == ["rollback"]


def test_policy_schema_constrains_event_type_to_real_tokens():
    """event_type must be a closed enum, or models invent uncompilable tokens.

    Observed with Qwen3: it emitted "READ" (not a real token), PolicyIR refused
    to compile the rule set, and a perfectly reasonable allow failed closed.
    """
    if not _pydantic_available():
        return
    from penumbra.policy import VALID_EVENT_TOKENS, _policy_decision_schema

    schema = _policy_decision_schema()
    rule_field = schema.model_fields["rules"]
    rule_model = rule_field.annotation.__args__[0]
    allowed = rule_model.model_fields["event_type"].annotation.__args__
    assert "OPEN" in allowed and "WRITE" in allowed
    assert "*" in allowed
    assert "READ" not in allowed          # plausible but not a real token
    assert "FILE_WRITE" not in allowed
    assert len(allowed) == len(VALID_EVENT_TOKENS) + 1


def test_preflight_reports_stale_mount_before_makedirs():
    """A leftover FUSE mount must produce a readable error, not FileExistsError.

    os.makedirs(exist_ok=True) fails on a stale mount (mkdir says EEXIST while
    isdir() says False), so the mount check has to run before ensure_dirs().
    """
    import penumbra.supervisor as sup_mod
    from penumbra.config import PenumbraConfig
    from penumbra.supervisor import StartupError, Supervisor

    tmp = tempfile.mkdtemp(prefix="penumbra-stale-")
    workspace = os.path.join(tmp, "workspace")
    saved = (os.geteuid, sup_mod._is_mounted, sup_mod._mount_responds,
             PenumbraConfig.missing_binaries)
    try:
        os.geteuid = lambda: 0
        sup_mod._is_mounted = lambda path: path == workspace
        sup_mod._mount_responds = lambda path: False       # stale
        PenumbraConfig.missing_binaries = lambda self: []
        sup = Supervisor(PenumbraConfig(workspace=workspace))
        try:
            sup._preflight()
            raise AssertionError("preflight accepted a stale mount")
        except StartupError as exc:
            message = str(exc)
        assert "STALE" in message
        assert f"umount -l {workspace}" in message
    finally:
        (os.geteuid, sup_mod._is_mounted, sup_mod._mount_responds,
         PenumbraConfig.missing_binaries) = saved
        shutil.rmtree(tmp, ignore_errors=True)


def test_client_wire_shape():
    """session_run must send the API's own 'timeout' field, not shadow it."""
    tmp = tempfile.mkdtemp(prefix="penumbra-wire-")
    sock = os.path.join(tmp, "s.sock")
    fake = FakeOrchestrator(sock)
    fake.start()
    try:
        client = OrchestratorClient(sock, timeout=5.0)
        opened = client.session_open("agent-x")
        sid = opened["session_id"]
        client.session_begin_epoch(sid, "agent-x")
        resp = client.session_run(sid, "echo hi", timeout=3.0)
        assert resp["output"] == "[ran] echo hi"
    finally:
        fake.stop()


if pytest is None:
    # ── minimal standalone runner (no pytest installed) ──────────────────
    import contextlib
    import traceback

    class _Raises:
        def __init__(self, exc):
            self.exc = exc

        def __enter__(self):
            return self

        def __exit__(self, et, ev, tb):
            assert et is not None and issubclass(et, self.exc), \
                f"expected {self.exc.__name__}, got {et}"
            return True

    class _PytestShim:
        @staticmethod
        def raises(exc):
            return _Raises(exc)

    pytest = _PytestShim()  # noqa: F811 - intentional shim for standalone run

    def _run_standalone():
        stack_gen = None
        tests = [(n, o) for n, o in sorted(globals().items())
                 if n.startswith("test_") and callable(o)]
        passed = failed = 0
        for name, fn in tests:
            params = fn.__code__.co_varnames[:fn.__code__.co_argcount]
            gen = fixture_ctx = None
            try:
                if "stack" in params:
                    gen = stack.__wrapped__() if hasattr(stack, "__wrapped__") \
                        else stack()
                    fixture_ctx = next(gen)
                    fn(fixture_ctx)
                else:
                    fn()
                passed += 1
                print(f"  PASS {name}")
            except Exception:  # noqa: BLE001
                failed += 1
                print(f"  FAIL {name}")
                traceback.print_exc()
            finally:
                if gen is not None:
                    with contextlib.suppress(StopIteration):
                        next(gen)
        print(f"\n{passed} passed, {failed} failed")
        return 1 if failed else 0


if __name__ == "__main__":
    if hasattr(pytest, "main"):
        sys.exit(pytest.main([__file__, "-v"]))
    sys.exit(_run_standalone())
