#!/usr/bin/env python3
"""
Unit tests for the Phase 1 fence / finalization hardening:

  * _release_proc discards baselines (commit_by_cgroup) BEFORE the full release
    (continue_by_cgroup), and fails CLOSED if the baseline discard fails.
  * session_commit_epoch drives the REAL finalization path: reversible
    quiesce, whole-agent FS "commit" (authorize + promote), a fail-closed
    can_release gate, and only THEN the destructive process commit
    (finalize_commit) + marker close + release ack. On FS failure or a
    not-yet-Finalized agent the baseline is preserved.
  * session_run releases output IMMEDIATELY, in or out of an epoch (optimistic
    release); ordering is enforced per agent by the begin_epoch barrier instead
    of by withholding speculative output.
  * An unknown policy event_type fails CLOSED (ValueError) instead of being
    widened to a match-everything wildcard.

No live services are needed: the orchestrator is built without its __init__ and
fed fake clients / a fake proxy with programmable responses.
"""

import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Also add project root for policy.policy_ir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shadow_orchestrator import ShadowOrchestrator
from policy.policy_ir import PolicyIR


class FakeClient:
    """Records every request and returns whatever `handler(req)` produces."""

    def __init__(self, handler):
        self._handler = handler
        self.calls = []

    def request(self, req):
        self.calls.append(dict(req))
        return self._handler(req)

    def actions(self):
        return [c["action"] for c in self.calls]


def _fs_ok(req):
    return {"status": "ok"}


def _bare_orch(proc_handler, fs_handler):
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch.proc_client = FakeClient(proc_handler)
    orch.fs_client = FakeClient(fs_handler)
    orch._pending_release = set()
    orch._pending_lock = threading.Lock()
    orch._pending_ack = set()
    orch._pending_ack_lock = threading.Lock()
    orch._release_lock = threading.RLock()
    return orch


class TestReleaseProcDiscardsBaseline(unittest.TestCase):
    """_release_proc must commit_by_cgroup (discard baselines) before the full
    release, and fail closed if that discard fails."""

    def test_commit_by_cgroup_precedes_continue(self):
        """Happy path: commit_by_cgroup is issued BEFORE continue_by_cgroup."""
        cg = "cg-order"

        def proc(req):
            a = req["action"]
            if a == "list_frozen":
                return {"status": "ok", "frozen": [10]}
            if a == "commit_by_cgroup":
                return {"status": "ok", "pids": [10]}
            if a == "continue_by_cgroup":
                return {"status": "ok", "pids": [10]}
            return {"status": "ok"}

        orch = _bare_orch(proc, _fs_ok)

        ok, out = orch._release_proc(cg)

        self.assertTrue(ok)
        self.assertEqual(out, "", "output now lives in the session transcript")
        acts = orch.proc_client.actions()
        self.assertIn("commit_by_cgroup", acts)
        self.assertIn("continue_by_cgroup", acts)
        self.assertLess(acts.index("commit_by_cgroup"),
                        acts.index("continue_by_cgroup"),
                        "baseline discard must precede the full release")
        self.assertEqual(orch.fs_client.actions().count("ack_release"), 1)

    def test_commit_by_cgroup_failure_fails_closed(self):
        """commit_by_cgroup error => (False,''): NO resume, NO ack."""
        cg = "cg-commit-fail"

        def proc(req):
            a = req["action"]
            if a == "list_frozen":
                return {"status": "ok", "frozen": [10, 11]}
            if a == "commit_by_cgroup":
                return {"status": "error", "message": "discard boom"}
            if a == "continue_by_cgroup":
                raise AssertionError("must NOT resume after baseline-discard fail")
            return {"status": "ok"}

        orch = _bare_orch(proc, _fs_ok)

        ok, out = orch._release_proc(cg)

        self.assertFalse(ok)
        self.assertEqual(out, "")
        self.assertNotIn("continue_by_cgroup", orch.proc_client.actions())
        self.assertNotIn("ack_release", orch.fs_client.actions())


class FakeProxy:
    """Records the commit-phase calls the orchestrator drives."""

    def __init__(self, output="TRANSCRIPT"):
        self.calls = []
        self._output = output

    def quiesce_for_commit(self, sid):
        self.calls.append("quiesce_for_commit")

    def finalize_commit(self, sid):
        self.calls.append("finalize_commit")

    def get_output(self, sid):
        self.calls.append("get_output")
        return self._output

    def peek_epoch_output(self, sid):
        self.calls.append("peek_epoch_output")
        return self._output

    def snapshot_epoch_output(self, sid):
        self.calls.append("snapshot_epoch_output")
        return self._output

    def run(self, sid, command):
        raise AssertionError("run() not exercised in these tests")


class _NullJournal:
    """No-op durable journal stub for the session-orchestrator unit tests."""

    def append(self, *args, **kwargs):
        pass


def _session_orch(proxy, fs_handler):
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch.fs_client = FakeClient(fs_handler)
    orch._proxy = proxy
    orch._sessions = {"sid1": "/cg-sess"}
    orch._sessions_lock = threading.Lock()
    orch._session_epochs = {}
    orch._journal = _NullJournal()
    orch._recovered_outputs = {}
    orch._release_lock = threading.RLock()
    orch._pending_release = set()
    orch._pending_lock = threading.Lock()
    orch._pending_ack = set()
    orch._pending_ack_lock = threading.Lock()
    # Per-agent barrier state: session_commit_epoch releases the agent slot on
    # every exit path, so these must exist even when no agent_id is used.
    orch._agent_inflight = {}
    orch._session_agents = {}
    orch._agent_cv = threading.Condition()
    orch._agent_wait_timeout = 5.0
    return orch


class TestSessionCommitEpochFSFirst(unittest.TestCase):
    def test_fs_success_finalizes_and_releases(self):
        """Group-level finalize ok + Finalized => quiesce THEN finalize;
        group acked, transcript released."""
        proxy = FakeProxy(output="OUT")

        def fs(req):
            a = req["action"]
            if a == "prepare_resolution":
                return {"status": "ok", "group_id": 1,
                        "members": ["epoch-1"], "graph_generation": 1}
            if a == "begin_finalize":
                return {"status": "ok", "state": "finalized"}
            if a == "get_finalize_status":
                return {"status": "ok", "state": "finalized"}
            if a == "ack_release_group":
                return {"status": "ok"}
            return {"status": "ok"}

        orch = _session_orch(proxy, fs)
        resp = orch.session_commit_epoch("sid1")

        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["output"], "OUT")
        # quiesce must come first, finalize only after the FS gate.
        self.assertEqual(proxy.calls[0], "quiesce_for_commit")
        self.assertIn("finalize_commit", proxy.calls)
        self.assertLess(proxy.calls.index("quiesce_for_commit"),
                        proxy.calls.index("finalize_commit"))
        # Group-level finalization path: prepare_resolution -> begin_finalize
        # -> ack_release_group, in that order.
        acts = orch.fs_client.actions()
        self.assertIn("prepare_resolution", acts)
        self.assertIn("begin_finalize", acts)
        self.assertIn("ack_release_group", acts)
        self.assertLess(acts.index("prepare_resolution"),
                        acts.index("begin_finalize"))
        self.assertLess(acts.index("begin_finalize"),
                        acts.index("ack_release_group"))

    def test_fs_failure_preserves_baseline(self):
        """prepare_resolution fail => quiesce ran but finalize_commit NEVER
        called (baseline preserved so the epoch can still be rolled back)."""
        proxy = FakeProxy()

        def fs(req):
            return {"status": "error", "message": "fs cannot finalize"}

        orch = _session_orch(proxy, fs)
        resp = orch.session_commit_epoch("sid1")

        self.assertNotEqual(resp["status"], "ok")
        self.assertIn("quiesce_for_commit", proxy.calls)
        self.assertNotIn("finalize_commit", proxy.calls,
                         "baseline must NOT be discarded when FS fails")
        self.assertNotIn("ack_release_group", orch.fs_client.actions())

    def test_not_finalized_preserves_baseline(self):
        """begin_finalize ok but agent NOT Finalized (deferred promotion/upstream)
        => authorized_pending, baseline preserved, nothing acked."""
        proxy = FakeProxy()

        def fs(req):
            a = req["action"]
            if a == "prepare_resolution":
                return {"status": "ok", "group_id": 1,
                        "members": ["epoch-1"], "graph_generation": 1}
            if a == "begin_finalize":
                return {"status": "ok", "state": "authorized_pending"}
            if a == "get_finalize_status":
                return {"status": "ok", "state": "authorized_pending"}
            return {"status": "ok"}

        orch = _session_orch(proxy, fs)
        resp = orch.session_commit_epoch("sid1")

        self.assertEqual(resp["status"], "error")
        self.assertEqual(resp.get("decision"), "authorized_pending")
        self.assertNotIn("finalize_commit", proxy.calls,
                         "baseline must NOT be discarded before Finalized")
        acts = orch.fs_client.actions()
        self.assertNotIn("ack_release_group", acts)


class RunProxy:
    """Minimal proxy whose run() returns a programmable (output, exit_code)."""

    def __init__(self, value, rc=0):
        self._value = value
        self._rc = rc

    def run(self, sid, command):
        return self._value, self._rc


class TestSessionRunOptimisticRelease(unittest.TestCase):
    """Output is released immediately, in or out of an epoch.

    The old contract held speculative in-epoch output back (status=pending,
    output=None). It no longer does: the agent's context is internal state and
    may advance optimistically, while externally-visible effects stay gated by
    the epoch. Ordering is enforced per agent at begin_epoch instead — see
    TestAgentBarrier.
    """

    def _orch(self, proxy):
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
        orch._proxy = proxy
        return orch

    def test_in_epoch_output_is_released_immediately(self):
        """Speculative in-epoch output is returned, not withheld."""
        orch = self._orch(RunProxy("spec out"))
        resp = orch.session_run("sid1", "echo hi")
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["output"], "spec out")
        self.assertEqual(resp["exit_code"], 0)

    def test_never_returns_pending(self):
        """Even a None from the proxy must not resurrect the pending path."""
        orch = self._orch(RunProxy(None))
        resp = orch.session_run("sid1", "echo hi")
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["output"], "")
        self.assertEqual(resp["exit_code"], 0)

    def test_out_of_epoch_output_returned(self):
        """Canonical output (a string, even empty) is returned immediately."""
        orch = self._orch(RunProxy("hi\n"))
        resp = orch.session_run("sid1", "echo hi")
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["output"], "hi\n")
        self.assertEqual(resp["exit_code"], 0)

        orch_empty = self._orch(RunProxy(""))
        resp2 = orch_empty.session_run("sid1", ":")
        self.assertEqual(resp2["status"], "ok")
        self.assertEqual(resp2["output"], "")

    def test_nonzero_exit_code_propagated(self):
        """A failing command's shell status is returned to the caller."""
        orch = self._orch(RunProxy("", rc=127))
        resp = orch.session_run("sid1", "nosuchcmd")
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["exit_code"], 127)


class TestAgentBarrier(unittest.TestCase):
    """Per-agent serialization: same agent waits, different agent does not."""

    def _orch(self):
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
        orch._agent_inflight = {}
        orch._session_agents = {}
        orch._agent_cv = threading.Condition()
        orch._agent_wait_timeout = 0.3
        return orch

    def test_no_agent_id_never_blocks(self):
        orch = self._orch()
        self.assertIsNone(orch._agent_barrier(None, "sid1"))
        self.assertIsNone(orch._agent_barrier(None, "sid1"))

    def test_first_call_claims_slot(self):
        orch = self._orch()
        self.assertIsNone(orch._agent_barrier("a1", "sid1"))
        self.assertIn("a1", orch._agent_inflight)

    def test_different_agent_does_not_wait(self):
        orch = self._orch()
        orch._agent_barrier("a1", "sid1")
        t0 = time.time()
        self.assertIsNone(orch._agent_barrier("a2", "sid2"))
        self.assertLess(time.time() - t0, 0.1,
                        "a different agent must not be made to wait")

    def test_same_agent_times_out_while_in_flight(self):
        orch = self._orch()
        orch._agent_barrier("a1", "sid1")
        busy = orch._agent_barrier("a1", "sid1")
        self.assertIsNotNone(busy)
        self.assertEqual(busy["status"], "error")
        self.assertTrue(busy.get("agent_busy"))

    def test_same_agent_proceeds_after_release(self):
        """Releasing the slot must wake a waiter rather than let it time out."""
        orch = self._orch()
        orch._agent_wait_timeout = 5.0
        orch._agent_barrier("a1", "sid1")

        def _finish():
            time.sleep(0.1)
            orch._agent_release("a1")

        threading.Thread(target=_finish, daemon=True).start()
        t0 = time.time()
        self.assertIsNone(orch._agent_barrier("a1", "sid1"))
        elapsed = time.time() - t0
        self.assertGreater(elapsed, 0.05, "should actually have waited")
        self.assertLess(elapsed, 2.0, "should wake on release, not time out")

    def test_agent_for_session_reverse_lookup(self):
        orch = self._orch()
        orch._session_agents["sid-x"] = "a1"
        self.assertEqual(orch._agent_for_session("sid-x"), "a1")
        self.assertIsNone(orch._agent_for_session("sid-unknown"))

    def test_resolve_agent_binds_late_agent_id(self):
        """Passing agent_id per call also binds it, so commit/rollback can find
        it without the caller repeating itself."""
        orch = self._orch()
        self.assertEqual(orch._resolve_agent("sid1", "a1"), "a1")
        self.assertEqual(orch._agent_for_session("sid1"), "a1")
        # Later calls need not resend it.
        self.assertEqual(orch._resolve_agent("sid1", None), "a1")

    def test_one_agent_many_sessions_serializes_across_them(self):
        """The barrier is per AGENT, not per session: an agent's second session
        must wait while its first session's call is still in flight."""
        orch = self._orch()
        orch._session_agents = {"sidA": "a1", "sidB": "a1"}
        # a1's call on sidA is in flight.
        self.assertIsNone(orch._agent_barrier("a1", "sidA"))
        # a1 now tries a DIFFERENT session -- same causal chain, must block.
        busy = orch._agent_barrier("a1", "sidB")
        self.assertIsNotNone(busy)
        self.assertTrue(busy.get("agent_busy"))

    def test_sessions_of_different_agents_do_not_block(self):
        orch = self._orch()
        orch._session_agents = {"sidA": "a1", "sidB": "a2"}
        self.assertIsNone(orch._agent_barrier("a1", "sidA"))
        t0 = time.time()
        self.assertIsNone(orch._agent_barrier("a2", "sidB"))
        self.assertLess(time.time() - t0, 0.1)

    def test_agent_sessions_listing(self):
        orch = self._orch()
        orch._session_agents = {"s1": "a1", "s2": "a2", "s3": "a1"}
        self.assertEqual(orch._agent_sessions("a1"), ["s1", "s3"])
        self.assertEqual(orch._agent_sessions("a2"), ["s2"])
        self.assertEqual(orch._agent_sessions("nobody"), [])


class TestPolicyFailClosed(unittest.TestCase):
    def test_audit_rules_unknown_event_raises(self):
        with self.assertRaises(ValueError):
            ir = PolicyIR.from_allowed_ops(
                [{"event_type": "NOT_A_REAL_EVENT", "action": "allow",
                  "path_pattern": "/tmp/"}])
            ir.to_audit_rules()

    def test_whitelist_unknown_event_raises(self):
        with self.assertRaises(ValueError):
            ir = PolicyIR.from_allowed_ops(
                [{"event_type": "BOGUS", "action": "allow",
                  "path_pattern": "/tmp/"}], 12345)
            ir.to_bpf_whitelist()

    def test_known_and_wildcard_events_accepted(self):
        ir = PolicyIR.from_allowed_ops(
            [{"event_type": "CREATE", "action": "allow", "path_pattern": "/tmp/"},
             {"event_type": "*", "action": "allow", "path_pattern": "/tmp/"}])
        rules = ir.to_audit_rules()
        # CREATE = CLASS_FILESYSTEM(1) | (OP_CREATE(3) << 8) = 769
        self.assertEqual(rules[0]["event_type"], 769)
        self.assertEqual(rules[1]["event_type"], -1)
        wl = PolicyIR.from_allowed_ops(
            [{"event_type": "ANY", "action": "allow", "path_pattern": "/tmp/"}],
            1).to_bpf_whitelist()
        self.assertEqual(wl[0]["event_type"], 0xFFFF)


if __name__ == "__main__":
    unittest.main(verbosity=2)
