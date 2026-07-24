#!/usr/bin/env python3
"""
Unit tests for the Phase 1 fence / finalization hardening:

  * _release_proc discards baselines (commit_by_cgroup) BEFORE the full release
    (continue_by_cgroup), and fails CLOSED if the baseline discard fails.
  * session_commit_epoch is FS-FIRST: the reversible quiesce runs, the file
    layer is gated, and the DESTRUCTIVE process commit (finalize_commit, which
    discards the baseline) happens ONLY on ShadowFS success. On FS failure the
    baseline is preserved (finalize_commit is never called).
  * session_run holds SPECULATIVE output pending during an epoch (never returns
    it to the caller before finalization).
  * An unknown policy event_type fails CLOSED (ValueError) instead of being
    widened to a match-everything wildcard.

No live services are needed: the orchestrator is built without its __init__ and
fed fake clients / a fake proxy with programmable responses.
"""

import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shadow_orchestrator import ShadowOrchestrator


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
    orch._output_buffers = {}
    orch._pending_release = set()
    orch._pending_lock = threading.Lock()
    orch._pending_ack = set()
    orch._pending_ack_lock = threading.Lock()
    orch._release_lock = threading.RLock()
    return orch


class TestReleaseProcDiscardsBaseline(unittest.TestCase):
    """_release_proc must commit_by_cgroup (discard baselines) before the full
    release, and fail closed if that discard fails."""

    def _make_buffer(self, orch, cg, content="hello"):
        fd, path = tempfile.mkstemp(prefix="shadow-out-")
        os.write(fd, content.encode())
        os.close(fd)
        orch._output_buffers[cg] = path
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

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
        self._make_buffer(orch, cg, content="done\n")

        ok, out = orch._release_proc(cg)

        self.assertTrue(ok)
        self.assertEqual(out, "done\n")
        acts = orch.proc_client.actions()
        self.assertIn("commit_by_cgroup", acts)
        self.assertIn("continue_by_cgroup", acts)
        self.assertLess(acts.index("commit_by_cgroup"),
                        acts.index("continue_by_cgroup"),
                        "baseline discard must precede the full release")
        self.assertEqual(orch.fs_client.actions().count("ack_release"), 1)

    def test_commit_by_cgroup_failure_fails_closed(self):
        """commit_by_cgroup error => (False,''): NO resume, NO ack, buffer kept."""
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
        path = self._make_buffer(orch, cg)

        ok, out = orch._release_proc(cg)

        self.assertFalse(ok)
        self.assertEqual(out, "")
        self.assertNotIn("continue_by_cgroup", orch.proc_client.actions())
        self.assertNotIn("ack_release", orch.fs_client.actions())
        self.assertIn(cg, orch._output_buffers, "buffer preserved for retry")
        self.assertTrue(os.path.exists(path))


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

    def run(self, sid, command):
        raise AssertionError("run() not exercised in these tests")


def _session_orch(proxy, fs_handler):
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch.fs_client = FakeClient(fs_handler)
    orch._proxy = proxy
    orch._sessions = {"sid1": "/cg-sess"}
    orch._sessions_lock = threading.Lock()
    return orch


class TestSessionCommitEpochFSFirst(unittest.TestCase):
    def test_fs_success_finalizes_and_releases(self):
        """FS commit_epoch ok => quiesce THEN finalize; transcript released."""
        proxy = FakeProxy(output="OUT")

        def fs(req):
            self.assertEqual(req["action"], "commit_epoch")
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

    def test_fs_failure_preserves_baseline(self):
        """FS commit_epoch fail => quiesce ran but finalize_commit NEVER called
        (baseline preserved so the epoch can still be rolled back)."""
        proxy = FakeProxy()

        def fs(req):
            return {"status": "error", "message": "fs cannot finalize"}

        orch = _session_orch(proxy, fs)
        resp = orch.session_commit_epoch("sid1")

        self.assertNotEqual(resp["status"], "ok")
        self.assertIn("quiesce_for_commit", proxy.calls)
        self.assertNotIn("finalize_commit", proxy.calls,
                         "baseline must NOT be discarded when FS fails")


class RunProxy:
    """Minimal proxy whose run() returns a programmable value."""

    def __init__(self, value):
        self._value = value

    def run(self, sid, command):
        return self._value


class TestSessionRunPending(unittest.TestCase):
    def _orch(self, proxy):
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
        orch._proxy = proxy
        return orch

    def test_in_epoch_output_is_pending(self):
        """proxy.run returns None (speculative) => status pending, no output."""
        orch = self._orch(RunProxy(None))
        resp = orch.session_run("sid1", "echo hi")
        self.assertEqual(resp["status"], "pending")
        self.assertIsNone(resp["output"])

    def test_out_of_epoch_output_returned(self):
        """Canonical output (a string, even empty) is returned immediately."""
        orch = self._orch(RunProxy("hi\n"))
        resp = orch.session_run("sid1", "echo hi")
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["output"], "hi\n")

        orch_empty = self._orch(RunProxy(""))
        resp2 = orch_empty.session_run("sid1", ":")
        self.assertEqual(resp2["status"], "ok")
        self.assertEqual(resp2["output"], "")


class TestPolicyFailClosed(unittest.TestCase):
    def test_audit_rules_unknown_event_raises(self):
        with self.assertRaises(ValueError):
            ShadowOrchestrator._convert_policy_to_audit_rules(
                [{"event_type": "NOT_A_REAL_EVENT", "action": "allow",
                  "path_pattern": "/tmp/"}])

    def test_whitelist_unknown_event_raises(self):
        with self.assertRaises(ValueError):
            ShadowOrchestrator._convert_policy_to_whitelist(
                [{"event_type": "BOGUS", "action": "allow",
                  "path_pattern": "/tmp/"}], 12345)

    def test_known_and_wildcard_events_accepted(self):
        rules = ShadowOrchestrator._convert_policy_to_audit_rules(
            [{"event_type": "CREATE", "action": "allow", "path_pattern": "/tmp/"},
             {"event_type": "*", "action": "allow", "path_pattern": "/tmp/"}])
        self.assertEqual(rules[0]["event_type"], 2)
        self.assertEqual(rules[1]["event_type"], -1)
        wl = ShadowOrchestrator._convert_policy_to_whitelist(
            [{"event_type": "ANY", "action": "allow", "path_pattern": "/tmp/"}],
            1)
        self.assertEqual(wl[0]["event_type"], 0xFFFF)


if __name__ == "__main__":
    unittest.main(verbosity=2)
