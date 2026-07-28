#!/usr/bin/env python3
"""
Unit tests for the orchestrator release path (_release_proc).

These exercise the fail-closed guarantee: a ShadowProc query/resume failure must
NOT ack the release and NOT drop pending state -- otherwise processes could stay
frozen while ShadowFS has already dropped the Finalized terminal record.

Scope note: _release_proc no longer touches any cgroup-level stdout buffer. Under
the session model tool output is released optimistically by SessionProxy.run and
recorded in the session transcript, so there is nothing to pre-read or consume
here; the second element of the returned tuple is always "". The tests that used
to cover that buffer (pre-read failure, flush failure, buffer consumption) were
removed together with the mechanism. The process-layer fail-closed ordering they
shared is still covered below.

No live services are needed: the orchestrator instance is built without its
__init__ (which would open sockets and start the retry thread) and fed fake
socket clients with programmable responses.
"""

import os
import sys
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


def _bare_orch(proc_handler, fs_handler):
    """Build an orchestrator with fake clients and no sockets/threads."""
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch.proc_client = FakeClient(proc_handler)
    orch.fs_client = FakeClient(fs_handler)
    orch._pending_release = set()
    orch._pending_lock = threading.Lock()
    orch._pending_ack = set()
    orch._pending_ack_lock = threading.Lock()
    orch._release_lock = threading.RLock()
    return orch


def _fs_ok(req):
    a = req["action"]
    if a == "can_release":
        return {"status": "ok", "releasable": True}
    if a == "commit":
        return {"status": "ok", "state": "Finalized", "releasable": True}
    return {"status": "ok"}


class TestReleaseProcFailClosed(unittest.TestCase):
    def test_continue_by_cgroup_failure_no_ack(self):
        """continue_by_cgroup error => (False,''), no ack."""
        cg = "cg-resume-fail"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "ok", "frozen": [111, 222]}
            if req["action"] == "continue_by_cgroup":
                return {"status": "error", "message": "resume boom"}
            return {"status": "ok"}

        orch = _bare_orch(proc, _fs_ok)

        ok, out = orch._release_proc(cg)

        self.assertFalse(ok, "resume failure must report failure")
        self.assertEqual(out, "")
        self.assertNotIn("ack_release", orch.fs_client.actions(),
                         "must NOT ack when processes are still frozen")

    def test_list_frozen_failure_no_ack(self):
        """list_frozen error => (False,''), no resume, no ack."""
        cg = "cg-query-fail"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "error", "message": "proc down"}
            raise AssertionError("continue_by_cgroup must not be attempted")

        orch = _bare_orch(proc, _fs_ok)

        ok, out = orch._release_proc(cg)

        self.assertFalse(ok)
        self.assertEqual(out, "")
        self.assertNotIn("continue_by_cgroup", orch.proc_client.actions())
        self.assertNotIn("ack_release", orch.fs_client.actions())

    def test_baseline_discard_failure_before_resume(self):
        """commit_by_cgroup (baseline discard) fails => must NOT resume, no ack.

        The baseline discard runs BEFORE the resume precisely so that a failure
        here leaves every process frozen and no external effect escapes.
        """
        cg = "cg-discard-fail"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "ok", "frozen": [5, 6]}
            if req["action"] == "commit_by_cgroup":
                return {"status": "error", "message": "discard boom"}
            if req["action"] == "continue_by_cgroup":
                raise AssertionError(
                    "must NOT resume when the baseline discard failed")
            return {"status": "ok"}

        orch = _bare_orch(proc, _fs_ok)

        ok, out = orch._release_proc(cg)

        self.assertFalse(ok)
        self.assertEqual(out, "")
        self.assertNotIn("continue_by_cgroup", orch.proc_client.actions(),
                         "processes must NOT be resumed after a discard failure")
        self.assertNotIn("ack_release", orch.fs_client.actions())

    def test_successful_release_acks(self):
        """Happy path => (True, ''), ack exactly once."""
        cg = "cg-ok"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "ok", "frozen": [7]}
            if req["action"] == "continue_by_cgroup":
                return {"status": "ok", "pids": [7]}
            return {"status": "ok"}

        orch = _bare_orch(proc, _fs_ok)

        ok, out = orch._release_proc(cg)

        self.assertTrue(ok)
        self.assertEqual(out, "", "output now lives in the session transcript")
        self.assertEqual(orch.fs_client.actions().count("ack_release"), 1)

    def test_ack_failure_retries_ack_only(self):
        """Resume succeeds but ack fails => (True,'') with the cgroup parked in
        _pending_ack; the ack-only retry then succeeds WITHOUT re-resuming or
        re-querying processes."""
        cg = "cg-ack-fail"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "ok", "frozen": [3]}
            if req["action"] == "continue_by_cgroup":
                return {"status": "ok", "pids": [3]}
            return {"status": "ok"}

        ack_state = {"n": 0}

        def fs(req):
            if req["action"] == "ack_release":
                ack_state["n"] += 1
                # Fail the first ack, succeed on the retry.
                if ack_state["n"] >= 2:
                    return {"status": "ok"}
                return {"status": "error", "message": "fs busy"}
            return _fs_ok(req)

        orch = _bare_orch(proc, fs)

        ok, out = orch._release_proc(cg)

        self.assertTrue(ok, "external effects released even though ack failed")
        self.assertEqual(out, "")
        self.assertIn((cg, ""), orch._pending_ack,
                      "failed ack must be parked for retry")

        # Ack-only retry: succeeds and must NOT resume or re-query processes.
        orch._retry_pending_acks()

        self.assertNotIn((cg, ""), orch._pending_ack, "ack should clear on retry")
        self.assertEqual(orch.proc_client.actions().count("continue_by_cgroup"), 1,
                         "ack retry must NOT resume processes again")
        self.assertEqual(orch.proc_client.actions().count("list_frozen"), 1,
                         "ack retry must NOT re-query frozen processes")
        self.assertEqual(orch.fs_client.actions().count("ack_release"), 2,
                         "exactly one initial ack + one retry")


if __name__ == "__main__":
    unittest.main(verbosity=2)
