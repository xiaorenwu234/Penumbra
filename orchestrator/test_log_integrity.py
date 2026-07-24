#!/usr/bin/env python3
"""
Unit tests for the audit-log-integrity fail-closed gates in submit_policy().

The design guarantees that an INCOMPLETE audit log implies rollback. These
tests verify the orchestrator refuses to commit when:
  1. stop_observe reports the log is incomplete (dropped events / write /
     drain error), and
  2. the audit reports parse errors (an unparsable record is an unknown event
     that may hide a violation) -- even when total_violations == 0.

No live services are needed: the orchestrator is built without __init__ and fed
fake socket clients.
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shadow_orchestrator import ShadowOrchestrator

CG = "/shadow-test"
INODE = 4242
LOG = "/tmp/shadow-test.jsonl"


class FakeClient:
    def __init__(self, handler):
        self._handler = handler
        self.calls = []

    def request(self, req):
        self.calls.append(dict(req))
        return self._handler(req)

    def actions(self):
        return [c["action"] for c in self.calls]


def _proc_ok(req):
    a = req["action"]
    if a == "freeze_by_cgroup":
        return {"status": "ok", "pids": [100, 101]}
    if a in ("reject_by_cgroup", "kill_by_cgroup"):
        return {"status": "ok", "pids": []}
    return {"status": "ok"}


def _fs_ok(req):
    if req["action"] == "rollback":
        return {"status": "ok", "affected": []}
    return {"status": "ok"}


def _bare_orch(observe_handler, proc_handler=_proc_ok, fs_handler=_fs_ok):
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch.observe_client = FakeClient(observe_handler)
    orch.proc_client = FakeClient(proc_handler)
    orch.fs_client = FakeClient(fs_handler)
    orch._observe_state = {CG: {"log_path": LOG, "cgroup_inode": INODE}}
    orch._output_buffers = {}
    orch._pending_release = set()
    orch._pending_lock = threading.Lock()
    return orch


ALLOWED_OPS = [{"event_type": "CREATE", "action": "allow", "path_pattern": "/tmp"}]


class TestLogIntegrityGates(unittest.TestCase):
    def test_incomplete_stop_fails_closed_and_skips_audit(self):
        """stop_observe reports dropped events => fail closed, no audit run."""

        def observe(req):
            if req["action"] == "stop_observe":
                return {"status": "ok", "complete": False,
                        "dropped_events": 3, "write_error": False,
                        "drain_error": False, "reason": "incomplete log"}
            if req["action"] == "audit":
                raise AssertionError("audit must NOT run when the log is incomplete")
            return {"status": "ok"}

        orch = _bare_orch(observe)
        resp = orch.submit_policy(CG, ALLOWED_OPS)

        self.assertEqual(resp["decision"], "fail_closed")
        self.assertIn("incomplete", resp["reason"])
        self.assertNotIn("audit", orch.observe_client.actions())
        self.assertIn("rollback", orch.fs_client.actions(),
                      "fail-closed must roll back the filesystem")

    def test_missing_complete_field_fails_closed(self):
        """An older daemon omitting 'complete' must be treated as incomplete."""

        def observe(req):
            if req["action"] == "stop_observe":
                return {"status": "ok", "log_path": LOG}  # no integrity fields
            if req["action"] == "audit":
                raise AssertionError("audit must NOT run when completeness unknown")
            return {"status": "ok"}

        orch = _bare_orch(observe)
        resp = orch.submit_policy(CG, ALLOWED_OPS)
        self.assertEqual(resp["decision"], "fail_closed")

    def test_audit_parse_errors_fail_closed_even_with_zero_violations(self):
        """A clean-looking audit (0 violations) with parse errors must NOT commit."""

        def observe(req):
            if req["action"] == "stop_observe":
                return {"status": "ok", "complete": True, "dropped_events": 0,
                        "write_error": False, "drain_error": False}
            if req["action"] == "audit":
                return {"status": "ok", "complete": False, "parse_errors": 2,
                        "total_events": 5, "total_violations": 0,
                        "violations": []}
            if req["action"] == "install_whitelist":
                raise AssertionError("must NOT install whitelist on integrity failure")
            return {"status": "ok"}

        def fs(req):
            if req["action"] == "commit":
                raise AssertionError("must NOT commit on audit integrity failure")
            if req["action"] == "rollback":
                return {"status": "ok", "affected": []}
            return {"status": "ok"}

        orch = _bare_orch(observe, fs_handler=fs)
        resp = orch.submit_policy(CG, ALLOWED_OPS)

        self.assertEqual(resp["decision"], "fail_closed")
        self.assertIn("integrity", resp["reason"])
        self.assertIn("rollback", orch.fs_client.actions())
        self.assertNotIn("commit", orch.fs_client.actions())


if __name__ == "__main__":
    unittest.main(verbosity=2)
