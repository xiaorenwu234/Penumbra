#!/usr/bin/env python3
"""
Unit tests for the orchestrator release path (_release_proc / _flush_output).

These exercise the fail-closed guarantee: a ShadowProc query/resume failure or
an output-read failure must NOT ack the release, NOT consume the output buffer,
and NOT drop pending state -- otherwise processes could stay frozen while
ShadowFS has already dropped the Finalized terminal record.

No live services are needed: the orchestrator instance is built without its
__init__ (which would open sockets and start the retry thread) and fed fake
socket clients with programmable responses.
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


def _bare_orch(proc_handler, fs_handler):
    """Build an orchestrator with fake clients and no sockets/threads."""
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch.proc_client = FakeClient(proc_handler)
    orch.fs_client = FakeClient(fs_handler)
    orch._output_buffers = {}
    orch._pending_release = set()
    orch._pending_lock = threading.Lock()
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
    def _make_buffer(self, orch, cg, content="hello-stdout"):
        fd, path = tempfile.mkstemp(prefix="shadow-out-")
        os.write(fd, content.encode())
        os.close(fd)
        orch._output_buffers[cg] = path
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_continue_by_cgroup_failure_no_ack(self):
        """continue_by_cgroup error => (False,''), no ack, buffer preserved."""
        cg = "cg-resume-fail"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "ok", "frozen": [111, 222]}
            if req["action"] == "continue_by_cgroup":
                return {"status": "error", "message": "resume boom"}
            return {"status": "ok"}

        orch = _bare_orch(proc, _fs_ok)
        path = self._make_buffer(orch, cg)

        ok, out = orch._release_proc(cg)

        self.assertFalse(ok, "resume failure must report failure")
        self.assertEqual(out, "")
        self.assertNotIn("ack_release", orch.fs_client.actions(),
                         "must NOT ack when processes are still frozen")
        self.assertIn(cg, orch._output_buffers,
                      "output buffer record must be preserved for retry")
        self.assertTrue(os.path.exists(path),
                        "buffered stdout file must not be consumed")

    def test_list_frozen_failure_no_ack(self):
        """list_frozen error => (False,''), no resume, no ack, buffer kept."""
        cg = "cg-query-fail"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "error", "message": "proc down"}
            raise AssertionError("continue_by_cgroup must not be attempted")

        orch = _bare_orch(proc, _fs_ok)
        path = self._make_buffer(orch, cg)

        ok, out = orch._release_proc(cg)

        self.assertFalse(ok)
        self.assertEqual(out, "")
        self.assertNotIn("continue_by_cgroup", orch.proc_client.actions())
        self.assertNotIn("ack_release", orch.fs_client.actions())
        self.assertIn(cg, orch._output_buffers)
        self.assertTrue(os.path.exists(path))

    def test_flush_read_failure_preserves_buffer_no_ack(self):
        """Output read failure => (False,''), no ack, record preserved."""
        cg = "cg-flush-fail"

        def proc(req):
            # No frozen procs, so resume is skipped; only the flush can fail.
            if req["action"] == "list_frozen":
                return {"status": "ok", "frozen": []}
            return {"status": "ok"}

        orch = _bare_orch(proc, _fs_ok)
        # Point the buffer at a directory: open() for read raises OSError
        # (IsADirectoryError), which is a genuine read failure, not "missing".
        bad = tempfile.mkdtemp(prefix="shadow-out-dir-")
        self.addCleanup(lambda: os.path.isdir(bad) and os.rmdir(bad))
        orch._output_buffers[cg] = bad

        ok, out = orch._release_proc(cg)

        self.assertFalse(ok)
        self.assertEqual(out, "")
        self.assertNotIn("ack_release", orch.fs_client.actions())
        self.assertIn(cg, orch._output_buffers,
                      "buffer record must survive a read failure")

    def test_successful_release_acks_and_flushes(self):
        """Happy path => (True, content), ack once, buffer consumed."""
        cg = "cg-ok"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "ok", "frozen": [7]}
            if req["action"] == "continue_by_cgroup":
                return {"status": "ok", "pids": [7]}
            return {"status": "ok"}

        orch = _bare_orch(proc, _fs_ok)
        path = self._make_buffer(orch, cg, content="done\n")

        ok, out = orch._release_proc(cg)

        self.assertTrue(ok)
        self.assertEqual(out, "done\n")
        self.assertEqual(orch.fs_client.actions().count("ack_release"), 1)
        self.assertNotIn(cg, orch._output_buffers)
        self.assertFalse(os.path.exists(path), "buffer file unlinked on success")

    def test_commit_defers_when_release_fails(self):
        """commit() keeps the cgroup fenced+pending when resume fails."""
        cg = "cg-commit-defer"

        def proc(req):
            if req["action"] == "list_frozen":
                return {"status": "ok", "frozen": [9]}
            if req["action"] == "continue_by_cgroup":
                return {"status": "error", "message": "resume boom"}
            return {"status": "ok"}

        fs_calls = {"can_release": 0}

        def fs(req):
            if req["action"] == "can_release":
                fs_calls["can_release"] += 1
                return {"status": "ok", "releasable": True}
            if req["action"] == "commit":
                return {"status": "ok", "state": "Finalized", "releasable": True}
            return {"status": "ok"}

        orch = _bare_orch(proc, fs)
        self._make_buffer(orch, cg)

        resp = orch.commit(cg)

        self.assertEqual(resp["decision"], "authorized_pending")
        self.assertFalse(resp["released"])
        self.assertTrue(resp.get("deferred"))
        self.assertEqual(resp["stdout"], "")
        self.assertIn(cg, orch._pending_release,
                      "cgroup must stay parked for the retry loop")
        self.assertNotIn("ack_release", orch.fs_client.actions(),
                         "release must never be acked while procs stay frozen")


if __name__ == "__main__":
    unittest.main(verbosity=2)
