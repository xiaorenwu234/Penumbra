#!/usr/bin/env python3
"""Unit tests for the durable orchestrator journal + crash recovery.

These cover the crash-result-semantics fix: a crash between 'file layer
finalized' and 'process/output released' must resolve to a DETERMINISTIC
result on restart. The tests exercise the pure journal replay logic and the
orchestrator recovery path (constructed via __new__ to avoid needing root /
live daemons), using a fake ShadowFS client.
"""
import os
import tempfile
import threading
import unittest

from shadow_orchestrator import ShadowOrchestrator, _OrchestratorJournal


class FakeFsClient:
    """Minimal ShadowFS client double: records requests, returns canned replies."""

    def __init__(self, can_release=True):
        self.requests = []
        self._can_release = can_release

    def request(self, req):
        self.requests.append(req)
        action = req.get("action")
        if action == "can_release":
            return {"status": "ok", "releasable": self._can_release}
        return {"status": "ok"}


def _new_orch(journal_path, fs_client=None):
    """Build a bare ShadowOrchestrator with just the journal machinery wired,
    bypassing __init__ (which would connect to live daemons)."""
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch._sessions = {}
    orch._sessions_lock = threading.Lock()
    orch._recovered_outputs = {}
    orch._journal = _OrchestratorJournal(journal_path)
    orch.fs_client = fs_client or FakeFsClient()
    orch._proxy = None
    return orch


class TestJournalReplay(unittest.TestCase):
    def test_open_close_tracking(self):
        recs = [
            {"op": "open", "sid": "s1", "cgroup": "/cg1"},
            {"op": "open", "sid": "s2", "cgroup": "/cg2"},
            {"op": "close", "sid": "s1"},
        ]
        state = _OrchestratorJournal.replay(recs)
        self.assertEqual(state["sessions"], {"s2": "/cg2"})
        self.assertEqual(state["committed"], {})
        self.assertEqual(state["undecided"], {})

    def test_fs_committed_without_done_is_committed_pending(self):
        # Crash AFTER fs_committed but BEFORE commit_done.
        recs = [
            {"op": "open", "sid": "s1", "cgroup": "/cg1"},
            {"op": "commit_intent", "sid": "s1", "cgroup": "/cg1"},
            {"op": "fs_committed", "sid": "s1", "cgroup": "/cg1", "output": "RESULT"},
        ]
        state = _OrchestratorJournal.replay(recs)
        self.assertEqual(state["committed"], {"s1": ("/cg1", "RESULT")})
        self.assertEqual(state["undecided"], {})

    def test_commit_done_is_not_pending(self):
        recs = [
            {"op": "open", "sid": "s1", "cgroup": "/cg1"},
            {"op": "commit_intent", "sid": "s1", "cgroup": "/cg1"},
            {"op": "fs_committed", "sid": "s1", "cgroup": "/cg1", "output": "R"},
            {"op": "commit_done", "sid": "s1", "cgroup": "/cg1"},
        ]
        state = _OrchestratorJournal.replay(recs)
        self.assertEqual(state["committed"], {})
        self.assertEqual(state["undecided"], {})

    def test_intent_without_fs_is_undecided(self):
        # Crash AFTER commit_intent but BEFORE fs_committed.
        recs = [
            {"op": "open", "sid": "s1", "cgroup": "/cg1"},
            {"op": "commit_intent", "sid": "s1", "cgroup": "/cg1"},
        ]
        state = _OrchestratorJournal.replay(recs)
        self.assertEqual(state["committed"], {})
        self.assertEqual(state["undecided"], {"s1": "/cg1"})

    def test_rollback_clears_commit(self):
        recs = [
            {"op": "open", "sid": "s1", "cgroup": "/cg1"},
            {"op": "commit_intent", "sid": "s1", "cgroup": "/cg1"},
            {"op": "fs_committed", "sid": "s1", "cgroup": "/cg1", "output": "R"},
            {"op": "rollback", "sid": "s1", "cgroup": "/cg1"},
        ]
        state = _OrchestratorJournal.replay(recs)
        self.assertEqual(state["committed"], {})
        self.assertEqual(state["undecided"], {})


class TestJournalIO(unittest.TestCase):
    def test_append_load_roundtrip_and_torn_tail(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "j.jsonl")
            j = _OrchestratorJournal(p)
            j.append("open", sid="s1", cgroup="/cg1")
            j.append("fs_committed", sid="s1", cgroup="/cg1", output="R")
            # Simulate a torn final record from a crash mid-write.
            with open(p, "a") as f:
                f.write('{"op": "commit_done", "sid": "s1"')  # no newline / cut
            recs = j.load()
            # The torn record is dropped; the two good ones survive.
            self.assertEqual(len(recs), 2)
            self.assertEqual(recs[0]["op"], "open")
            self.assertEqual(recs[1]["op"], "fs_committed")

    def test_rewrite_compaction(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "j.jsonl")
            j = _OrchestratorJournal(p)
            for i in range(10):
                j.append("open", sid=f"s{i}", cgroup=f"/cg{i}")
            j.rewrite([{"op": "open", "sid": "keep", "cgroup": "/cgk"}])
            recs = j.load()
            self.assertEqual(recs, [{"op": "open", "sid": "keep", "cgroup": "/cgk"}])


class TestRecovery(unittest.TestCase):
    def test_fs_committed_recovers_as_committed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "j.jsonl")
            # Pre-seed a journal as if a crash happened right after fs_committed.
            seed = _OrchestratorJournal(p)
            seed.append("open", sid="s1", cgroup="/cg1")
            seed.append("commit_intent", sid="s1", cgroup="/cg1")
            seed.append("fs_committed", sid="s1", cgroup="/cg1", output="COMMITTED-OUT")

            fs = FakeFsClient(can_release=True)
            orch = _new_orch(p, fs)
            orch._recover_from_journal()

            # Session map restored; committed transcript recovered.
            self.assertEqual(orch._sessions, {"s1": "/cg1"})
            self.assertEqual(orch._recovered_outputs["s1"], "COMMITTED-OUT")
            # Recovery nudged ShadowFS to finish finalizing the committed state.
            self.assertTrue(any(r.get("action") == "retry_finalize"
                                and r.get("cgroup_id") == "/cg1"
                                for r in fs.requests))
            # A commit_done was journaled so a second recovery is a no-op.
            state2 = _OrchestratorJournal.replay(orch._journal.load())
            self.assertEqual(state2["committed"], {})

    def test_get_output_falls_back_to_recovered(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "j.jsonl")
            orch = _new_orch(p)
            orch._recovered_outputs["s1"] = "RECOVERED"

            class DeadProxy:
                def get_output(self, sid):
                    raise KeyError(sid)  # live session did not survive the crash

            orch._proxy = DeadProxy()
            resp = orch.session_get_output("s1")
            self.assertEqual(resp["status"], "ok")
            self.assertEqual(resp["output"], "RECOVERED")
            self.assertTrue(resp.get("recovered"))

    def test_undecided_without_fs_is_not_committed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "j.jsonl")
            seed = _OrchestratorJournal(p)
            seed.append("open", sid="s1", cgroup="/cg1")
            seed.append("commit_intent", sid="s1", cgroup="/cg1")

            fs = FakeFsClient(can_release=False)  # FS did not finalize
            orch = _new_orch(p, fs)
            orch._recover_from_journal()

            # No committed output is fabricated for an undecided epoch.
            self.assertNotIn("s1", orch._recovered_outputs)
            self.assertEqual(orch._sessions, {"s1": "/cg1"})


if __name__ == "__main__":
    unittest.main()
