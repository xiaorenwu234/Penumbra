#!/usr/bin/env python3
"""
Unit tests for the RQ3 scalability observation surface.

The multi-agent and dependency-graph scaling experiments report their numbers
through three additions to the orchestrator:

  * _fs_group_finalize(..., timings=tm) — the per-phase breakdown of turning an
    authorization into a durably published group, including the
    authorization-completion → finalization interval and the graph-revalidation
    count;
  * graph_stats(reset) — passthrough to ShadowFS's dependency-graph counters;
  * epoch_states() — the per-epoch state machine position that list_agents()
    deliberately drops.

These are measurement paths, so the tests assert on what an experiment is
allowed to rely on: every documented key is present, the keys are numeric and
non-negative, a stale graph_generation is COUNTED (not just logged), reset is
forwarded verbatim, and the commit/rollback wrappers attach `timings` even on
their failure returns (the authorized_pending return is precisely the one the
SCC experiment polls).

No live services are needed: the orchestrator is built without its __init__ and
fed fake clients with programmable responses, matching the other suites here.
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch.proc_client = FakeClient(proc_handler)
    orch.fs_client = FakeClient(fs_handler)
    orch._graph_sequence_lock = threading.Lock()
    orch._pending_release = set()
    orch._pending_lock = threading.Lock()
    orch._pending_ack = set()
    orch._pending_ack_lock = threading.Lock()
    orch._release_lock = threading.RLock()
    return orch


def _proc_ok(req):
    if req["action"] == "freeze_by_cgroup":
        return {"status": "ok", "frozen": [10]}
    return {"status": "ok"}


# Every phase the experiments are documented to read off a commit. A missing
# key would silently become a missing column in the results table.
FINALIZE_PHASES = (
    "fs_authorize_ms",
    "fs_prepare_resolution_ms",
    "fs_freeze_ms",
    "fs_begin_finalize_ms",
    "fs_wait_finalized_ms",
    "authz_to_finalized_ms",
    "finalize_lock_wait_ms",
    "finalize_lock_held_ms",
    "finalize_polls",
)


class TestGroupFinalizeTimings(unittest.TestCase):
    """_fs_group_finalize fills the caller's timings dict in place."""

    def _fs(self, begin_finalize_responses):
        """FS handler whose begin_finalize returns the queued responses in order."""
        queue = list(begin_finalize_responses)

        def handler(req):
            a = req["action"]
            if a == "authorize":
                return {"status": "ok", "epoch_id": "ep-A",
                        "policy_hash": req.get("policy_hash", "")}
            if a == "prepare_resolution":
                return {"status": "ok", "group_id": 1, "members": ["ep-A"],
                        "graph_generation": 7}
            if a == "begin_finalize":
                return queue.pop(0) if queue else {"status": "ok",
                                                   "state": "finalized"}
            if a == "get_finalize_status":
                return {"status": "ok", "state": "finalized"}
            return {"status": "ok"}

        return handler

    def test_happy_path_stamps_every_phase(self):
        orch = _bare_orch(_proc_ok,
                          self._fs([{"status": "ok", "state": "finalized"}]))
        tm = {}
        res = orch._fs_group_finalize("ep-A", "cg-a",
                                      proc_policy={"rules": []}, timings=tm)

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["state"], "finalized")
        for key in FINALIZE_PHASES:
            self.assertIn(key, tm, f"missing timing phase {key}")
            self.assertIsInstance(tm[key], float, f"{key} must be numeric")
            self.assertGreaterEqual(tm[key], 0.0, f"{key} went backwards")
        # BeginFinalize promotes synchronously, so the poll loop must not run:
        # a non-zero wait here would mean the experiment is measuring a sleep.
        self.assertEqual(tm["finalize_polls"], 0.0)
        self.assertLess(tm["fs_wait_finalized_ms"], 1000.0)
        # No mismatch happened, so nothing was revalidated.
        self.assertNotIn("graph_revalidations", tm)

    def test_authz_to_finalized_brackets_the_documented_interval(self):
        """authz_to_finalized_ms covers prepare + freeze + begin + wait."""
        orch = _bare_orch(_proc_ok,
                          self._fs([{"status": "ok", "state": "finalized"}]))
        tm = {}
        orch._fs_group_finalize("ep-A", "cg-a", proc_policy={"rules": []},
                                timings=tm)

        inner = (tm["fs_prepare_resolution_ms"] + tm["fs_freeze_ms"]
                 + tm["fs_begin_finalize_ms"] + tm["fs_wait_finalized_ms"])
        # Rounding to 3 decimals per stamp means the sum of parts can exceed
        # the whole by at most a few tens of microseconds.
        self.assertGreaterEqual(tm["authz_to_finalized_ms"] + 0.01, inner)
        # And it must NOT include the authorize RPC that precedes the interval.
        self.assertLessEqual(tm["authz_to_finalized_ms"],
                             tm["finalize_lock_held_ms"] + 0.01)

    def test_timings_are_optional_and_do_not_change_the_result(self):
        """Omitting timings must be a no-op, not a crash."""
        orch = _bare_orch(_proc_ok,
                          self._fs([{"status": "ok", "state": "finalized"}]))
        res = orch._fs_group_finalize("ep-A", "cg-a", proc_policy={"rules": []})
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["state"], "finalized")

    def test_stale_graph_generation_is_counted(self):
        """A TOCTOU refusal must show up in timings, not only in the log.

        This is the orchestrator-visible half of graph revalidation; ShadowFS
        counts its own half in finalize_rejected_toctou, and the contended
        workload reports both. The refusal is classified by the structured
        err_code, which is the stable contract the orchestrator branches on.
        """
        orch = _bare_orch(_proc_ok, self._fs([
            {"status": "error", "err_code": "toctou_reprepare",
             "message": "begin_finalize: group 3 is no longer atomic "
                        "(prepared members=[ep-A] at graph_generation=7, "
                        "caller=8): its SCC membership changed, "
                        "re-prepare required (TOCTOU)"},
            {"status": "ok", "state": "finalized"},
        ]))
        tm = {}
        res = orch._fs_group_finalize("ep-A", "cg-a",
                                      proc_policy={"rules": []}, timings=tm)

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["state"], "finalized",
                         "the retry with the fresh generation must succeed")
        self.assertEqual(tm.get("graph_revalidations"), 1.0)
        self.assertEqual(orch.fs_client.actions().count("begin_finalize"), 2)
        self.assertEqual(orch.fs_client.actions().count("prepare_resolution"), 2)

    def test_current_backend_wording_without_err_code_still_reprepares(self):
        """Regression: the reworded refusal must re-prepare even with no code.

        Publication once wedged because the backend changed its TOCTOU message
        to "no longer atomic ... re-prepare required" while the orchestrator
        still matched only the retired "graph_generation mismatch" wording, so
        the re-prepare branch became dead code and every refusal was returned
        as a hard error. An out-of-date daemon that omits err_code must still
        be recognised by the message fallback.
        """
        orch = _bare_orch(_proc_ok, self._fs([
            {"status": "error",
             "message": "begin_finalize: group 3 is no longer atomic "
                        "(prepared members=[ep-A] at graph_generation=7, "
                        "caller=8): its SCC membership changed, "
                        "re-prepare required (TOCTOU)"},
            {"status": "ok", "state": "finalized"},
        ]))
        tm = {}
        res = orch._fs_group_finalize("ep-A", "cg-a",
                                      proc_policy={"rules": []}, timings=tm)

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["state"], "finalized")
        self.assertEqual(tm.get("graph_revalidations"), 1.0)
        self.assertEqual(orch.fs_client.actions().count("prepare_resolution"), 2)

    def test_waiting_for_a_sibling_reports_zero_finalized_wait(self):
        """authorized_pending (SCC sibling not yet authorized) returns early.

        The experiment distinguishes that case by `state`, so the early return
        must still carry the phases it did reach — authorize and prepare ran,
        the group simply could not be finalized yet.
        """
        def fs(req):
            a = req["action"]
            if a == "authorize":
                return {"status": "ok", "epoch_id": "ep-A",
                        "policy_hash": req.get("policy_hash", "")}
            if a == "prepare_resolution":
                # Two-member SCC, but only ep-A was authorized by this thread.
                return {"status": "ok", "group_id": 3,
                        "members": ["ep-A", "ep-B"], "graph_generation": 9}
            return {"status": "ok"}

        orch = _bare_orch(_proc_ok, fs)
        tm = {}
        res = orch._fs_group_finalize("ep-A", "cg-a",
                                      proc_policy={"rules": []}, timings=tm)

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["state"], "authorized_pending")
        self.assertIn("fs_authorize_ms", tm)
        self.assertIn("fs_prepare_resolution_ms", tm)
        self.assertIn("finalize_lock_held_ms", tm)
        # Nothing was finalized, so the post-lock phases were never reached.
        self.assertNotIn("authz_to_finalized_ms", tm)


class TestGraphStatsPassthrough(unittest.TestCase):
    """graph_stats is a verbatim passthrough: the counters live in ShadowFS."""

    def test_snapshot_does_not_reset(self):
        orch = _bare_orch(_proc_ok, lambda req: {
            "status": "ok",
            "graph": {"epochs": 4, "edges": 3, "edge_insertions": 3},
        })
        res = orch.graph_stats()
        self.assertEqual(orch.fs_client.calls[-1],
                         {"action": "graph_stats", "reset": False})
        self.assertEqual(res["graph"]["edges"], 3)

    def test_reset_flag_is_forwarded(self):
        orch = _bare_orch(_proc_ok, lambda req: {"status": "ok", "graph": {}})
        orch.graph_stats(reset=True)
        self.assertEqual(orch.fs_client.calls[-1],
                         {"action": "graph_stats", "reset": True})

    def test_epoch_states_exposes_the_state_machine(self):
        """list_agents() drops agents_info; epoch_states() must not."""
        orch = _bare_orch(_proc_ok, lambda req: {
            "status": "ok",
            "agents": ["ep-A", "ep-B"],
            "agents_info": [
                {"epoch_id": "ep-A", "state": "finalized", "versions": 1,
                 "cgroup_id": "cg-a", "session_id": "s-a"},
                {"epoch_id": "ep-B", "state": "authorized", "versions": 2,
                 "cgroup_id": "cg-b", "session_id": "s-b"},
            ],
        })
        states = orch.epoch_states()
        self.assertEqual([e["epoch_id"] for e in states], ["ep-A", "ep-B"])
        self.assertEqual(states[1]["state"], "authorized")
        # And list_agents keeps its original ID-only contract.
        self.assertEqual(orch.list_agents(), ["ep-A", "ep-B"])

    def test_epoch_states_tolerates_a_daemon_without_the_field(self):
        orch = _bare_orch(_proc_ok, lambda req: {"status": "ok", "agents": []})
        self.assertEqual(orch.epoch_states(), [])


class TestCommitRollbackTimingWrappers(unittest.TestCase):
    """The wrappers attach `timings` on EVERY return path.

    The experiments read timings off failures too: `authorized_pending` is the
    normal outcome for an SCC member that commits before its siblings, and a
    refused rollback is a data point about cascade cost.
    """

    def test_commit_wrapper_merges_inner_phases_and_adds_total(self):
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)

        def inner(session_id, proc_policy, timings):
            timings["fs_authorize_ms"] = 1.5
            timings["authz_to_finalized_ms"] = 4.0
            return {"status": "ok", "released": True}

        orch._commit_epoch_impl_timed = inner
        res = orch._commit_epoch_impl("s1", proc_policy={"rules": []})

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["timings"]["fs_authorize_ms"], 1.5)
        self.assertEqual(res["timings"]["authz_to_finalized_ms"], 4.0)
        self.assertGreaterEqual(res["timings"]["total_ms"], 0.0)

    def test_commit_wrapper_times_the_authorized_pending_path(self):
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
        orch._commit_epoch_impl_timed = lambda sid, pp, tm: {
            "status": "error", "decision": "authorized_pending",
            "message": "file layer not finalized; epoch kept intact for retry",
        }
        res = orch._commit_epoch_impl("s1", proc_policy={"rules": []})
        self.assertEqual(res["decision"], "authorized_pending")
        self.assertIn("total_ms", res["timings"])

    def test_commit_wrapper_does_not_clobber_an_inner_timings(self):
        """setdefault, not assignment: an inner result wins."""
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
        orch._commit_epoch_impl_timed = lambda sid, pp, tm: {
            "status": "ok", "timings": {"total_ms": 99.0},
        }
        res = orch._commit_epoch_impl("s1", proc_policy={"rules": []})
        self.assertEqual(res["timings"], {"total_ms": 99.0})

    def test_commit_wrapper_survives_a_non_dict_result(self):
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
        orch._commit_epoch_impl_timed = lambda sid, pp, tm: None
        self.assertIsNone(orch._commit_epoch_impl("s1", proc_policy={}))

    def test_rollback_wrapper_reports_the_cascade(self):
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)

        def inner(session_id, timings):
            timings["fs_rollback_ms"] = 2.0
            timings["proc_rollback_ms"] = 1.0
            return {"status": "ok", "affected_epochs": ["ep-A", "ep-B", "ep-C"]}

        orch._rollback_epoch_impl_timed = inner
        res = orch._rollback_epoch_impl("s1")

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["affected_epochs"], ["ep-A", "ep-B", "ep-C"])
        self.assertEqual(res["timings"]["fs_rollback_ms"], 2.0)
        self.assertGreaterEqual(res["timings"]["total_ms"], 0.0)

    def test_rollback_wrapper_times_a_refused_rollback(self):
        orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
        orch._rollback_epoch_impl_timed = lambda sid, tm: {
            "status": "error", "message": "epoch already promoted",
        }
        res = orch._rollback_epoch_impl("s1")
        self.assertEqual(res["status"], "error")
        self.assertIn("total_ms", res["timings"])


class TestBeginEpochTimings(unittest.TestCase):
    """session_begin_epoch reports where epoch-begin latency goes."""

    def test_success_carries_the_phase_breakdown(self):
        orch = _bare_orch(_proc_ok, lambda req: {"status": "ok"})
        # Session/agent bookkeeping normally built by __init__.
        orch._sessions_lock = threading.Lock()
        orch._sessions = {"s1": "cg-a"}
        orch._session_epochs = {}
        orch._session_agents = {"s1": "agent-1"}
        orch._agent_cv = threading.Condition()
        orch._agent_inflight = {}
        orch._agent_wait_timeout = 5.0

        class FakeProxy:
            def begin_epoch(self, session_id):
                return None

        orch._proxy = FakeProxy()
        orch._get_proxy = lambda: orch._proxy
        # ShadowObserve is not configured in this suite; the recorder start is
        # expected to be a no-op.
        orch._session_start_observe = lambda *a, **kw: None

        res = orch.session_begin_epoch("s1", agent_id="agent-1")

        self.assertEqual(res["status"], "ok", res)
        tm = res["timings"]
        for key in ("agent_barrier_ms", "begin_lock_wait_ms",
                    "fs_begin_epoch_ms", "proc_begin_epoch_ms", "total_ms"):
            self.assertIn(key, tm)
            self.assertGreaterEqual(tm[key], 0.0)
        self.assertEqual(orch.fs_client.actions(), ["begin_epoch"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
