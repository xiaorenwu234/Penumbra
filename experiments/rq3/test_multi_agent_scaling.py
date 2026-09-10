#!/usr/bin/env python3
"""Unit tests for the pure logic of the multi-agent scaling experiment.

The experiment itself needs root, three daemons and a FUSE mount, so it cannot
run in a test suite. What CAN be tested -- and what silently ruins a scaling
curve when it is wrong -- is the part that decides what is measured:

  * the workload layouts, because "independent" that accidentally shares a file
    is not independent and "partially shared" without a real pair measures
    nothing;
  * the exact expected cascade sets, because a verification that accepts any
    affected set cannot distinguish a chain from a star from an empty graph;
  * the derived figures (edges per invocation, insertion latency), because they
    are ratios the paper quotes directly;
  * the branch-preservation check, because it must FAIL when an unrelated agent
    is collateral damage -- a correctness check that passes on a broken system
    is worse than no check;
  * the epoch lifecycle of the rollback and insertion phases, because an epoch
    left unresolved does not merely lose its own sample -- it blocks the
    barrier and the finalization of everything the run does afterwards.

Run: python3 -m unittest discover -s experiments/rq3 -p "test_multi_agent*.py" -t .
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import multi_agent_scaling as mas


# ─── fakes ─────────────────────────────────────────────────────────────────

class FakeObs:
    """Stand-in for the observation OrchClient (get_affected / epoch_states)."""

    def __init__(self, affected=None, alive_epochs=(), raise_on=(), graph=None):
        self.affected = affected or {}
        self.alive = set(alive_epochs)
        self.raise_on = set(raise_on)
        self.affected_calls = []
        self.graph = graph if graph is not None else {}

    def graph_stats(self, reset=False):
        return dict(self.graph)

    def get_affected(self, cgroup_id):
        self.affected_calls.append(cgroup_id)
        if cgroup_id in self.raise_on:
            raise RuntimeError("get_affected blew up")
        return {"status": "ok", "affected": sorted(self.affected.get(cgroup_id, []))}

    def epoch_states(self):
        return [{"epoch_id": e, "state": "active"} for e in sorted(self.alive)]


class FakeAgentClient:
    """Stand-in for one agent's own socket connection.

    The barrier is modelled, and that is the point: the orchestrator releases an
    agent's slot ONLY on a commit or a rollback, so a second begin_epoch for the
    same agent waits out the timeout and fails with agent_busy. A fake that lets
    one agent hold two epochs at once is more permissive than the system it
    stands for, and that slack is precisely where the rollback-loop bug hid.
    """

    def __init__(self, rollback=None, commit=None, barrier=True,
                 begin_ns=111, run_ns=222):
        self.rollback = rollback if rollback is not None else {"status": "ok",
                                                               "affected_epochs": ["ep"]}
        self.commit = commit if commit is not None else {"status": "ok"}
        self.requests = []
        self.barrier = barrier
        self.begin_ns = begin_ns
        self.run_ns = run_ns
        self.slot_open = False     # an epoch is in flight: the slot is claimed
        self.barrier_hits = 0
        self.begins = 0
        self.runs = []
        self.rollbacks = 0
        self.commits = 0

    def _or_raise(self, resp, action):
        """request_ok's contract: a non-ok status is an exception, not a value."""
        if resp.get("status") != "ok":
            raise RuntimeError(f"Orchestrator {action} failed: "
                               f"{resp.get('message', resp)}")
        return resp

    def request(self, req):
        self.requests.append(req)
        action = req.get("action")
        if action == "session_rollback_epoch":
            self.rollbacks += 1
            self.slot_open = False        # the barrier releases here ...
            return dict(self.rollback)
        if action == "session_commit_epoch":
            self.commits += 1
            self.slot_open = False        # ... and here, and nowhere else
            return dict(self.commit)
        return {"status": "ok"}

    def timed_begin_epoch(self, session_id, agent_id):
        if self.barrier and self.slot_open:
            self.barrier_hits += 1
            resp = {"status": "error", "agent_busy": True,
                    "message": (f"agent {agent_id} still has a tool call "
                                f"in flight")}
        else:
            self.slot_open = True
            self.begins += 1
            resp = {"status": "ok", "epoch_id": f"ep-{self.begins}",
                    "timings": {}}
        return self._or_raise(resp, "session_begin_epoch"), self.begin_ns

    def timed_run(self, session_id, command):
        self.runs.append(command)
        return {"status": "ok", "output": "", "exit_code": 0}, self.run_ns


def make_handles(n, workload="independent"):
    """Handles shaped like open_agent()'s return value, epochs pre-assigned."""
    out = []
    for i in range(n):
        out.append({"idx": i, "agent_id": f"mas-t-a{i}", "session_id": f"s{i}",
                    "cgroup_id": f"cg{i}", "epoch_id": f"ep{i}",
                    "client": FakeAgentClient(), "error": None, "open_ns": 0})
    return out


def make_result(workload="independent", agents=1):
    return mas.ScalingResult(workload=workload, agents=agents, repeats=1,
                             invocations_per_agent=1,
                             rollback_invocations_per_agent=0)


# ─── workload layout ───────────────────────────────────────────────────────

class TestWorkloadLayout(unittest.TestCase):

    def test_independent_files_are_disjoint(self):
        """No two agents may touch the same file, or the workload is not
        independent and the "linear scaling" claim measures contention."""
        seen = {}
        for i in range(8):
            reads, writes = mas.agent_files("independent", i, 8)
            # An agent reads back the file it writes; that is one file, not a
            # shared one, so deduplicate within the agent before comparing.
            for f in set(reads) | set(writes):
                self.assertNotIn(f, seen,
                                 f"{f} shared by agents {seen.get(f)} and {i}")
                seen[f] = i
        self.assertEqual(len(seen), 8)

    def test_partially_shared_pairs_producer_and_consumer(self):
        # A writes x, B reads x and writes y -- the user's specification.
        self.assertEqual(mas.agent_files("partially_shared", 0, 4),
                         (["x_0.dat"], ["x_0.dat"]))
        self.assertEqual(mas.agent_files("partially_shared", 1, 4),
                         (["x_0.dat"], ["y_0.dat"]))
        self.assertEqual(mas.agent_files("partially_shared", 2, 4),
                         (["x_1.dat"], ["x_1.dat"]))
        self.assertEqual(mas.agent_files("partially_shared", 3, 4),
                         (["x_1.dat"], ["y_1.dat"]))

    def test_partially_shared_trailing_agent_is_independent(self):
        """With an odd agent count the last agent is the 'E independent' branch:
        it must not read or write either pair's files."""
        reads, writes = mas.agent_files("partially_shared", 4, 5)
        self.assertEqual((reads, writes), (["solo.dat"], ["solo.dat"]))
        self.assertEqual(mas.agent_role("partially_shared", 4, 5), "independent")
        # An even count has no trailing agent.
        self.assertEqual(mas.agent_role("partially_shared", 3, 4), "consumer")

    def test_partially_shared_pairs_do_not_cross(self):
        """Each pair owns its own x/y files: a file touched by two pairs would
        couple branches the workload claims are independent."""
        for n in (2, 4, 6, 8):
            pair_files = {}
            for i in range(n):
                reads, writes = mas.agent_files("partially_shared", i, n)
                for f in set(reads) | set(writes):
                    if f == "solo.dat":
                        continue
                    pair_files.setdefault(f, set()).add(i // 2)
            self.assertEqual(len(pair_files), n, f"n={n}: {sorted(pair_files)}")
            for f, pairs in pair_files.items():
                self.assertEqual(len(pairs), 1,
                                 f"{f} touched by pairs {pairs} at n={n}")

    def test_contended_every_agent_reads_whole_shared_set(self):
        for n in (4, 8, 32):
            shared = min(mas.SHARED_FILES, n)
            for i in range(n):
                reads, writes = mas.agent_files("contended", i, n)
                self.assertEqual(len(reads), shared)
                self.assertEqual(len(set(reads)), shared)
                # Every write lands inside the shared set: no private escape
                # hatch that would silently lower the contention.
                for w in writes:
                    self.assertIn(w, reads)

    def test_contended_shrinks_shared_set_below_four_agents(self):
        reads, writes = mas.agent_files("contended", 0, 2)
        self.assertEqual(reads, ["sh_0.dat", "sh_1.dat"])
        self.assertEqual(writes, ["sh_0.dat"])

    def test_seed_files_cover_every_touched_file(self):
        """A file an agent reads but that was never seeded fails FUSE Lookup
        with ENOENT before Resolve() can record the read-from edge."""
        for workload in mas.WORKLOADS:
            for n in (1, 2, 3, 5, 8):
                seeds = set(mas.seed_files(workload, n))
                for i in range(n):
                    reads, writes = mas.agent_files(workload, i, n)
                    for f in reads + writes:
                        self.assertIn(f, seeds,
                                      f"{workload} n={n} agent{i}: {f} unseeded")

    def test_invocation_body_reads_before_writing(self):
        """Read-then-write: an agent that wrote first would read its own
        version and form no edge, flattening the very curve being measured."""
        cmds = mas.invocation_commands("partially_shared", 1, 4, 3)
        self.assertTrue(cmds[0].startswith("cat "), cmds)
        self.assertTrue(cmds[-1].startswith("echo "), cmds)
        self.assertIn("x_0.dat", cmds[0])
        self.assertIn("y_0.dat", cmds[-1])

    def test_unknown_workload_is_rejected(self):
        with self.assertRaises(ValueError):
            mas.agent_files("telepathic", 0, 2)


# ─── exact expected cascade sets ───────────────────────────────────────────

class TestExpectedAffected(unittest.TestCase):

    def test_independent_agent_only_affects_itself(self):
        handles = make_handles(4)
        for i in range(4):
            self.assertEqual(mas.expected_affected("independent", i, 4, handles),
                             {f"cg{i}"})

    def test_producer_carries_consumer_but_not_the_reverse(self):
        handles = make_handles(4)
        self.assertEqual(mas.expected_affected("partially_shared", 0, 4, handles),
                         {"cg0", "cg1"})
        self.assertEqual(mas.expected_affected("partially_shared", 1, 4, handles),
                         {"cg1"})

    def test_last_producer_without_consumer_affects_only_itself(self):
        handles = make_handles(3)
        self.assertEqual(mas.expected_affected("partially_shared", 2, 3, handles),
                         {"cg2"})

    def test_contended_returns_none_because_it_is_not_constructed(self):
        """Asserting an exact set for a graph the experiment did not build
        deterministically would be a check that passes by luck."""
        self.assertIsNone(mas.expected_affected("contended", 0, 4, make_handles(4)))


class TestVerifyAffectedSets(unittest.TestCase):

    def test_exact_pass(self):
        handles = make_handles(2)
        obs = FakeObs(affected={"cg0": {"cg0", "cg1"}, "cg1": {"cg1"}})
        ok, errors, detail = mas.verify_affected_sets(
            obs, "partially_shared", 2, handles)
        self.assertTrue(ok, errors)
        self.assertEqual(detail["max_affected"], 2)
        self.assertTrue(detail["union_covers_all"])

    def test_missing_dependency_edge_is_detected(self):
        """The producer's cascade set omits its consumer: the read-from edge
        never formed, so every latency measured on this graph is a no-dependency
        baseline masquerading as a dependency result."""
        handles = make_handles(2)
        obs = FakeObs(affected={"cg0": {"cg0"}, "cg1": {"cg1"}})
        ok, errors, _ = mas.verify_affected_sets(
            obs, "partially_shared", 2, handles)
        self.assertFalse(ok)
        self.assertTrue(any("agent0" in e for e in errors), errors)

    def test_extra_coupling_is_detected(self):
        """An over-broad cascade set is a correctness bug too: rollback would
        destroy work that does not depend on the rolled-back epoch."""
        handles = make_handles(4)
        obs = FakeObs(affected={"cg0": {"cg0"}, "cg1": {"cg1"},
                                "cg2": {"cg2", "cg0"}, "cg3": {"cg3"}})
        ok, errors, _ = mas.verify_affected_sets(
            obs, "independent", 4, handles)
        self.assertFalse(ok)
        self.assertTrue(any("agent2" in e for e in errors), errors)

    def test_own_cgroup_missing_is_detected(self):
        handles = make_handles(2)
        obs = FakeObs(affected={"cg0": {"cg1"}, "cg1": {"cg1"}})
        ok, errors, _ = mas.verify_affected_sets(
            obs, "partially_shared", 2, handles)
        self.assertFalse(ok)
        self.assertTrue(any("own cgroup missing" in e for e in errors), errors)

    def test_contended_requires_real_coupling(self):
        """Every agent affecting only itself means the shared set produced no
        edges at all -- the worst case would not have been exercised."""
        handles = make_handles(4)
        obs = FakeObs(affected={f"cg{i}": {f"cg{i}"} for i in range(4)})
        ok, errors, detail = mas.verify_affected_sets(
            obs, "contended", 4, handles)
        self.assertFalse(ok)
        self.assertTrue(any("no agent is coupled" in e for e in errors), errors)
        self.assertEqual(detail["max_affected"], 1)

    def test_contended_passes_on_coupled_graph(self):
        handles = make_handles(4)
        obs = FakeObs(affected={
            "cg0": {"cg0", "cg3"}, "cg1": {"cg1", "cg3"},
            "cg2": {"cg2", "cg3"}, "cg3": {"cg0", "cg1", "cg2", "cg3"}})
        ok, errors, detail = mas.verify_affected_sets(
            obs, "contended", 4, handles)
        self.assertTrue(ok, errors)
        self.assertEqual(detail["max_affected"], 4)
        self.assertTrue(detail["union_covers_all"])

    def test_unreachable_get_affected_is_an_error_not_a_pass(self):
        handles = make_handles(2)
        obs = FakeObs(affected={"cg1": {"cg1"}}, raise_on={"cg0"})
        ok, errors, _ = mas.verify_affected_sets(
            obs, "partially_shared", 2, handles)
        self.assertFalse(ok)
        self.assertTrue(any("get_affected(agent0)" in e for e in errors), errors)


# ─── branch preservation ───────────────────────────────────────────────────

class TestBranchPreservation(unittest.TestCase):

    def _result(self):
        return mas.ScalingResult(workload="partially_shared", agents=3)

    def test_passes_when_only_the_victim_leaves(self):
        handles = make_handles(3, "partially_shared")
        handles[1]["client"].rollback = {"status": "ok", "affected_epochs": ["ep1"]}
        obs = FakeObs(affected={"cg0": {"cg0"}},
                      alive_epochs={"ep0", "ep2"})
        res = self._result()
        mas.verify_branch_preservation(obs, "partially_shared", 3, handles, res)
        self.assertTrue(res.branch_preservation_ok, res.branch_errors)
        # The two survivors must both have been committed.
        for idx in (0, 2):
            self.assertTrue(any(r.get("action") == "session_commit_epoch"
                                for r in handles[idx]["client"].requests),
                            f"agent{idx} was never committed")

    def test_fails_when_an_unrelated_agent_is_collateral_damage(self):
        """The independent agent's epoch vanished with the consumer's: the
        cascade followed something other than the dependency edges."""
        handles = make_handles(3, "partially_shared")
        handles[1]["client"].rollback = {"status": "ok",
                                         "affected_epochs": ["ep1", "ep2"]}
        obs = FakeObs(affected={"cg0": {"cg0"}}, alive_epochs={"ep0"})
        res = self._result()
        mas.verify_branch_preservation(obs, "partially_shared", 3, handles, res)
        self.assertFalse(res.branch_preservation_ok)
        self.assertTrue(any("agent2" in e for e in res.branch_errors),
                        res.branch_errors)
        self.assertTrue(any("cascaded to 2 epochs" in e
                            for e in res.branch_errors), res.branch_errors)

    def test_fails_when_the_victim_survives_its_own_rollback(self):
        handles = make_handles(2, "partially_shared")
        obs = FakeObs(affected={"cg0": {"cg0"}}, alive_epochs={"ep0", "ep1"})
        res = self._result()
        mas.verify_branch_preservation(obs, "partially_shared", 2, handles, res)
        self.assertFalse(res.branch_preservation_ok)
        self.assertTrue(any("still in the graph" in e for e in res.branch_errors),
                        res.branch_errors)

    def test_fails_when_producer_keeps_the_edge_to_a_dead_consumer(self):
        handles = make_handles(2, "partially_shared")
        obs = FakeObs(affected={"cg0": {"cg0", "cg1"}}, alive_epochs={"ep0"})
        res = self._result()
        mas.verify_branch_preservation(obs, "partially_shared", 2, handles, res)
        self.assertFalse(res.branch_preservation_ok)
        self.assertTrue(any("producer affected set is 2" in e
                            for e in res.branch_errors), res.branch_errors)

    def test_fails_when_a_survivor_cannot_publish(self):
        handles = make_handles(2, "partially_shared")
        handles[0]["client"].commit = {"status": "error",
                                       "message": "group stuck"}
        obs = FakeObs(affected={"cg0": {"cg0"}}, alive_epochs={"ep0"})
        res = self._result()
        mas.verify_branch_preservation(obs, "partially_shared", 2, handles, res)
        self.assertFalse(res.branch_preservation_ok)
        self.assertTrue(any("commit after unrelated rollback" in e
                            for e in res.branch_errors), res.branch_errors)

    def test_not_applicable_for_contended_and_single_agent(self):
        handles = make_handles(2)
        res = mas.ScalingResult(workload="contended", agents=2)
        mas.verify_branch_preservation(FakeObs(), "contended", 2, handles, res)
        self.assertIsNone(res.branch_preservation_ok)
        self.assertTrue(any("couples every agent" in e for e in res.branch_errors))

        res1 = mas.ScalingResult(workload="independent", agents=1)
        mas.verify_branch_preservation(FakeObs(), "independent", 1,
                                       make_handles(1), res1)
        self.assertIsNone(res1.branch_preservation_ok)

    def test_independent_victim_is_agent_zero(self):
        handles = make_handles(3, "independent")
        obs = FakeObs(affected={}, alive_epochs={"ep1", "ep2"})
        res = mas.ScalingResult(workload="independent", agents=3)
        mas.verify_branch_preservation(obs, "independent", 3, handles, res)
        self.assertTrue(res.branch_preservation_ok, res.branch_errors)
        self.assertTrue(handles[0]["client"].requests,
                        "the independent victim was never rolled back")


# ─── derived figures ───────────────────────────────────────────────────────

class TestDerivedMetrics(unittest.TestCase):

    def _filled(self, **kw):
        r = mas.ScalingResult(workload="independent", agents=4, **kw)
        return r

    def test_edges_per_invocation_divides_by_completed_invocations_only(self):
        r = self._filled()
        r.invocations_ok = [80, 70]        # 150 invocations actually measured
        r.graph = {"edge_insertions": 300}
        self.assertAlmostEqual(r.edges_per_invocation, 2.0)

    def test_edges_per_invocation_none_without_invocations(self):
        r = self._filled()
        r.graph = {"edge_insertions": 12}
        self.assertIsNone(r.edges_per_invocation)

    def test_insertion_latency_is_median_difference(self):
        r = self._filled()
        # Medians, not means: one stalled probe must not become the headline.
        r.edge_run_ns = [1e7, 1.2e7, 5e8]
        r.noedge_run_ns = [9e6, 1.0e7, 4e8]
        self.assertAlmostEqual(r.insertion_latency_ns, 2e6)

    def test_insertion_latency_none_until_both_sides_measured(self):
        r = self._filled()
        r.edge_run_ns = [1e7]
        self.assertIsNone(r.insertion_latency_ns)

    def test_daemon_side_per_edge_cost(self):
        r = self._filled()
        r.graph = {"edge_insertions": 10, "edge_insert_ns": 4_000_000}
        self.assertAlmostEqual(r.daemon_edge_insert_ns, 400_000.0)

    def test_probe_verification_flags_a_control_that_formed_edges(self):
        r = self._filled()
        r.probe_probes = r.control_probes = 5
        r.probe_edges = 5
        r.control_edges = 0
        self.assertTrue(r.to_dict()["insertion_probe"]["verified"])
        r.control_edges = 2      # reads of a finalized version formed edges
        self.assertFalse(r.to_dict()["insertion_probe"]["verified"])
        r.control_edges = 0
        r.probe_edges = 3        # two probes silently formed no edge
        self.assertFalse(r.to_dict()["insertion_probe"]["verified"])

    def test_to_dict_reports_modelled_graph_overhead(self):
        r = self._filled()
        r.invocations_ok = [100]
        r.graph = {"edge_insertions": 50, "edge_insert_ns": 50 * 400_000}
        d = r.to_dict()
        self.assertAlmostEqual(d["edges_per_invocation"], 0.5)
        self.assertAlmostEqual(d["insertion_latency_ns_daemon"], 400_000.0)
        self.assertAlmostEqual(d["modelled_graph_overhead_us_per_invocation"], 200.0)

    def test_to_dict_survives_an_empty_result(self):
        """A configuration that failed at session_open still has to serialize,
        or one bad row loses the whole results file."""
        d = self._filled().to_dict()
        self.assertEqual(d["total_invocations"], 0)
        self.assertIsNone(d["edges_per_invocation"])
        self.assertEqual(d["stats"], {})
        self.assertIsNone(d["structure"]["ok"])

    def test_merge_timings_discovers_keys_and_ignores_non_numbers(self):
        dst = {}
        mas._merge_timings(dst, {"total_ms": 1.5, "fs_ack_ms": 2})
        mas._merge_timings(dst, {"total_ms": 2.5, "released": True,
                                 "message": "x", "group_id": None})
        self.assertEqual(sorted(dst), ["fs_ack_ms", "total_ms"])
        self.assertEqual(dst["total_ms"], [1.5, 2.5])
        self.assertEqual(dst["fs_ack_ms"], [2.0])

    def test_ms_stats_report_milliseconds(self):
        s = mas._ms_stats("x", [1.0, 2.0, 3.0])
        self.assertAlmostEqual(s["median_ms"], 2.0)
        self.assertIsNone(mas._ms_stats("x", []))


# ─── epoch lifecycle: the rollback phase ───────────────────────────────────

class TestRollbackLoopStartsFromTheOpenGraph(unittest.TestCase):
    """phase_rollback wires a real graph with build_open_graph, which leaves
    every agent's epoch OPEN on purpose: ShadowFS records a read-from edge only
    against a version that is still live and unfinalized. The orchestrator
    releases the agent's barrier slot only on a commit or a rollback, so a loop
    that begins a FRESH epoch first queues behind the open one for the full 30s
    timeout, on every iteration, and returns zero samples -- while looking
    merely slow rather than broken.
    """

    def _opened(self):
        """One agent in the state build_open_graph leaves it in."""
        h = make_handles(1)[0]
        h["client"].timed_begin_epoch(h["session_id"], h["agent_id"])
        return h

    # Commands per rollback iteration, so the run counts below are stated in
    # iterations rather than in whatever this workload happens to emit.
    PER_ITER = len(mas.invocation_commands("independent", 0, 1, 1001))

    def test_the_first_rollback_undoes_the_epoch_that_is_already_open(self):
        h = self._opened()
        out = mas._agent_rollback_loop(h, "independent", 1, invocations=2)
        self.assertEqual(h["client"].barrier_hits, 0,
                         "began a second epoch while the agent's slot was taken")
        self.assertEqual(out["failed"], 0)
        self.assertEqual(out["errors"], [])
        self.assertEqual(len(out["rollback_ns"]), 2)
        self.assertEqual(len(out["affected"]), 2)
        # The open epoch is rolled back rather than begun again: one begin and
        # one iteration's worth of commands, both belonging to k=1.
        self.assertEqual(h["client"].begins, 2)
        self.assertEqual(len(h["client"].runs), self.PER_ITER)
        self.assertEqual(h["client"].rollbacks, 2)

    def test_with_no_open_epoch_every_iteration_sets_up_its_own(self):
        """The flag must not simply suppress the first begin -- a phase that did
        not build a graph still has to set its own epochs up."""
        h = make_handles(1)[0]
        out = mas._agent_rollback_loop(h, "independent", 1, invocations=2,
                                       first_epoch_open=False)
        self.assertEqual(h["client"].begins, 2)
        self.assertEqual(len(h["client"].runs), 2 * self.PER_ITER)
        self.assertEqual(len(out["rollback_ns"]), 2)
        self.assertEqual(h["client"].barrier_hits, 0)

    def test_a_refused_begin_is_a_counted_failure_not_a_silent_zero(self):
        """The failure mode as it was reported: the open epoch is never undone,
        so every iteration is refused and the phase still returns normally,
        leaving an empty rollback column and no obvious cause."""
        h = self._opened()
        out = mas._agent_rollback_loop(h, "independent", 1, invocations=2,
                                       first_epoch_open=False)
        self.assertEqual(out["failed"], 2)
        self.assertEqual(out["rollback_ns"], [])
        self.assertEqual(len(out["errors"]), 2)
        self.assertIn("in flight", out["errors"][0])
        self.assertEqual(h["client"].barrier_hits, 2)


# ─── epoch lifecycle: the insertion probe ──────────────────────────────────

class TestProbeReadResolvesNothingItDependsOn(unittest.TestCase):
    """The probe reads a version whose producer epoch is DELIBERATELY still open
    -- that is the only condition under which the read forms an edge. Committing
    the reader therefore asks the system to publish a consumer ahead of the
    writer it read from, which dependency-safe publication refuses: the group
    parks, each retry costs the server's 30s finalize poll, and a single `cat`
    consumes the whole pending budget.
    """

    def _probe(self, client=None):
        client = client if client is not None else FakeAgentClient()
        h = {"idx": 9100, "agent_id": "mas-t-ie-a9100", "session_id": "sp",
             "cgroup_id": "cgp", "epoch_id": "", "client": client,
             "error": None, "open_ns": 0}
        closed = []
        with mock.patch.object(mas, "open_agent", lambda idx, tag: dict(h)), \
             mock.patch.object(mas, "close_agents",
                               lambda hs: closed.extend(hs)):
            ns, err = mas._probe_read(None, "mas-t-ie", 9100)
        return ns, err, client, closed

    def test_the_consumer_is_rolled_back_and_never_committed(self):
        ns, err, client, closed = self._probe()
        self.assertIsNone(err)
        self.assertEqual(ns, client.run_ns)
        self.assertEqual(client.commits, 0,
                         "a reader of a live foreign version cannot be published")
        self.assertEqual(client.rollbacks, 1)
        self.assertEqual(len(closed), 1)

    def test_exactly_one_read_happens_in_exactly_one_epoch(self):
        """An edge is per (producer, consumer) epoch pair, so a second read
        inside the same epoch would be deduplicated and measure nothing."""
        _, _, client, _ = self._probe()
        self.assertEqual(client.begins, 1)
        self.assertEqual(len(client.runs), 1)

    def test_a_refused_begin_is_reported_and_still_torn_down(self):
        client = FakeAgentClient()
        client.slot_open = True          # something else holds the barrier
        ns, err, _, closed = self._probe(client)
        self.assertIsNone(ns)
        self.assertIn("in flight", err)
        self.assertEqual(client.rollbacks, 1)
        self.assertEqual(len(closed), 1)

    def test_an_open_failure_short_circuits_before_any_epoch_is_begun(self):
        with mock.patch.object(mas, "open_agent",
                               lambda idx, tag: {"error": "no cgroup left"}):
            ns, err = mas._probe_read(None, "mas-t-ie", 9100)
        self.assertIsNone(ns)
        self.assertEqual(err, "no cgroup left")


# ─── throughput phase: a collision is not a genuine error ──────────────────

class _FailRunClient(FakeAgentClient):
    """FakeAgentClient whose timed_run fails with a given exit code + stderr.

    run_agent_commands turns a non-zero exit into
    `command exited {rc}: {cmd!r} -> {output!r}`, so putting the strerror text
    in `output` reproduces exactly the message the real path raises -- the only
    channel _is_cascade_collision has to work with.
    """

    def __init__(self, output, exit_code=1, **kw):
        super().__init__(**kw)
        self._output = output
        self._exit_code = exit_code

    def timed_run(self, session_id, command):
        self.runs.append(command)
        return ({"status": "ok", "output": self._output,
                 "exit_code": self._exit_code}, self.run_ns)


class TestThroughputCollisionIsNotAGenuineError(unittest.TestCase):
    """A fail-closed EIO/EBADF on the throughput phase's in-flight `cat`/`echo`
    is the SAME designed worst case the rollback phase already tallies as a
    collision -- not a genuine error. Before _is_cascade_collision was wired
    into _agent_commit_loop, contended's `err` column was inflated by exactly
    these (2 at n=4, 1 at n=32) while the identical rollback-phase events were
    correctly counted apart. Both classifier guards must still hold here:
    `independent` is never excused, and text without an EIO/EBADF signature
    stays genuine.
    """

    def _handle(self, client, idx=20):
        return {"idx": idx, "agent_id": f"mas-t-a{idx}",
                "session_id": f"s{idx}", "cgroup_id": f"cg{idx}",
                "epoch_id": f"ep{idx}", "client": client, "error": None,
                "open_ns": 0}

    def _run(self, workload, output, n_agents=32):
        c = _FailRunClient(output)
        out = mas._agent_commit_loop(self._handle(c), workload, n_agents,
                                     warmup=0, invocations=1)
        return out, c

    def test_shared_eio_is_tallied_as_a_collision_not_an_error(self):
        out, c = self._run(
            "contended",
            "cat: /tmp/shadow-rq2-test/mnt/rq3-multi/sh_0.dat: 输入/输出错误")
        self.assertEqual(out["collisions"], 1)
        self.assertEqual(len(out["collision_samples"]), 1)
        self.assertEqual(out["errors"], [])
        self.assertTrue(out["aborted"], "a collision still aborts the agent")
        self.assertEqual(c.rollbacks, 1, "epoch is rolled back before abort")

    def test_shared_ebadf_is_also_a_collision(self):
        out, _ = self._run("contended", "cat: /x/sh_1.dat: 错误的文件描述符")
        self.assertEqual(out["collisions"], 1)
        self.assertEqual(out["errors"], [])

    def test_independent_eio_stays_a_genuine_error(self):
        # Guard 1: independent files are disjoint, no foreign cascade reaches
        # them, so an EIO there is a real bug and must never be excused.
        out, _ = self._run("independent", "cat: /x/f.dat: 输入/输出错误",
                           n_agents=1)
        self.assertEqual(out["collisions"], 0)
        self.assertEqual(len(out["errors"]), 1)

    def test_a_non_eio_failure_stays_a_genuine_error(self):
        # Guard 2: no EIO/EBADF signature -> genuine, so a dropped socket or a
        # timeout is never masked as a collision.
        out, _ = self._run("contended", "connection reset by peer")
        self.assertEqual(out["collisions"], 0)
        self.assertEqual(len(out["errors"]), 1)

    def test_enoent_is_not_a_collision(self):
        # A seeded file must not vanish; ENOENT is a real error, not a
        # fail-closed collision (it is not in the classifier's marker set).
        out, _ = self._run("contended", "cat: /x/sh_0.dat: 没有那个文件或目录")
        self.assertEqual(out["collisions"], 0)
        self.assertEqual(len(out["errors"]), 1)

    def test_total_collisions_sums_both_phases(self):
        r = make_result(workload="contended", agents=32)
        r.rollback_collisions = 35
        r.throughput_collisions = 1
        self.assertEqual(r.total_collisions, 36)


# ─── epoch lifecycle: the pending-commit retry budget ──────────────────────

class _Clock:
    """A monotonic clock that advances a fixed amount per read.

    The orchestrator answers a parked commit only after its own 30s finalize
    poll, so one read per attempt is the real cadence -- and it lets a
    ninety-second budget be tested without spending ninety seconds.
    """

    def __init__(self, step_s):
        self.t = 0.0
        self.step_s = step_s

    def __call__(self):
        now = self.t
        self.t += self.step_s
        return now


class TestCommitRetryBudget(unittest.TestCase):
    PENDING = {"status": "error", "decision": "authorized_pending",
               "message": "component not fully authorized"}

    def _commit(self, step_s, commit=None):
        h = make_handles(1)[0]
        h["client"] = FakeAgentClient(commit=commit or dict(self.PENDING))
        with mock.patch.object(mas.time, "monotonic", _Clock(step_s)), \
             mock.patch.object(mas.time, "sleep", lambda s: None):
            resp, _, attempts = mas.commit_agent_epoch(h)
        return resp, attempts

    def test_a_group_that_never_resolves_costs_the_budget_not_the_cap(self):
        """60 attempts at the server's 30s poll each is half an hour of silence
        on ONE commit -- indistinguishable from a hang, and paid once per probe.
        The wall clock is the real bound; the cap only catches a server that
        answers pending instantly."""
        resp, attempts = self._commit(step_s=30.0)
        self.assertEqual(resp.get("decision"), "authorized_pending")
        self.assertEqual(attempts, 3)
        self.assertLess(attempts, mas.PENDING_RETRY_LIMIT)
        self.assertLessEqual((attempts - 1) * 30.0, mas.PENDING_RETRY_BUDGET_S)

    def test_an_instant_pending_answer_is_still_bounded_by_the_cap(self):
        """The budget must not turn into an unbounded loop when the server
        answers immediately: the attempt cap is the backstop for that case."""
        _, attempts = self._commit(step_s=0.0)
        self.assertEqual(attempts, mas.PENDING_RETRY_LIMIT)

    def test_a_commit_that_succeeds_is_not_retried(self):
        resp, attempts = self._commit(step_s=30.0, commit={"status": "ok"})
        self.assertEqual(resp.get("status"), "ok")
        self.assertEqual(attempts, 1)

    def test_a_non_pending_error_stops_at_once(self):
        """`authorized_pending` is the documented recovery path; a denial is a
        result, and retrying it would report contention as a slow success."""
        resp, attempts = self._commit(step_s=0.0, commit={
            "status": "error", "decision": "denied", "message": "policy"})
        self.assertEqual(resp.get("decision"), "denied")
        self.assertEqual(attempts, 1)


# ─── epoch lifecycle: phase teardown ───────────────────────────────────────

class TestPhaseTeardownLeavesNoEpochOpen(unittest.TestCase):
    """An epoch that is neither committed nor rolled back stays in the graph, and
    the release path then refuses to let its session go -- polling it every two
    seconds for the rest of the run, which is how one leaked epoch turned into a
    wall of `still not finalized -- not releasing`. Both phases that open epochs
    the measurement itself does not resolve have to undo them on the way out.
    """

    def test_rollback_phase_undoes_the_graph_even_when_it_measured_nothing(self):
        handles = make_handles(3)
        res = make_result(agents=3)

        def build(obs, workload, n, live):
            # What the real build_open_graph leaves behind: every epoch open.
            for h in live:
                h["client"].timed_begin_epoch(h["session_id"], h["agent_id"])
            return []

        with mock.patch.object(mas, "seed_workspace", lambda *a: None), \
             mock.patch.object(mas, "open_agents", lambda n, tag: handles), \
             mock.patch.object(mas, "build_open_graph", build), \
             mock.patch.object(mas, "close_agents", lambda hs: None):
            mas.phase_rollback(FakeObs(), "independent", 3, "t", res,
                               {"rollback_invocations": 0})

        for h in handles:
            self.assertFalse(h["client"].slot_open,
                             f"agent{h['idx']} left its epoch open")
            self.assertEqual(h["client"].rollbacks, 1)

    def test_insertion_probe_undoes_a_producer_it_could_not_finalize(self):
        """The producer is the one epoch this phase must resolve, and if its
        commit does not succeed the failure has to be visible: a producer that
        never finalized also invalidates the control arm, which would then read
        a live version and form edges of its own."""
        producer = make_handles(1)[0]
        producer["client"] = FakeAgentClient(commit={
            "status": "error", "decision": "authorized_pending",
            "message": "parked"})
        res = make_result()
        with mock.patch.object(mas, "PENDING_RETRY_LIMIT", 2), \
             mock.patch.object(mas.time, "sleep", lambda s: None), \
             mock.patch.object(mas, "create_seed_file", lambda *a: None), \
             mock.patch.object(mas, "open_agent", lambda idx, tag: producer), \
             mock.patch.object(mas, "_probe_read", lambda *a: (500.0, None)), \
             mock.patch.object(mas, "close_agents", lambda hs: None):
            mas.phase_insertion(FakeObs(), "t", res, probes=2)
        self.assertFalse(producer["client"].slot_open,
                         "the producer's epoch outlived the phase")
        self.assertEqual(producer["client"].rollbacks, 1)
        self.assertTrue(any("producer commit" in e for e in res.errors),
                        f"a parked producer commit went unreported: {res.errors}")

    def test_insertion_probe_records_both_arms_when_the_producer_finalizes(self):
        producer = make_handles(1)[0]
        res = make_result()
        reads = []
        with mock.patch.object(mas, "create_seed_file", lambda *a: None), \
             mock.patch.object(mas, "open_agent", lambda idx, tag: producer), \
             mock.patch.object(mas, "_probe_read",
                               lambda obs, tag, idx: reads.append(tag) or (7.0, None)), \
             mock.patch.object(mas, "close_agents", lambda hs: None):
            mas.phase_insertion(FakeObs(), "t", res, probes=3)
        self.assertEqual(res.errors, [])
        self.assertEqual(producer["client"].commits, 1)
        self.assertEqual(len(res.edge_run_ns), 3)
        self.assertEqual(len(res.noedge_run_ns), 3)
        # The control arm runs only AFTER the producer is gone, which is what
        # makes its read a no-edge read.
        self.assertEqual(reads, ["t-ie"] * 3 + ["t-ic"] * 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
