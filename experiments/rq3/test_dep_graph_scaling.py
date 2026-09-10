#!/usr/bin/env python3
"""Unit tests for the pure logic of the dependency-graph scaling experiment.

The experiment needs root, three daemons and a FUSE mount, so none of it can run
in a test suite. What CAN be tested is every part that decides WHAT gets
measured -- and each of these, when wrong, produces a plausible-looking scaling
curve that says nothing:

  * seeding vs. reading. A FUSE Lookup that returns ENOENT never reaches Open,
    so Resolve() never runs and the read-from edge is silently not recorded. The
    experiment would then time the finalization of an EMPTY graph and report it
    as a dependency-graph result. So for every builder, the set of files it reads
    must be a subset of the set its dimension seeds.
  * the expected affected sets, checked by EQUALITY. An empty graph satisfies
    every "affected contains me" check, so containment would verify a graph that
    was never built.
  * `already finalized` counting as success. It is the atomic-publication
    contract; treating it as a failure turns the worst-case contention result
    into an apparent correctness break.
  * the counters that are read-modify-write under 64 concurrent members.
  * node_count, because fan-out/fan-in/diamond/concurrent all hold more nodes
    than their shape parameter, and the x-axis of the scaling plot is nodes.

Run: python3 -m unittest discover -s experiments/rq3 -p "test_dep_graph*.py" -t .
"""

import os
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dep_graph_scalability as dgs


# ─── fakes ─────────────────────────────────────────────────────────────────

class FakeClient:
    """One socket's worth of orchestrator API, scripted per action.

    `pending_times` makes session_commit_epoch answer `authorized_pending` that
    many times per session before succeeding, which is exactly what an SCC
    member that authorized before its siblings sees.
    """

    def __init__(self, commit=None, rollback=None, run=None, begin=None,
                 pending_times=0, graph=None, epochs_gone_after=0):
        self._commit = commit if commit is not None else {"status": "ok"}
        self._rollback = (rollback if rollback is not None
                          else {"status": "ok", "affected_epochs": []})
        self._run = run if run is not None else {"status": "ok", "exit_code": 0}
        self._begin = (begin if begin is not None
                       else {"status": "ok", "epoch_id": "ep",
                             "timings": {"fs_begin_epoch_ms": 1.0}})
        self._graph = graph if graph is not None else {}
        self.pending_times = pending_times
        self.epochs_gone_after = epochs_gone_after
        self.requests = []
        self._seen = {}
        self._polls = 0
        self._lock = threading.Lock()
        self.closed = False

    def connect(self):
        return None

    def close(self):
        self.closed = True

    # observation API
    def graph_stats(self, reset=False):
        return dict(self._graph)

    def epoch_states(self):
        self._polls += 1
        if self._polls > self.epochs_gone_after:
            return []
        return [{"epoch_id": "ep", "state": "finalizing"}]

    def wait_epochs_gone(self, epoch_ids, timeout=60.0, interval=0.02):
        gone = self.epochs_gone_after == 0
        return gone, 1234, [""] * len(epoch_ids) if gone else ["active"] * 1

    # session API
    def timed_open(self, agent_id="rq3-bench"):
        self.requests.append({"action": "session_open", "agent_id": agent_id})
        return {"session_id": f"sid-{agent_id}",
                "cgroup_id": f"cg-{agent_id}"}, 111

    def timed_begin_epoch(self, session_id, agent_id="rq3-bench"):
        self.requests.append({"action": "session_begin_epoch",
                              "session_id": session_id})
        return dict(self._begin), 222

    def timed_run(self, session_id, command):
        self.requests.append({"action": "session_run", "command": command})
        return dict(self._run), 333

    def request(self, req):
        action = req.get("action")
        with self._lock:
            self.requests.append(dict(req))
            key = (action, req.get("session_id"))
            n = self._seen.get(key, 0)
            self._seen[key] = n + 1
        if action == "session_commit_epoch":
            if n < self.pending_times:
                return {"status": "error", "decision": "authorized_pending",
                        "message": "component not fully authorized",
                        "timings": {"graph_revalidations": 1.0}}
            return dict(self._commit)
        if action in ("session_rollback_epoch", "session_resolve_epoch"):
            return dict(self._rollback)
        return {"status": "ok"}

    def session_close(self, session_id):
        self.requests.append({"action": "session_close",
                              "session_id": session_id})
        return {"status": "ok"}

    def get_affected(self, cgroup_id):
        return {"status": "ok", "affected": []}


def node(i, client=None, epoch_id=None):
    return dgs.EpochNode(node_id=f"n{i}", session_id=f"s{i}",
                         cgroup_id=f"cg{i}",
                         epoch_id=epoch_id if epoch_id is not None else f"e{i}",
                         agent_id=f"a{i}", client=client)


def nodes(n, own_clients=False):
    return [node(i, FakeClient() if own_clients else None) for i in range(n)]


class _Clock:
    """A monotonic clock that advances a fixed amount per read.

    The orchestrator answers a parked commit only after its own 30s finalize
    poll, so one read per attempt is the real cadence -- and it lets a
    two-minute budget be tested without spending two minutes.
    """

    def __init__(self, step_s):
        self.t = 0.0
        self.step_s = step_s

    def __call__(self):
        now = self.t
        self.t += self.step_s
        return now


class FakeObs:
    """Observation client: affected sets and graph snapshots, both scripted."""

    def __init__(self, affected=None, snapshots=()):
        self.affected = affected or {}
        self.snapshots = list(snapshots)
        self.stats_calls = 0

    def get_affected(self, cgroup_id):
        return {"status": "ok", "affected": sorted(self.affected.get(cgroup_id,
                                                                     []))}

    def graph_stats(self, reset=False):
        self.stats_calls += 1
        if not self.snapshots:
            return {}
        idx = min(self.stats_calls - 1, len(self.snapshots) - 1)
        return dict(self.snapshots[idx])

    def wait_epochs_gone(self, epoch_ids, timeout=60.0, interval=0.02):
        return True, 5000, [""] * len(epoch_ids)


class FakeWindow:
    def __init__(self, result):
        self.result = result
        self.entered = self.exited = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *exc):
        self.exited = True
        return False


class FakeDaemonRes:
    def __init__(self, result=None):
        self.result = result if result is not None else {"daemons_cpu_pct": 1.0}
        self.windows = []

    def window(self, poll=True):
        w = FakeWindow(self.result)
        self.windows.append(w)
        return w


class BuilderRecorder:
    """Runs a builder against fakes and records the file traffic it produces."""

    def __init__(self):
        self.reads = []
        self.writes = []

    def open_epoch_node(self, client, node_id, run_tag, res=None,
                        own_client=False):
        return dgs.EpochNode(node_id=node_id, session_id=f"sid-{node_id}",
                             cgroup_id=f"cg-{node_id}", epoch_id=f"ep-{node_id}",
                             agent_id=f"dep-{run_tag}-{node_id}",
                             client=FakeClient() if own_client else None)

    def run_cmd(self, client, nd, command, res=None):
        if res is not None:
            res.run_ns.append(1.0)
            with res._ctr_lock:
                res.invocations += 1
        if command.startswith("cat "):
            self.reads.append(command.split()[1])
        elif ">" in command:
            self.writes.append(command.rsplit(">", 1)[1].strip())
        return {"status": "ok", "exit_code": 0}

    def build(self, fn, *args, **kwargs):
        with patch.object(dgs, "open_epoch_node", self.open_epoch_node), \
                patch.object(dgs, "run_cmd", self.run_cmd):
            return fn(*args, **kwargs)


# ─── seeding: the edge that never formed ───────────────────────────────────

class TestSeedingCoversEveryRead(unittest.TestCase):
    """Every file a builder reads must already exist in the backing store.

    This is the single most damaging silent failure in the whole experiment: an
    unseeded read costs one ENOENT, forms no dependency edge, and leaves a
    finalization latency that looks excellent because there was no graph.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = patch.object(dgs, "DEP_WORK_ORIG", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        # The mount does not exist in a test run; point it somewhere harmless so
        # dep_fuse_path() still composes a deterministic relative name.
        patcher = patch.object(dgs, "DEP_WORK_FUSE", "/mnt/fake/rq3-dep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _seeded(self):
        return sorted(os.listdir(self._tmp.name))

    def _fuse(self, rels):
        return {dgs.dep_fuse_path(r) for r in rels}

    def _check(self, rec, seeded):
        self.assertTrue(rec.reads, "builder issued no reads at all")
        missing = set(rec.reads) - self._fuse(seeded)
        self.assertEqual(missing, set(),
                         f"reads with no backing-store file: {sorted(missing)}")

    def test_chain_reads_are_seeded(self):
        dgs.seed_files("chain", 8)
        rec = BuilderRecorder()
        out = rec.build(dgs.build_chain, FakeClient(), 8, "t")
        self.assertEqual(len(out), 8)
        self._check(rec, self._seeded())

    def test_cycle_reads_are_seeded_and_wrap_around(self):
        dgs.seed_files("scc", 5)
        rec = BuilderRecorder()
        rec.build(dgs.build_cycle, FakeClient(), 5, "t")
        self._check(rec, self._seeded())
        # The ring must close: node 0 reads node 4's file, not its own.
        self.assertEqual(rec.reads[0], dgs.dep_fuse_path("scc_4.dat"))

    def test_cycle_writes_everything_before_reading_anything(self):
        """The two-pass split is load-bearing: if a node reads before its
        predecessor has written, it reads the BACKING version, no live producer
        exists, and ShadowFS records no edge -- the 'cycle' is n isolated nodes
        that still passes an affected-set check for size 1."""
        cmds = []
        rec = BuilderRecorder()

        def spy(client, nd, command, res=None):
            cmds.append(command)
            return rec.run_cmd(client, nd, command, res)

        with patch.object(dgs, "open_epoch_node", rec.open_epoch_node), \
                patch.object(dgs, "run_cmd", spy):
            dgs.build_cycle(FakeClient(), 4, "t")

        writes = [i for i, c in enumerate(cmds) if c.startswith("echo")]
        reads = [i for i, c in enumerate(cmds) if c.startswith("cat")]
        self.assertEqual(len(writes), 4)
        self.assertEqual(len(reads), 4)
        self.assertLess(max(writes), min(reads),
                        "a read happened before all writes were done")

    def test_diamond_reads_are_seeded(self):
        dgs.seed_files("dia_mid", 4, extra=("dia_root.dat",))
        rec = BuilderRecorder()
        out = rec.build(dgs.build_diamond, FakeClient(), 4, "t")
        self.assertEqual(len(out), 6)          # root + 4 middles + sink
        self._check(rec, self._seeded())
        # 2*width edges worth of reads: every middle reads the root, the sink
        # reads every middle.
        self.assertEqual(len(rec.reads), 8)

    def test_fan_out_reads_are_seeded(self):
        dgs.create_seed_file("fan_root.dat", "root-data")
        rec = BuilderRecorder()
        out = rec.build(dgs.build_fan_out, FakeClient(), 6, "t")
        self.assertEqual(len(out), 7)          # root + 6 leaves
        self._check(rec, self._seeded())
        self.assertEqual(len(rec.reads), 6)

    def test_fan_in_reads_are_seeded(self):
        dgs.seed_files("fanin_src", 6)
        rec = BuilderRecorder()
        out = rec.build(dgs.build_fan_in, FakeClient(), 6, "t")
        self.assertEqual(len(out), 7)          # 6 sources + sink
        self._check(rec, self._seeded())
        self.assertEqual(len(rec.reads), 6)

    def test_seed_files_writes_into_the_backing_store_not_the_mount(self):
        """Seeding through the FUSE mount would create a speculative version
        owned by no epoch, which is not the same file the consumer resolves."""
        dgs.seed_files("chain", 2, extra=("extra.dat",))
        self.assertEqual(self._seeded(),
                         ["chain_0.dat", "chain_1.dat", "extra.dat"])

    def test_d7_seeds_match_the_prefix_it_builds_with(self):
        """D7 builds with prefix="sccp"; seeding "scc" would leave every read
        unbacked and the SCC would never form."""
        dgs.seed_files("sccp", 4)
        rec = BuilderRecorder()
        rec.build(dgs.build_cycle, FakeClient(), 4, "t", prefix="sccp")
        self._check(rec, self._seeded())


# ─── a partial build must not leak cgroup slots ────────────────────────────

class TestPartialBuildNeverLeaksCgroupSlots(unittest.TestCase):
    """A builder that fails partway MUST close the nodes it already opened.

    Every open node holds one of ShadowProc's 64 concurrent cgroup slots. The
    builders open nodes incrementally, so when the ceiling refuses one more
    open mid-build the nodes opened so far exist only in the builder's local
    list -- the caller never receives a return value to clean up. If the
    builder does not close them itself they leak, the slot table stays full for
    the rest of the run, and every later configuration fails session_open
    instantly. That is the cascade which turned ONE over-ceiling chain=64
    repeat into a whole run of errors (chain root-deny, fan-out, fan-in all
    dying at 0.0s with `Maximum 64 concurrent cgroups supported`).
    """

    CEILING_MSG = ("Orchestrator session_open failed: add_cgroup: "
                   "Maximum 64 concurrent cgroups supported")

    def _fail_at_open(self, fn, fail_at, *args, **kwargs):
        """Run `fn` with open_epoch_node raising on the (fail_at+1)-th open.

        Returns (opened, closed): the nodes successfully opened before the
        failure, and the nodes the builder handed to close_all_nodes. The leak
        fix is correct iff closed == opened.
        """
        opened, closed = [], []

        def fake_open(client, node_id, run_tag, res=None, own_client=False):
            if len(opened) >= fail_at:
                raise RuntimeError(self.CEILING_MSG)
            nd = dgs.EpochNode(node_id=node_id, session_id=f"sid-{node_id}",
                               cgroup_id=f"cg-{node_id}",
                               epoch_id=f"ep-{node_id}",
                               agent_id=f"dep-{run_tag}-{node_id}",
                               client=FakeClient() if own_client else None)
            opened.append(nd)
            return nd

        def fake_close(client, nds):
            closed.extend(nds)

        with patch.object(dgs, "open_epoch_node", fake_open), \
                patch.object(dgs, "close_all_nodes", fake_close), \
                patch.object(dgs, "run_cmd",
                             lambda *a, **k: {"status": "ok",
                                              "exit_code": 0}):
            with self.assertRaises(RuntimeError):
                fn(*args, **kwargs)
        return opened, closed

    def _assert_closes_exactly_what_it_opened(self, fn, fail_at, *a, **k):
        opened, closed = self._fail_at_open(fn, fail_at, *a, **k)
        self.assertEqual(len(opened), fail_at)
        self.assertEqual([n.session_id for n in closed],
                         [n.session_id for n in opened],
                         "builder leaked the nodes it opened before failing")

    def test_chain_closes_nodes_opened_before_the_ceiling(self):
        self._assert_closes_exactly_what_it_opened(
            dgs.build_chain, 5, FakeClient(), 8, "t")

    def test_cycle_closes_nodes_opened_before_the_ceiling(self):
        self._assert_closes_exactly_what_it_opened(
            dgs.build_cycle, 3, FakeClient(), 6, "t")

    def test_fan_out_closes_nodes_opened_before_the_ceiling(self):
        self._assert_closes_exactly_what_it_opened(
            dgs.build_fan_out, 4, FakeClient(), 6, "t")

    def test_fan_in_closes_nodes_opened_before_the_ceiling(self):
        self._assert_closes_exactly_what_it_opened(
            dgs.build_fan_in, 4, FakeClient(), 6, "t")

    def test_diamond_closes_nodes_opened_before_the_ceiling(self):
        self._assert_closes_exactly_what_it_opened(
            dgs.build_diamond, 3, FakeClient(), 4, "t")

    def test_a_run_cmd_failure_also_closes_the_fully_opened_graph(self):
        """The leak is not only at the open loop: a run_cmd that raises AFTER
        every node is open must close them too, or the whole graph leaks."""
        opened, closed = [], []

        def fake_open(client, node_id, run_tag, res=None, own_client=False):
            nd = dgs.EpochNode(node_id=node_id, session_id=f"sid-{node_id}",
                               cgroup_id=f"cg-{node_id}",
                               epoch_id=f"ep-{node_id}",
                               agent_id=f"dep-{run_tag}-{node_id}", client=None)
            opened.append(nd)
            return nd

        def fake_close(client, nds):
            closed.extend(nds)

        def boom(client, nd, command, res=None):
            raise RuntimeError("run_cmd failed")

        with patch.object(dgs, "open_epoch_node", fake_open), \
                patch.object(dgs, "close_all_nodes", fake_close), \
                patch.object(dgs, "run_cmd", boom):
            with self.assertRaises(RuntimeError):
                dgs.build_chain(FakeClient(), 4, "t")
        self.assertEqual(len(opened), 4)
        self.assertEqual([n.session_id for n in closed],
                         [n.session_id for n in opened])


# ─── expected affected sets ────────────────────────────────────────────────

class TestVerifyDependencies(unittest.TestCase):

    def _affected(self, mapping):
        return {k: sorted(v) for k, v in mapping.items()}

    def test_chain_exact_sets_pass(self):
        ns = nodes(4)
        all_cg = [n.cgroup_id for n in ns]
        obs = FakeObs(self._affected({
            n.cgroup_id: all_cg[i:] for i, n in enumerate(ns)}))
        count, ok, errs = dgs.verify_dependencies(obs, ns, "chain")
        self.assertTrue(ok, errs)
        self.assertEqual(count, 4)

    def test_chain_rejects_an_empty_graph(self):
        """The trap containment-checking falls into: nothing affected but me is
        also what an unbuilt graph looks like."""
        ns = nodes(4)
        obs = FakeObs(self._affected({n.cgroup_id: [n.cgroup_id] for n in ns}))
        count, ok, errs = dgs.verify_dependencies(obs, ns, "chain")
        self.assertFalse(ok)
        self.assertEqual(count, 1)
        self.assertTrue(any("chain[0]" in e for e in errs))

    def test_chain_rejects_a_star_shaped_graph(self):
        """Every leaf depending on every other leaf is not a chain, and the two
        have very different rollback blast radii."""
        ns = nodes(4)
        all_cg = [n.cgroup_id for n in ns]
        star = {n.cgroup_id: all_cg for n in ns}
        star[ns[-1].cgroup_id] = [ns[-1].cgroup_id]
        _, ok, _ = dgs.verify_dependencies(FakeObs(self._affected(star)),
                                           ns, "chain")
        self.assertFalse(ok)

    def test_chain_rejects_an_off_by_one_suffix(self):
        ns = nodes(4)
        all_cg = [n.cgroup_id for n in ns]
        obs = FakeObs(self._affected({
            n.cgroup_id: all_cg[i + 1:] or all_cg[i:]
            for i, n in enumerate(ns)}))
        _, ok, _ = dgs.verify_dependencies(obs, ns, "chain")
        self.assertFalse(ok, "a node that omits ITSELF from its own affected "
                             "set must not verify")

    def test_diamond_is_asymmetric_between_arms(self):
        """The property that makes a diamond a diamond: rolling back one arm
        must not reach the other."""
        ns = nodes(4)                      # root, m0, m1, sink
        root, m0, m1, sink = ns
        obs = FakeObs(self._affected({
            root.cgroup_id: [n.cgroup_id for n in ns],
            m0.cgroup_id: [m0.cgroup_id, sink.cgroup_id],
            m1.cgroup_id: [m1.cgroup_id, sink.cgroup_id],
            sink.cgroup_id: [sink.cgroup_id]}))
        count, ok, errs = dgs.verify_dependencies(obs, ns, "diamond")
        self.assertTrue(ok, errs)
        self.assertEqual(count, 4)

    def test_diamond_rejects_cross_arm_leakage(self):
        ns = nodes(4)
        root, m0, m1, sink = ns
        obs = FakeObs(self._affected({
            root.cgroup_id: [n.cgroup_id for n in ns],
            m0.cgroup_id: [m0.cgroup_id, m1.cgroup_id, sink.cgroup_id],
            m1.cgroup_id: [m1.cgroup_id, sink.cgroup_id],
            sink.cgroup_id: [sink.cgroup_id]}))
        _, ok, errs = dgs.verify_dependencies(obs, ns, "diamond")
        self.assertFalse(ok)
        self.assertTrue(any("diamond[n1]" in e for e in errs))

    def test_diamond_rejects_a_pure_fan_out(self):
        """A diamond whose sink never depends on the middles is a fan-out, and
        fan-out is D2 -- accepting it here would double-count a shape."""
        ns = nodes(4)
        root = ns[0]
        obs = FakeObs(self._affected({
            root.cgroup_id: [n.cgroup_id for n in ns],
            **{n.cgroup_id: [n.cgroup_id] for n in ns[1:]}}))
        _, ok, _ = dgs.verify_dependencies(obs, ns, "diamond")
        self.assertFalse(ok)

    def test_scc_requires_every_node_to_reach_every_node(self):
        ns = nodes(5)
        all_cg = [n.cgroup_id for n in ns]
        obs = FakeObs(self._affected({n.cgroup_id: all_cg for n in ns}))
        count, ok, errs = dgs.verify_dependencies(obs, ns, "scc")
        self.assertTrue(ok, errs)
        self.assertEqual(count, 5)

    def test_scc_rejects_a_chain(self):
        """A cycle that did not close is a chain. Same node count, completely
        different finalization semantics, so it must not verify as an SCC."""
        ns = nodes(5)
        all_cg = [n.cgroup_id for n in ns]
        obs = FakeObs(self._affected({
            n.cgroup_id: all_cg[i:] for i, n in enumerate(ns)}))
        _, ok, _ = dgs.verify_dependencies(obs, ns, "scc")
        self.assertFalse(ok)

    def test_fan_out_and_fan_in_expectations(self):
        ns = nodes(4)
        root, sink = ns[0], ns[-1]
        fan_out = FakeObs(self._affected({
            root.cgroup_id: [n.cgroup_id for n in ns],
            **{n.cgroup_id: [n.cgroup_id] for n in ns[1:]}}))
        _, ok, errs = dgs.verify_dependencies(fan_out, ns, "fan-out")
        self.assertTrue(ok, errs)

        fan_in = FakeObs(self._affected({
            sink.cgroup_id: [sink.cgroup_id],
            **{n.cgroup_id: [n.cgroup_id, sink.cgroup_id] for n in ns[:-1]}}))
        _, ok, errs = dgs.verify_dependencies(fan_in, ns, "fan-in")
        self.assertTrue(ok, errs)

    def test_fan_out_and_fan_in_are_not_interchangeable(self):
        ns = nodes(4)
        root, sink = ns[0], ns[-1]
        fan_out = FakeObs(self._affected({
            root.cgroup_id: [n.cgroup_id for n in ns],
            **{n.cgroup_id: [n.cgroup_id] for n in ns[1:]}}))
        _, ok, _ = dgs.verify_dependencies(fan_out, ns, "fan-in")
        self.assertFalse(ok, "a fan-out verified as fan-in would mean the "
                             "expectations are not actually different")

    def test_records_affected_samples_and_reports_get_affected_failure(self):
        ns = nodes(3)
        res = dgs.DepGraphResult(dimension="T", topology="chain", size=3,
                                 repeats=1)

        class Boom(FakeObs):
            def get_affected(self, cgroup_id):
                if cgroup_id == ns[1].cgroup_id:
                    raise RuntimeError("socket died")
                return super().get_affected(cgroup_id)

        obs = Boom({n.cgroup_id: [x.cgroup_id for x in ns[i:]]
                    for i, n in enumerate(ns)})
        _, ok, errs = dgs.verify_dependencies(obs, ns, "chain", res=res)
        self.assertFalse(ok)
        self.assertTrue(any("get_affected(n1) failed" in e for e in errs))
        # A failed lookup records nothing rather than a zero that would drag the
        # mean affected-set size down.
        self.assertEqual(len(res.affected_samples), 2)

    def test_empty_node_list_fails_instead_of_passing_vacuously(self):
        _, ok, errs = dgs.verify_dependencies(FakeObs(), [], "chain")
        self.assertFalse(ok)
        self.assertTrue(errs)


# ─── commit semantics ──────────────────────────────────────────────────────

class TestCommitSemantics(unittest.TestCase):

    def test_already_finalized_is_success(self):
        """A sibling member published the whole component first. That is the
        atomic-publication contract working, not a failure."""
        self.assertTrue(dgs.commit_succeeded(
            {"status": "error",
             "message": "begin_finalize: group already finalized"}))
        self.assertTrue(dgs.commit_succeeded({"status": "ok"}))

    def test_pending_and_other_errors_are_not_success(self):
        self.assertFalse(dgs.commit_succeeded(
            {"status": "error", "decision": "authorized_pending"}))
        self.assertFalse(dgs.commit_succeeded(
            {"status": "error", "message": "WAL barrier failed"}))
        self.assertFalse(dgs.commit_succeeded({}))

    def test_commit_node_records_latency_and_timings(self):
        r = dgs.DepGraphResult(dimension="T", topology="chain", size=1)
        resp = dgs.commit_node(FakeClient(), node(0), r)
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(len(r.commit_ns), 1)
        self.assertEqual(r.commit_attempts, [1])
        self.assertEqual(r.pending_commits, 0)
        self.assertEqual(len(r.finalization_wait_ns), 1)
        self.assertEqual(r.invocations, 0, "a commit is not an invocation")

    def test_commit_node_retries_authorized_pending(self):
        """The orchestrator's own retry loop ticks every 2 s, so waiting on it
        would measure the interval instead of the graph. The client retries."""
        r = dgs.DepGraphResult(dimension="D7", topology="scc", size=4)
        client = FakeClient(pending_times=3)
        with patch.object(dgs, "PENDING_RETRY_SLEEP_S", 0.0):
            resp = dgs.commit_node(client, node(0), r)
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(r.commit_attempts, [4])
        self.assertEqual(r.pending_commits, 1)
        commits = [q for q in client.requests
                   if q["action"] == "session_commit_epoch"]
        self.assertEqual(len(commits), 4)

    def test_commit_node_gives_up_at_the_retry_limit(self):
        r = dgs.DepGraphResult(dimension="D7", topology="scc", size=4)
        client = FakeClient(pending_times=10 ** 6)
        with patch.object(dgs, "PENDING_RETRY_SLEEP_S", 0.0), \
                patch.object(dgs, "PENDING_RETRY_LIMIT", 5):
            resp = dgs.commit_node(client, node(0), r)
        self.assertEqual(resp.get("decision"), "authorized_pending")
        self.assertEqual(r.commit_attempts, [5])
        self.assertFalse(dgs.commit_succeeded(resp))

    def test_commit_node_gives_up_at_the_wall_clock_budget(self):
        """The attempt cap is not a time bound. Every attempt blocks in the
        orchestrator's own 30s finalize poll before it can answer pending again,
        so 150 attempts is seventy-five minutes of silence on ONE commit --
        longer than a whole dimension sweep, and indistinguishable from a hang.
        The budget has to fire first."""
        r = dgs.DepGraphResult(dimension="D7", topology="scc", size=4)
        client = FakeClient(pending_times=10 ** 6)
        with patch.object(dgs, "PENDING_RETRY_SLEEP_S", 0.0), \
                patch.object(dgs.time, "monotonic", _Clock(30.0)), \
                patch.object(dgs.time, "sleep", lambda s: None):
            resp = dgs.commit_node(client, node(0), r)
        self.assertEqual(resp.get("decision"), "authorized_pending")
        self.assertEqual(r.commit_attempts, [4])
        self.assertLess(r.commit_attempts[0], dgs.PENDING_RETRY_LIMIT)

    def test_a_commit_that_never_publishes_is_reported(self):
        """Giving up has to leave a trace. A parked commit that is silently
        abandoned puts an enormous sample into commit_ns and offers no
        explanation anywhere in the results file, so the number is read as a
        measurement of the graph rather than as a component that never
        published."""
        r = dgs.DepGraphResult(dimension="D7", topology="scc", size=4)
        with patch.object(dgs, "PENDING_RETRY_SLEEP_S", 0.0), \
                patch.object(dgs, "PENDING_RETRY_LIMIT", 3):
            dgs.commit_node(FakeClient(pending_times=10 ** 6), node(0), r)
        self.assertEqual(len(r.errors), 1)
        self.assertIn("still parked after 3 attempt", r.errors[0])
        self.assertIn("e0", r.errors[0])

    def test_an_unrequested_publication_is_not_reported_as_a_failure(self):
        """D3 and D5 undo their graphs on purpose. A dimension that never asked
        for a publication must not be told it failed to produce one, or the
        intended outcomes bury the real ones."""
        r = dgs.DepGraphResult(dimension="D3", topology="scc", size=4)
        with patch.object(dgs, "PENDING_RETRY_SLEEP_S", 0.0):
            dgs.commit_node(FakeClient(pending_times=3), node(0), r,
                            retry_pending=False)
        self.assertEqual(r.errors, [])

    def test_a_denial_is_not_reported_as_a_parked_commit(self):
        """A denied epoch is a result the dimension asked for, not a component
        stuck mid-publication -- and it must not inherit that error's wording."""
        r = dgs.DepGraphResult(dimension="D6", topology="diamond", size=4)
        denied = {"status": "error", "decision": "deny", "message": "policy"}
        with patch.object(dgs, "PENDING_RETRY_SLEEP_S", 0.0):
            dgs.commit_node(FakeClient(commit=denied), node(0), r)
        self.assertEqual(r.errors, [])
        self.assertEqual(r.commit_attempts, [1])

    def test_retry_pending_can_be_disabled(self):
        r = dgs.DepGraphResult(dimension="T", topology="scc", size=2)
        client = FakeClient(pending_times=3)
        resp = dgs.commit_node(client, node(0), r, retry_pending=False)
        self.assertEqual(r.commit_attempts, [1])
        self.assertEqual(resp.get("decision"), "authorized_pending")
        # No wait is claimed for a single attempt that was never retried.
        self.assertEqual(r.finalization_wait_ns, [])

    def test_concurrent_pending_commits_are_not_lost(self):
        """Every member of a 64-node SCC parks once, so exactly 64 increments
        must land. `pending_commits += 1` is a read-modify-write, which is why
        the result carries a guard: CPython seldom preempts inside the
        expression (this test does not reliably catch it unguarded), but
        "seldom" is not a measurement guarantee and the count is the evidence
        that atomic publication actually made anyone wait."""
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)      # give any race its best chance
        try:
            for _ in range(20):
                r = dgs.DepGraphResult(dimension="D7", topology="scc", size=64)
                # Every member owns its socket (that is what makes them able to
                # authorize at the same instant) and every member parks once.
                ns = [node(i, FakeClient(pending_times=1)) for i in range(64)]
                with patch.object(dgs, "PENDING_RETRY_SLEEP_S", 0.0):
                    resps = dgs.commit_all(FakeClient(), ns, r, concurrent=True)
                self.assertEqual(len(resps), 64)
                self.assertEqual(r.pending_commits, 64)
                self.assertEqual(sum(r.commit_attempts), 128)
                self.assertEqual(len(r.finalization_wait_ns), 64)
                self.assertEqual(len(r.commit_ns), 64)
        finally:
            sys.setswitchinterval(old)

    def test_concurrent_invocation_counter_is_not_lost(self):
        """D4's agents build their dependencies from 32 threads at once, and
        `invocations` is the denominator of edges-per-invocation."""
        from concurrent.futures import ThreadPoolExecutor
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            r = dgs.DepGraphResult(dimension="D4", topology="concurrent",
                                   size=32)
            ns = nodes(32, own_clients=True)
            with ThreadPoolExecutor(max_workers=32) as pool:
                list(pool.map(lambda n: dgs.run_cmd(n.conn(None), n, "true", r),
                              ns))
            self.assertEqual(r.invocations, 32)
            self.assertEqual(len(r.run_ns), 32)
        finally:
            sys.setswitchinterval(old)

    def test_sequential_commit_all_uses_the_shared_connection(self):
        ns = nodes(3)
        shared = FakeClient()
        dgs.commit_all(shared, ns, None, concurrent=False)
        self.assertEqual(len([q for q in shared.requests
                              if q["action"] == "session_commit_epoch"]), 3)

    def test_node_conn_prefers_its_own_socket(self):
        """Two threads on one line-oriented socket read each other's replies."""
        own = FakeClient()
        self.assertIs(node(0, own).conn(FakeClient()), own)
        shared = FakeClient()
        self.assertIs(node(0).conn(shared), shared)

    def test_run_cmd_raises_on_nonzero_exit(self):
        """A failed `cat` forms no edge; without this it surfaces only as a
        topology mismatch several RPCs later."""
        r = dgs.DepGraphResult(dimension="T", topology="chain", size=1)
        client = FakeClient(run={"status": "ok", "exit_code": 2,
                                 "output": "cat: no such file"})
        with self.assertRaises(RuntimeError) as cm:
            dgs.run_cmd(client, node(0), "cat x > /dev/null", r)
        self.assertIn("exited 2", str(cm.exception))
        self.assertEqual(r.invocations, 1, "the attempt still happened")


# ─── rollback semantics ────────────────────────────────────────────────────

class TestUndoNode(unittest.TestCase):

    def test_deny_goes_through_resolve_and_rolls_back_explicitly(self):
        client = FakeClient(rollback={"status": "ok",
                                      "affected_epochs": ["a", "b", "c"],
                                      "timings": {"fs_rollback_ms": 2.0}})
        r = dgs.DepGraphResult(dimension="T", topology="chain", size=3)
        resp, elapsed = dgs.undo_node(client, node(0), r, via="deny")
        self.assertEqual(resp["status"], "ok")
        # A fake RPC can complete inside the clock's granularity, so the only
        # honest claim about the elapsed value is that it was produced.
        self.assertIsInstance(elapsed, int)
        self.assertGreaterEqual(elapsed, 0)
        sent = client.requests[-1]
        self.assertEqual(sent["action"], "session_resolve_epoch")
        self.assertEqual(sent["decision"], "deny")

        resp, _ = dgs.undo_node(client, node(1), r, via="rollback")
        sent = client.requests[-1]
        self.assertEqual(sent["action"], "session_rollback_epoch")
        self.assertNotIn("decision", sent)
        # Both paths cascade inside one RPC, so both report the cascade size.
        self.assertEqual(r.rollback_affected, [3, 3])
        self.assertEqual(len(r.rollback_ns), 2)
        self.assertIn("fs_rollback_ms", r.rollback_timings)

    def test_rollback_affected_is_kept_apart_from_dry_run_samples(self):
        """One is what the graph SAID would be undone (verification), the other
        is what WAS undone. Mixing them makes the cascade curve unverifiable."""
        r = dgs.DepGraphResult(dimension="T", topology="chain", size=2)
        r.affected_samples.append(9)
        dgs.undo_node(FakeClient(rollback={"status": "ok",
                                           "affected_epochs": ["x"]}),
                      node(0), r, via="deny")
        self.assertEqual(r.affected_samples, [9])
        self.assertEqual(r.rollback_affected, [1])


# ─── graph observation ─────────────────────────────────────────────────────

class TestGraphObservation(unittest.TestCase):

    def test_peak_keeps_the_largest_population(self):
        """Publication drops a group's edges and ack removes its nodes, so the
        only fully-populated instant is before resolution. A repeat that opened
        fewer nodes must not overwrite a real peak -- and must say so."""
        r = dgs.DepGraphResult(dimension="D1", topology="chain", size=8,
                               repeats=3)
        obs = FakeObs(snapshots=[{"epochs": 8, "edges": 7},
                                 {"epochs": 3, "edges": 2},
                                 {"epochs": 8, "edges": 7}])
        dgs.record_graph_peak(r, obs)
        dgs.record_graph_peak(r, obs)
        dgs.record_graph_peak(r, obs)
        self.assertEqual(r.graph_peak["epochs"], 8)
        self.assertEqual(r.graph_peak["edges"], 7)
        # Only the short sample is reported, once.
        self.assertEqual(len(r.errors), 1)
        self.assertIn("holds 3 epochs", r.errors[0])

    def test_a_full_peak_leaves_no_error(self):
        r = dgs.DepGraphResult(dimension="D1", topology="chain", size=8,
                               repeats=2)
        obs = FakeObs(snapshots=[{"epochs": 8, "edges": 7}] * 2)
        dgs.record_graph_peak(r, obs)
        dgs.record_graph_peak(r, obs)
        self.assertEqual(r.errors, [])

    def test_shortfall_is_reported_as_a_topology_that_never_built(self):
        r = dgs.DepGraphResult(dimension="D1", topology="chain", size=16,
                               repeats=1)
        dgs.record_graph_peak(r, FakeObs(snapshots=[{"epochs": 4, "edges": 3}]))
        self.assertTrue(any("did not fully build" in e for e in r.errors))

    def test_extra_epochs_are_not_an_error(self):
        """Something else may be using the daemon; only a shortfall means this
        configuration's topology is missing."""
        r = dgs.DepGraphResult(dimension="D1", topology="chain", size=2,
                               repeats=1)
        dgs.record_graph_peak(r, FakeObs(snapshots=[{"epochs": 9, "edges": 3}]))
        self.assertEqual(r.errors, [])

    def test_unavailable_graph_stats_degrades_quietly(self):
        """An older ShadowFS must empty a column of the table, not abort a run
        that may already have taken an hour."""
        r = dgs.DepGraphResult(dimension="D1", topology="chain", size=2,
                               repeats=1)
        dgs.record_graph_peak(r, FakeObs(snapshots=[]))
        self.assertEqual(r.graph_peak, {})
        self.assertEqual(r.errors, [])

    def test_config_measure_samples_even_when_the_body_raises(self):
        """A phase that failed still did graph work; dropping its counters would
        understate exactly the configuration that broke."""
        r = dgs.DepGraphResult(dimension="D1", topology="chain", size=4,
                               repeats=1)
        obs = FakeObs(snapshots=[{"epochs": 0, "edge_insertions": 0},
                                 {"epochs": 0, "edge_insertions": 12}])
        dres = FakeDaemonRes({"shadowfs_cpu_pct": 7.0})
        with patch.object(dgs, "summarize", lambda win: {"from": win}):
            with self.assertRaises(RuntimeError):
                with dgs.ConfigMeasure(obs, r, dres):
                    raise RuntimeError("boom")
        self.assertEqual(r.graph.get("edge_insertions"), 12)
        self.assertEqual(r.resources,
                         {"from": {"shadowfs_cpu_pct": 7.0}},
                         "the window result must be summarized, not dropped")
        self.assertTrue(dres.windows[0].entered)
        self.assertTrue(dres.windows[0].exited)

    def test_config_measure_without_a_daemon_sampler(self):
        r = dgs.DepGraphResult(dimension="D1", topology="chain", size=2,
                               repeats=1)
        with dgs.ConfigMeasure(FakeObs(snapshots=[{"epochs": 2}]), r, None):
            pass
        self.assertEqual(r.resources, {})

    def test_graph_delta_separates_counters_from_shape_and_memory(self):
        before = {"epochs": 1, "edges": 0, "edge_insertions": 5,
                  "heap_alloc_bytes": 100}
        after = {"epochs": 4, "edges": 3, "edge_insertions": 9,
                 "heap_alloc_bytes": 400}
        d = dgs.graph_delta(before, after)
        self.assertEqual(d["edge_insertions"], 4, "counters are a difference")
        self.assertEqual(d["shape_epochs"], 4, "shape is the later value")
        self.assertEqual(d["mem_heap_alloc_bytes"], 400)

    def test_edges_per_invocation_uses_the_flat_counter_key(self):
        r = dgs.DepGraphResult(dimension="D1", topology="chain", size=8,
                               repeats=1)
        self.assertIsNone(r.edges_per_invocation, "no invocations, no ratio")
        r.invocations = 15
        r.graph = {"edge_insertions": 30}
        self.assertEqual(r.edges_per_invocation, 2.0)


# ─── result schema ─────────────────────────────────────────────────────────

class TestResultSchema(unittest.TestCase):

    def test_node_count_is_the_shape_parameter_plus_the_extra_nodes(self):
        """The x-axis of the scaling plot is NODES. Using `size` for a fan-out
        would plot an 18-node graph at x=16 and flatten the curve."""
        cases = {"chain": (8, 8), "scc": (8, 8), "fan-out": (8, 9),
                 "fan-in": (8, 9), "concurrent": (8, 9), "diamond": (8, 10)}
        for topo, (size, want) in cases.items():
            r = dgs.DepGraphResult(dimension="T", topology=topo, size=size)
            self.assertEqual(r.node_count, want, topo)

    def test_metadata_bytes_per_node_is_none_rather_than_zero(self):
        r = dgs.DepGraphResult(dimension="T", topology="chain", size=4)
        self.assertIsNone(r.metadata_bytes_per_node)
        r.graph_peak = {"heap_alloc_bytes": 4096}
        self.assertEqual(r.metadata_bytes_per_node, 1024.0)
        empty = dgs.DepGraphResult(dimension="T", topology="chain", size=0)
        empty.graph_peak = {"heap_alloc_bytes": 4096}
        self.assertIsNone(empty.metadata_bytes_per_node)

    def test_graph_revalidations_sums_the_count_key(self):
        r = dgs.DepGraphResult(dimension="D7", topology="scc", size=4)
        r.commit_timings["graph_revalidations"] = [1.0, 1.0, 2.0]
        self.assertEqual(r.graph_revalidations, 4)

    def test_topo_verified_requires_a_check_for_every_repeat(self):
        """A configuration where 9 of 10 repeats crashed must not report
        topo_verified from the one that ran."""
        r = dgs.DepGraphResult(dimension="T", topology="chain", size=4,
                               repeats=3)
        r.topo_checks = [True, True]
        self.assertFalse(r.topo_verified)
        r.topo_checks = [True, True, True]
        self.assertTrue(r.topo_verified)
        r.topo_checks = [True, False, True]
        self.assertFalse(r.topo_verified)

    def test_count_keys_are_not_reported_as_milliseconds(self):
        """`graph_revalidations` is stamped into the same dict as the phase
        timings; reporting it under a *_ms key would turn "revalidated twice"
        into "took 2 ms"."""
        r = dgs.DepGraphResult(dimension="D7", topology="scc", size=4, repeats=1)
        r.commit_timings["graph_revalidations"] = [2.0]
        r.commit_timings["finalize_polls"] = [3.0]
        r.commit_timings["fs_begin_finalize_ms"] = [1.5]
        d = r.to_dict()
        self.assertIn("commit_counts.graph_revalidations", d["stats"])
        self.assertIn("commit_counts.finalize_polls", d["stats"])
        self.assertIn("commit_timings_ms.fs_begin_finalize_ms", d["stats"])
        self.assertNotIn("commit_timings_ms.graph_revalidations", d["stats"])
        self.assertEqual(
            d["stats"]["commit_counts.graph_revalidations"]["total"], 2.0)

    def test_to_dict_carries_every_reported_metric(self):
        r = dgs.DepGraphResult(dimension="D7", topology="scc", size=8,
                               decision="publish", resolution_op="commit",
                               repeats=1)
        r.finalize_ns = [1000.0]
        r.rollback_ns = [2000.0]
        r.finalization_wait_ns = [3000.0]
        r.drain_ns = [4000.0]
        r.pending_commits = 7
        r.commit_attempts = [2, 3]
        r.invocations = 16
        r.graph = {"edge_insertions": 16, "finalize_rejected_toctou": 1}
        r.graph_peak = {"epochs": 8, "edges": 8, "cyclic_scc_count": 1,
                        "max_scc_size": 8, "heap_alloc_bytes": 8192}
        r.resources = {"daemons_cpu_pct": 12.5}
        r.affected_samples = [8]
        r.rollback_affected = [8]
        d = r.to_dict()
        for key in ("nodes", "resolution_op", "pending_commits",
                    "commit_attempts_mean", "commit_attempts_max",
                    "invocations", "edges_per_invocation",
                    "graph_revalidations", "graph", "resources", "graph_peak",
                    "metadata_bytes_per_node", "affected_mean", "affected_max",
                    "rollback_affected_mean", "rollback_affected_max"):
            self.assertIn(key, d, key)
        self.assertEqual(d["nodes"], 8)
        self.assertEqual(d["edges_per_invocation"], 1.0)
        self.assertEqual(d["commit_attempts_max"], 3)
        for key in ("finalize_ns", "rollback_ns", "finalization_wait_ns",
                    "drain_ns"):
            self.assertIn(key, d["stats"], key)
        self.assertEqual(set(d["graph_peak"]),
                         {"epochs", "edges", "versions", "objects", "scc_count",
                          "cyclic_scc_count", "max_scc_size", "active_groups",
                          "heap_alloc_bytes", "heap_inuse_bytes", "sys_bytes",
                          "goroutines"})

    def test_merge_timings_ignores_non_numbers_and_keeps_unknown_keys(self):
        dst = {}
        dgs._merge_timings(dst, {"a_ms": 1.5, "flag": True, "s": "x",
                                 "none": None, "b_ms": 2})
        self.assertEqual(sorted(dst), ["a_ms", "b_ms"],
                         "bools and strings must not become samples")
        self.assertEqual(dst["b_ms"], [2.0])
        dgs._merge_timings(dst, None)
        self.assertEqual(dst["a_ms"], [1.5])

    def test_extend_timings_concatenates_repeats(self):
        dst = {"x_ms": [1.0]}
        dgs._extend_timings(dst, {"x_ms": [2.0], "y_ms": [3.0]})
        self.assertEqual(dst, {"x_ms": [1.0, 2.0], "y_ms": [3.0]})


# ─── node lifecycle ────────────────────────────────────────────────────────

class TestNodeLifecycle(unittest.TestCase):

    def test_open_epoch_node_records_begin_cost_and_timings(self):
        r = dgs.DepGraphResult(dimension="T", topology="chain", size=1)
        client = FakeClient()
        with patch.object(dgs, "OrchClient", FakeClient):
            nd = dgs.open_epoch_node(client, "root", "tag", r)
        self.assertEqual(nd.node_id, "root")
        self.assertEqual(r.open_ns, [111.0])
        self.assertEqual(r.begin_ns, [222.0])
        self.assertIn("fs_begin_epoch_ms", r.begin_timings)
        self.assertIsNone(nd.client, "a shared connection stays shared")

    def test_open_epoch_node_can_own_its_connection(self):
        made = []

        class Factory(FakeClient):
            def __init__(self):
                super().__init__()
                made.append(self)

        with patch.object(dgs, "OrchClient", Factory):
            nd = dgs.open_epoch_node(FakeClient(), "cyc0", "tag", None,
                                     own_client=True)
        self.assertIs(nd.client, made[-1])

    def test_open_epoch_node_closes_the_socket_it_opened_on_failure(self):
        class Boom(FakeClient):
            def timed_open(self, agent_id="rq3-bench"):
                raise RuntimeError("no cgroup slots left")

        made = []

        class Factory(Boom):
            def __init__(self):
                super().__init__()
                made.append(self)

        with patch.object(dgs, "OrchClient", Factory):
            with self.assertRaises(RuntimeError):
                dgs.open_epoch_node(FakeClient(), "x", "tag", None,
                                    own_client=True)
        self.assertTrue(made[-1].closed,
                        "a leaked private socket leaks a cgroup slot too")

    def test_close_all_nodes_frees_every_cgroup_slot(self):
        """Each open session holds one of ShadowProc's 64 slots; a leaked one
        silently lowers the ceiling for every later configuration."""
        shared = FakeClient()
        own = [FakeClient(), FakeClient()]
        ns = [node(0), node(1, own[0]), node(2, own[1])]
        dgs.close_all_nodes(shared, ns)
        closed = [q for q in shared.requests if q["action"] == "session_close"]
        self.assertEqual([q["session_id"] for q in closed], ["s0"])
        for c in own:
            self.assertTrue(c.closed)
            self.assertTrue(any(q["action"] == "session_close"
                                for q in c.requests))
        self.assertIsNone(ns[1].client, "closed once, not twice")

    def test_close_all_nodes_survives_a_dead_socket(self):
        class Boom(FakeClient):
            def session_close(self, session_id):
                raise RuntimeError("gone")

        dgs.close_all_nodes(Boom(), [node(0), node(1)])   # must not raise


# ─── configuration ─────────────────────────────────────────────────────────

class TestConfiguration(unittest.TestCase):

    def test_no_configured_size_sits_at_or_over_the_cgroup_ceiling(self):
        """ShadowProc's BPF slot table caps concurrent live cgroups at 64 and
        one node holds one for the whole repeat. Every sweep must stay STRICTLY
        below that: a graph needing exactly 64 slots has zero headroom, so a
        single residual slot tips its last session_open over the ceiling --
        which is what killed chain=64. assertLess, not assertLessEqual."""
        for name, sizes in (
                ("chain", dgs.FULL_CHAIN_SIZES), ("fan", dgs.FULL_FAN_SIZES),
                ("scc", dgs.FULL_SCC_SIZES),
                ("concurrent", dgs.FULL_CONCURRENT_SIZES)):
            for s in sizes:
                extra = 1 if name in ("fan", "concurrent") else 0
                self.assertLess(s + extra, dgs.MAX_NODES,
                                f"{name}={s} builds {s + extra} nodes")
        for w in dgs.FULL_DIAMOND_WIDTHS:
            self.assertLess(w + 2, dgs.MAX_NODES)
        self.assertLess(dgs.FULL_DECISION_CHAIN, dgs.MAX_NODES)

    def test_sweeps_cover_the_requested_ranges(self):
        """Chains and SCCs sweep to 32. The chain deliberately stops one step
        below MAX_NODES=64: a 64-node chain needs all 64 cgroup slots at once
        (zero headroom) and fails at the last open, so 32 is the largest chain
        that runs cleanly on this host."""
        self.assertEqual(dgs.FULL_CHAIN_SIZES, [2, 4, 8, 16, 32])
        self.assertEqual(dgs.FULL_SCC_SIZES, [2, 4, 8, 16, 32])
        self.assertEqual(dgs.FULL_DIAMOND_WIDTHS, [2, 4, 8, 16])
        self.assertEqual(dgs.FULL_CONCURRENT_SIZES, [1, 4, 8, 16, 32])
        self.assertEqual(dgs.MAX_NODES, 64)

    def test_quick_is_a_strict_subset_of_full(self):
        for quick, full in ((dgs.QUICK_CHAIN_SIZES, dgs.FULL_CHAIN_SIZES),
                            (dgs.QUICK_FAN_SIZES, dgs.FULL_FAN_SIZES),
                            (dgs.QUICK_SCC_SIZES, dgs.FULL_SCC_SIZES),
                            (dgs.QUICK_CONCURRENT_SIZES,
                             dgs.FULL_CONCURRENT_SIZES),
                            (dgs.QUICK_DIAMOND_WIDTHS,
                             dgs.FULL_DIAMOND_WIDTHS)):
            self.assertTrue(set(quick) <= set(full), f"{quick} vs {full}")

    def test_all_seven_dimensions_are_reachable(self):
        self.assertEqual(dgs.ALL_DIMENSIONS, (1, 2, 3, 4, 5, 6, 7))
        for d in dgs.ALL_DIMENSIONS:
            fn = {1: dgs.run_d1_chain, 2: dgs.run_d2_fan, 3: dgs.run_d3_scc,
                  4: dgs.run_d4_concurrent, 5: dgs.run_d5_decisions,
                  6: dgs.run_d6_diamond, 7: dgs.run_d7_scc_publish}[d]
            self.assertTrue(callable(fn))

    def test_every_dimension_takes_the_observation_and_resource_handles(self):
        """A dimension that forgot them silently loses the graph-shape, memory
        and daemon-CPU columns for its rows only, which is the kind of hole a
        summary table does not show."""
        import inspect
        for fn in (dgs.run_d1_chain, dgs.run_d2_fan, dgs.run_d3_scc,
                   dgs.run_d4_concurrent, dgs.run_d5_decisions,
                   dgs.run_d6_diamond, dgs.run_d7_scc_publish):
            params = list(inspect.signature(fn).parameters)
            self.assertEqual(params[-2:], ["obs", "daemon_res"], fn.__name__)

    def test_pending_retry_budget_outlives_a_reasonable_wait(self):
        budget = dgs.PENDING_RETRY_LIMIT * dgs.PENDING_RETRY_SLEEP_S
        self.assertGreater(budget, 2.0,
                           "the retry budget must exceed one tick of the "
                           "orchestrator's own 2 s background loop, or a member "
                           "that parked gives up before it is published")


if __name__ == "__main__":
    unittest.main(verbosity=2)
