#!/usr/bin/env python3
"""Unit tests for daemon resource sampling and the graph-observation client API.

Two surfaces the RQ3 scalability numbers depend on:

  framework.resources  -- CPU/RSS attribution for ShadowFS, ShadowProc and the
    orchestrator. The risky part is /proc parsing: a wrong field index in
    /proc/<pid>/stat yields plausible-looking numbers that are simply someone
    else's counter, so the parse is cross-checked against an independent
    reading of the same file for a live process.

  orch_client graph helpers -- graph_delta's counter/shape/memory split, and
  wait_epochs_gone's polling contract (an SCC commit may return
  authorized_pending and still be a success).

No daemons are required: tests target their own child processes and fake
clients.
"""

import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework import resources as R
from framework.orch_client import (OrchClient, graph_delta,
                                   GRAPH_COUNTER_KEYS, GRAPH_SHAPE_KEYS,
                                   GRAPH_MEMORY_KEYS)


class _Child:
    """A live process to sample, torn down with the test."""

    def __init__(self, argv=("sleep", "30")):
        self.proc = subprocess.Popen(list(argv),
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        self.pid = self.proc.pid

    def burn_cpu(self, seconds: float = 0.3) -> None:
        """Make the child do real work so cpu_seconds is measurably non-zero."""
        subprocess.run(
            [sys.executable, "-c",
             "import time\n"
             f"end = time.time() + {seconds}\n"
             "while time.time() < end:\n"
             "    sum(i * i for i in range(2000))\n"],
            stdout=subprocess.DEVNULL, check=False)

    def close(self):
        self.proc.kill()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            pass


class TestProcParsing(unittest.TestCase):
    """Field indices in /proc/<pid>/stat are 1-based over the WHOLE line."""

    def test_stat_indices_match_an_independent_parse(self):
        child = _Child()
        self.addCleanup(child.close)
        cpu, threads = R._read_stat(child.pid)

        with open(f"/proc/{child.pid}/stat") as fh:
            raw = fh.read()
        fields = raw[raw.rfind(")") + 2:].split()
        expect_cpu = (int(fields[11]) + int(fields[12])) / float(R.CLK_TCK)

        self.assertAlmostEqual(cpu, expect_cpu, places=9)
        self.assertGreaterEqual(threads, 1)
        # A freshly started sleep has burned almost nothing: a parse that picked
        # up e.g. cutime or a start-time field would be orders of magnitude off.
        self.assertLess(cpu, 5.0)

    def test_stat_survives_a_comm_with_spaces_and_parens(self):
        """comm is field 2 and may contain ' ' and ')'; split on the LAST ')'."""
        synthetic = ("1234 (weird ) name) S 1 1234 1234 0 -1 4194560 "
                     "100 0 0 0 7 3 0 0 20 0 5 0 999 1000 10 "
                     "18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 2 0 0 0")
        fields = synthetic[synthetic.rfind(")") + 2:].split()
        self.assertEqual(fields[0], "S", "state must be the first tail field")
        self.assertEqual(int(fields[11]), 7, "utime")
        self.assertEqual(int(fields[12]), 3, "stime")
        self.assertEqual(int(fields[17]), 5, "num_threads")
        # A naive whitespace split would have landed on a different field
        # entirely, which is the bug this pins down.
        naive = synthetic.split()
        self.assertNotEqual(naive[13], "7")

    def test_rss_is_positive_and_in_bytes(self):
        child = _Child()
        self.addCleanup(child.close)
        rss = R._read_rss(child.pid)
        self.assertGreater(rss, 0)
        # VmRSS is reported in kB; a live interpreter is at least a page.
        self.assertGreater(rss, 4096)

    def test_dead_pid_raises_rather_than_returning_zero(self):
        """A zero would silently read as 'the daemon is idle'."""
        child = _Child(argv=("true",))
        dead = child.pid
        child.proc.wait(timeout=5)
        # Reaped, so /proc/<pid> is gone. (A pid is never reused that fast.)
        self.assertFalse(os.path.exists(f"/proc/{dead}"))
        with self.assertRaises(OSError):
            R._read_stat(dead)
        with self.assertRaises(OSError):
            R._read_rss(dead)
        self.assertFalse(R._pid_alive(dead))

    def test_pid_alive_accepts_a_process_owned_by_someone_else(self):
        # pid 1 is init: not ours to signal, but definitely alive.
        self.assertTrue(R._pid_alive(1))


class TestDiscovery(unittest.TestCase):
    """Env var, then pidfile, then /proc cmdline scan."""

    def test_env_var_wins(self):
        child = _Child()
        self.addCleanup(child.close)
        res = R.DaemonResources(roles=("shadowfs",))
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "fs.pid")
            with open(pidfile, "w") as fh:
                fh.write(str(os.getpid()))
            patched = dict(R._PIDFILE, shadowfs=pidfile)
            old_pidfile, old_env = R._PIDFILE, os.environ.get("SHADOW_FS_PID")
            R._PIDFILE = patched
            os.environ["SHADOW_FS_PID"] = str(child.pid)
            try:
                found = res.discover()
            finally:
                R._PIDFILE = old_pidfile
                if old_env is None:
                    os.environ.pop("SHADOW_FS_PID", None)
                else:
                    os.environ["SHADOW_FS_PID"] = old_env
        self.assertEqual(found, {"shadowfs": child.pid})

    def test_pidfile_used_when_env_is_absent(self):
        child = _Child()
        self.addCleanup(child.close)
        res = R.DaemonResources(roles=("shadowproc",))
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "sp.pid")
            with open(pidfile, "w") as fh:
                fh.write(f"{child.pid}\n")
            old = R._PIDFILE
            R._PIDFILE = dict(old, shadowproc=pidfile)
            os.environ.pop("SHADOW_PROC_PID", None)
            try:
                found = res.discover()
            finally:
                R._PIDFILE = old
        self.assertEqual(found, {"shadowproc": child.pid})

    def test_stale_pidfile_is_ignored(self):
        """A pidfile left by a previous run must not be sampled as a daemon.

        The /proc cmdline scan is disabled here on purpose: it is the last
        fallback and has its own tests below. Left enabled, this test would
        pass or fail depending on whether a real orchestrator happens to be
        running on the host -- and the host is running one exactly when the
        experiment suite is being exercised.
        """
        res = R.DaemonResources(roles=("orchestrator",))
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "orch.pid")
            dead = 2 ** 22
            while os.path.exists(f"/proc/{dead}"):  # pragma: no cover
                dead += 1
            with open(pidfile, "w") as fh:
                fh.write(str(dead))
            old_pidfile = R._PIDFILE
            old_scan = R._scan_proc
            R._PIDFILE = dict(old_pidfile, orchestrator=pidfile)
            R._scan_proc = lambda substrings: 0
            os.environ.pop("SHADOW_ORCH_PID", None)
            try:
                found = res.discover()
            finally:
                R._PIDFILE = old_pidfile
                R._scan_proc = old_scan
        self.assertNotIn("orchestrator", found)
        self.assertEqual(res.missing(), ["orchestrator"])

    def test_cmdline_scan_requires_every_substring(self):
        """A look-alike must not be sampled as the daemon."""
        marker = "rq3-test-shadow-proc-marker"
        child = _Child(argv=(sys.executable, "-c",
                             f"import time; '{marker}'; time.sleep(30)"))
        self.addCleanup(child.close)
        # argv is preserved verbatim in /proc/<pid>/cmdline, marker included.
        self.assertEqual(R._scan_proc((marker,)), child.pid)
        self.assertEqual(R._scan_proc((marker, "--definitely-not-present")), 0)
        self.assertEqual(R._scan_proc(("no-such-daemon-anywhere",)), 0)


class TestResourceWindow(unittest.TestCase):
    """Bracketing a phase yields CPU%, RSS peak and a sample count."""

    def _res_over_self(self, roles=("shadowfs", "shadowproc", "orchestrator")):
        res = R.DaemonResources(roles=roles, poll_interval=0.05)
        res.pids = {r: os.getpid() for r in roles}
        res._discovered = True   # pinned by hand; do not re-discover
        return res

    def test_cpu_is_attributed_to_the_phase(self):
        res = self._res_over_self(roles=("shadowfs",))
        with res.window() as w:
            end = time.time() + 0.35
            while time.time() < end:
                sum(i * i for i in range(3000))
        d = w.result["shadowfs"]
        self.assertTrue(d.found)
        self.assertGreater(d.cpu_seconds, 0.05,
                           "the busy loop must show up as daemon CPU")
        # Single-threaded work: cannot exceed one core by much.
        self.assertLess(d.cpu_pct, 200.0)
        self.assertGreater(d.wall_seconds, 0.3)
        self.assertGreaterEqual(d.samples, 2, "the poller must have run")

    def test_peak_rss_tracks_growth_within_the_phase(self):
        res = self._res_over_self(roles=("shadowfs",))
        keep = []
        with res.window() as w:
            for _ in range(8):
                blob = bytearray(1024 * 1024)
                # Touch every page: a calloc'd buffer is not resident until it
                # is written, so an untouched allocation would prove nothing.
                for i in range(0, len(blob), 4096):
                    blob[i] = 1
                keep.append(blob)
        d = w.result["shadowfs"]
        self.assertGreater(d.rss_end_bytes, d.rss_start_bytes,
                           "8 MiB of touched pages must show up in VmRSS")
        self.assertGreaterEqual(d.rss_peak_bytes, d.rss_end_bytes)
        # No sample-count assertion here: the poller's count is a function of
        # phase duration, and this phase is short. test_cpu_is_attributed_to_the_phase
        # covers the polling behaviour on a phase that outlives the interval.

    def test_a_daemon_that_vanishes_is_reported_not_raised(self):
        child = _Child()
        res = R.DaemonResources(roles=("shadowfs",), poll_interval=0.05)
        res.pids = {"shadowfs": child.pid}
        res._discovered = True
        with res.window() as w:
            child.proc.kill()
            child.proc.wait(timeout=5)
            time.sleep(0.15)
        d = w.result["shadowfs"]
        self.assertFalse(d.found)
        self.assertTrue(d.error, "the reason must be recorded for the table")

    def test_undiscovered_role_degrades_to_a_column_of_zeros(self):
        res = R.DaemonResources(roles=("orchestrator",), poll_interval=0.05)
        res.pids = {}
        res._discovered = True
        with res.window() as w:
            time.sleep(0.05)
        d = w.result["orchestrator"]
        self.assertFalse(d.found)
        self.assertEqual(d.cpu_pct, 0.0)
        self.assertEqual(d.error, "pid not discovered")

    def test_window_stops_the_poller_on_an_exception(self):
        res = self._res_over_self(roles=("shadowfs",))
        before = threading.active_count()
        with self.assertRaises(RuntimeError):
            with res.window() as w:
                raise RuntimeError("phase blew up")
        time.sleep(0.2)
        self.assertLessEqual(threading.active_count(), before)
        self.assertTrue(w.result["shadowfs"].found,
                        "the window must still close and report")


class TestSummarize(unittest.TestCase):
    def test_flat_keys_and_aggregate(self):
        res = R.DaemonResources(roles=R.ROLES, poll_interval=0.05)
        res.pids = {r: os.getpid() for r in R.ROLES}
        res._discovered = True
        with res.window() as w:
            time.sleep(0.05)
        flat = R.summarize(w.result)
        for role in R.ROLES:
            for suffix in ("found", "pid", "cpu_seconds", "cpu_pct",
                           "rss_start_mb", "rss_peak_mb", "rss_delta_mb",
                           "rss_samples"):
                self.assertIn(f"{role}_{suffix}", flat)
        self.assertIn("daemons_cpu_pct", flat)
        self.assertIn("daemons_rss_peak_mb", flat)
        # Three roles sampling the same process: the aggregate peak is 3x.
        self.assertAlmostEqual(
            flat["daemons_rss_peak_mb"],
            sum(flat[f"{r}_rss_peak_mb"] for r in R.ROLES), places=2)

    def test_missing_role_still_produces_its_keys(self):
        flat = R.summarize({"shadowfs": R.ProcDelta(role="shadowfs",
                                                    found=False,
                                                    error="gone")})
        self.assertFalse(flat["shadowfs_found"])
        self.assertEqual(flat["shadowfs_error"], "gone")
        self.assertEqual(flat["daemons_cpu_pct"], 0.0)

    def test_to_dict_is_json_shaped(self):
        import json
        d = R.ProcDelta(role="shadowfs", pid=1, found=True, cpu_pct=12.5)
        json.dumps(d.to_dict())
        json.dumps(R.ProcSample(role="shadowfs", pid=1).to_dict())


class TestGraphDelta(unittest.TestCase):
    """Counters are differenced; shape and memory are taken from the sample."""

    def _snap(self, **over):
        base = {k: 0 for k in GRAPH_COUNTER_KEYS}
        base.update({k: 0 for k in GRAPH_SHAPE_KEYS})
        base.update({k: 0 for k in GRAPH_MEMORY_KEYS})
        base.update(over)
        return base

    def test_counters_difference(self):
        before = self._snap(edge_insertions=3, edge_insert_ns=900,
                            scc_computations=1, scc_compute_ns=500,
                            finalize_rejected_toctou=0, edges=3, epochs=4)
        after = self._snap(edge_insertions=10, edge_insert_ns=2400,
                           scc_computations=5, scc_compute_ns=3000,
                           finalize_rejected_toctou=2, edges=10, epochs=11,
                           heap_alloc_bytes=1 << 20)
        d = graph_delta(before, after)
        self.assertEqual(d["edge_insertions"], 7)
        self.assertEqual(d["edge_insert_ns"], 1500)
        self.assertEqual(d["scc_computations"], 4)
        self.assertEqual(d["scc_compute_ns"], 2500)
        self.assertEqual(d["finalize_rejected_toctou"], 2)

    def test_shape_and_memory_are_snapshots_not_deltas(self):
        """edges=10-3 would be nonsense: the graph is a live structure."""
        before = self._snap(edges=3, epochs=4, heap_alloc_bytes=1 << 20)
        after = self._snap(edges=10, epochs=11, heap_alloc_bytes=3 << 20)
        d = graph_delta(before, after)
        self.assertEqual(d["shape_edges"], 10)
        self.assertEqual(d["shape_epochs"], 11)
        self.assertEqual(d["mem_heap_alloc_bytes"], 3 << 20)
        self.assertNotIn("edges", d)
        self.assertNotIn("heap_alloc_bytes", d)

    def test_missing_fields_read_as_zero(self):
        """An older daemon without the action returns {} for both samples."""
        d = graph_delta({}, {})
        for key in GRAPH_COUNTER_KEYS:
            self.assertEqual(d[key], 0)
        for key in GRAPH_SHAPE_KEYS:
            self.assertIsNone(d[f"shape_{key}"])

    def test_every_counter_key_is_covered(self):
        d = graph_delta(self._snap(), self._snap())
        for key in GRAPH_COUNTER_KEYS:
            self.assertIn(key, d)
        self.assertEqual(len(GRAPH_COUNTER_KEYS), 16)


class _FakeGraphClient(OrchClient):
    """OrchClient with the socket layer replaced by a scripted state list."""

    def __init__(self, states_by_call):
        super().__init__(sock_path="/nonexistent")
        self._script = list(states_by_call)
        self.calls = 0

    def request(self, req):
        self.calls += 1
        if req.get("action") != "epoch_states":
            return {"status": "ok"}
        if self._script:
            return {"status": "ok", "epochs": self._script.pop(0)}
        return {"status": "ok", "epochs": []}


class TestEpochStatePolling(unittest.TestCase):
    def test_returns_immediately_when_the_graph_is_already_empty(self):
        c = _FakeGraphClient([[]])
        ok, elapsed, seen = c.wait_epochs_gone(["ep-A"], timeout=1.0)
        self.assertTrue(ok)
        self.assertEqual(seen, [""])
        self.assertGreaterEqual(elapsed, 0)

    def test_waits_through_authorized_pending_to_finalized(self):
        """The SCC path: members sit authorized, then all leave together."""
        c = _FakeGraphClient([
            [{"epoch_id": "ep-A", "state": "authorized"},
             {"epoch_id": "ep-B", "state": "active"}],
            [{"epoch_id": "ep-A", "state": "finalized"},
             {"epoch_id": "ep-B", "state": "authorized"}],
            [],
        ])
        ok, _, seen = c.wait_epochs_gone(["ep-A", "ep-B"], timeout=2.0,
                                         interval=0.001)
        self.assertTrue(ok)
        self.assertEqual(seen, ["finalized", "authorized"])
        self.assertEqual(c.calls, 3)

    def test_timeout_reports_the_state_it_gave_up_on(self):
        stuck = [{"epoch_id": "ep-A", "state": "authorized"}]
        c = _FakeGraphClient([stuck] * 50)
        ok, elapsed, seen = c.wait_epochs_gone(["ep-A"], timeout=0.1,
                                               interval=0.005)
        self.assertFalse(ok)
        self.assertEqual(seen, ["authorized"])
        self.assertGreater(elapsed, 0)

    def test_unrelated_epochs_are_ignored(self):
        c = _FakeGraphClient([[{"epoch_id": "ep-OTHER", "state": "active"}], []])
        ok, _, seen = c.wait_epochs_gone(["ep-A"], timeout=1.0, interval=0.001)
        self.assertTrue(ok)
        self.assertEqual(seen, [""])


class TestGraphStatsClient(unittest.TestCase):
    def test_graph_object_is_unwrapped(self):
        class C(OrchClient):
            def __init__(self):
                super().__init__(sock_path="/nonexistent")
                self.sent = None

            def request(self, req):
                self.sent = req
                return {"status": "ok", "graph": {"epochs": 5, "edges": 4}}

        c = C()
        self.assertEqual(c.graph_stats(), {"epochs": 5, "edges": 4})
        self.assertEqual(c.sent, {"action": "graph_stats", "reset": False})
        c.graph_stats(reset=True)
        self.assertTrue(c.sent["reset"])

    def test_unsupported_action_yields_an_empty_snapshot(self):
        class C(OrchClient):
            def __init__(self):
                super().__init__(sock_path="/nonexistent")

            def request(self, req):
                return {"status": "error", "message": "unknown action: graph_stats"}

        self.assertEqual(C().graph_stats(), {})
        self.assertEqual(C().epoch_states(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
