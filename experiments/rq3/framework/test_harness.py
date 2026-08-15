#!/usr/bin/env python3
"""Unit tests for the RQ3 WorkloadHarness measurement logic.

Covers the RQ3 fixes:
  - speculative samples are EXCLUDED when the command exits non-zero
    (session_run exit_code) or its output fails verify_fn — a failed run
    is never counted as a fast success
  - multi-command epochs (list of commands in ONE epoch, one transcript
    entry per command) sum run time and verify every command
  - speculative commands are pinned to the same CPU as raw runs (taskset)
  - raw measurements run setup_fn/teardown_fn around EACH invocation,
    symmetric with the speculative loop
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.harness import WorkloadHarness


class FakeClient:
    """In-memory OrchClient substitute with programmable responses."""

    def __init__(self):
        self.rc = 0
        self.output = ""
        self.begin_ns = 1_000
        self.run_ns = 2_000
        self.fin_ns = 3_000
        self.runs = []
        self.rollback_calls = 0
        self.pin_calls = []

    def connect(self):
        pass

    def close(self):
        pass

    def timed_begin_epoch(self, session_id, agent_id):
        return {"status": "ok"}, self.begin_ns

    def timed_pin_epoch_cpu(self, session_id, cpu):
        self.pin_calls.append(cpu)
        return {"status": "ok"}, 1

    def timed_run(self, session_id, command):
        self.runs.append(command)
        return ({"status": "ok", "output": self.output,
                 "exit_code": self.rc}, self.run_ns)

    def timed_commit(self, session_id, agent_id):
        return {"status": "ok"}, self.fin_ns

    def timed_rollback(self, session_id, agent_id):
        self.rollback_calls += 1
        return {"status": "ok"}, self.fin_ns

    def session_rollback_epoch(self, session_id, agent_id):
        self.rollback_calls += 1

    def session_open(self, agent_id):
        return {"status": "ok", "session_id": "s1"}

    def session_close(self, session_id):
        pass


def make_verify(pattern):
    """Same verify builder as run_all.py (regex search in output)."""
    import re
    rx = re.compile(pattern)

    def verify(output):
        if not rx.search(output or ""):
            return f"output {output[:120]!r} does not match {pattern!r}"
        return None
    return verify


class TestSpecCommandValidation(unittest.TestCase):
    """exit_code and verify_fn gate the spec samples."""

    def setUp(self):
        self.client = FakeClient()
        self.h = WorkloadHarness(warmup=0, verbose=False)
        self.h._client = self.client

    def test_nonzero_exit_code_fails_measurement(self):
        self.client.rc = 127
        m = self.h.measure_spec_epoch("s1", "nosuchcmd")
        self.assertFalse(m.success)
        self.assertIn("exited 127", m.error)
        self.assertEqual(self.client.rollback_calls, 1,
                         "failed epoch must be rolled back")

    def test_zero_exit_success(self):
        m = self.h.measure_spec_epoch("s1", "true")
        self.assertTrue(m.success)
        self.assertEqual(m.run_ns, self.client.run_ns)
        self.assertEqual(m.total_ns, 1_000 + 2_000 + 3_000)

    def test_verify_rejects_bad_output(self):
        self.client.output = "written=0"
        m = self.h.measure_spec_epoch(
            "s1", "w4_write_new", verify_fn=make_verify(r"written=16777216"))
        self.assertFalse(m.success)
        self.assertIn("does not match", m.error)

    def test_verify_passes_good_output(self):
        self.client.output = "created=100 write_size=4096"
        m = self.h.measure_spec_epoch(
            "s1", "w7_multifile",
            verify_fn=make_verify(r"created=100 write_size=4096"))
        self.assertTrue(m.success)

    def test_verify_catches_partial_report(self):
        """A tool that exits 0 but truncated (e.g. wrote fewer bytes than
        requested) must be rejected by the output check."""
        self.client.output = "written=8192"
        m = self.h.measure_spec_epoch(
            "s1", "w4_write_new", verify_fn=make_verify(r"written=16777216"))
        self.assertFalse(m.success)
        self.assertEqual(self.client.rollback_calls, 1)

    def test_taskset_prefix_matches_raw_cpu(self):
        with mock.patch("framework.harness.CPU_PIN", 2):
            m = self.h.measure_spec_epoch("s1", "w2_cpu 10")
        self.assertTrue(m.success)
        self.assertEqual(self.client.runs, ["taskset -c 2 w2_cpu 10"])

    def test_no_taskset_when_pin_off(self):
        with mock.patch("framework.harness.CPU_PIN", None):
            m = self.h.measure_spec_epoch("s1", "w2_cpu 10")
        self.assertTrue(m.success)
        self.assertEqual(self.client.runs, ["w2_cpu 10"])

    def test_pin_once_pins_candidate_not_each_command(self):
        """pin_once: one epoch-level pin, NO per-command taskset wrapper."""
        with mock.patch("framework.harness.CPU_PIN", 2):
            m = self.h.measure_spec_epoch(
                "s1", ["w10_output 1024"] * 3, pin_once=True)
        self.assertTrue(m.success)
        # Candidate pinned once for the epoch...
        self.assertEqual(self.client.pin_calls, [2])
        # ...and the N runs carry NO per-run taskset startup.
        self.assertEqual(self.client.runs,
                         ["w10_output 1024"] * 3)

    def test_pin_once_false_still_uses_per_run_taskset(self):
        with mock.patch("framework.harness.CPU_PIN", 2):
            m = self.h.measure_spec_epoch(
                "s1", ["w10_output 1024"] * 2)
        self.assertTrue(m.success)
        self.assertEqual(self.client.pin_calls, [])
        self.assertEqual(self.client.runs,
                         ["taskset -c 2 w10_output 1024"] * 2)


class TestMultiCommandEpoch(unittest.TestCase):
    """A list of commands runs inside ONE epoch (N transcript entries)."""

    def setUp(self):
        self.client = FakeClient()
        self.h = WorkloadHarness(warmup=0, verbose=False)
        self.h._client = self.client

    def test_commands_run_in_order_in_single_epoch(self):
        self.client.output = "total=1024 writes=1"
        m = self.h.measure_spec_epoch(
            "s1", ["w10_output 1024"] * 3,
            verify_fn=make_verify(r"total=1024 writes=1"))
        self.assertTrue(m.success)
        self.assertEqual(len(self.client.runs), 3)
        self.assertEqual(m.run_ns, 3 * self.client.run_ns)
        self.assertEqual(m.begin_ns, self.client.begin_ns)
        self.assertEqual(m.finalize_ns, self.client.fin_ns)
        # finalize ran exactly once: begin + N runs + 1 finalize
        self.assertEqual(m.total_ns,
                         self.client.begin_ns + 3 * self.client.run_ns
                         + self.client.fin_ns)

    def test_any_command_failure_fails_epoch(self):
        class Flaky(FakeClient):
            def timed_run(self, session_id, command):
                self.runs.append(command)
                if len(self.runs) == 2:
                    return {"status": "ok", "output": "", "exit_code": 1}, 5
                return {"status": "ok", "output": "x", "exit_code": 0}, 5
        self.client = Flaky()
        self.h._client = self.client
        m = self.h.measure_spec_epoch("s1", ["a", "b", "c"])
        self.assertFalse(m.success)
        self.assertEqual(self.client.rollback_calls, 1)

    def test_verify_applied_to_every_command(self):
        self.client.output = "total=1024 writes=1"
        m = self.h.measure_spec_epoch(
            "s1", ["w10_output 1024"] * 2,
            verify_fn=make_verify(r"total=1024 writes=1"))
        self.assertTrue(m.success)


class TestMeasureRawSymmetry(unittest.TestCase):
    """Raw loop runs setup_fn/teardown_fn around each invocation."""

    def setUp(self):
        self.h = WorkloadHarness(warmup=2, verbose=False)

    def test_setup_teardown_per_invocation(self):
        calls = []
        with mock.patch.object(self.h, "run_raw") as rr:
            rr.return_value = mock.Mock(
                success=True, elapsed_ns=1000, returncode=0)
            samples, excluded = self.h.measure_raw(
                ["x"], 3,
                setup_fn=lambda: calls.append("setup"),
                teardown_fn=lambda: calls.append("teardown"))
        # warmup 2 + measured 3 = 5 invocations, each bracketed
        self.assertEqual(calls, ["setup", "teardown"] * 5)
        self.assertEqual(len(samples), 3)
        self.assertEqual(excluded, 0)

    def test_setup_teardown_not_called_without_fns(self):
        with mock.patch.object(self.h, "run_raw") as rr:
            rr.return_value = mock.Mock(success=True, elapsed_ns=1)
            samples, _ = self.h.measure_raw(["x"], 2)
        self.assertEqual(len(samples), 2)

    def test_failed_raw_bracketed_and_excluded(self):
        calls = []
        with mock.patch.object(self.h, "run_raw") as rr:
            rr.return_value = mock.Mock(
                success=False, elapsed_ns=0, returncode=1)
            samples, excluded = self.h.measure_raw(
                ["x"], 1,
                setup_fn=lambda: calls.append("s"),
                teardown_fn=lambda: calls.append("t"))
        self.assertEqual(calls, ["s", "t"] * 3)  # warmup 2 + measured 1
        self.assertEqual(samples, [])
        self.assertEqual(excluded, 3)


class TestRunWorkloadPlumbing(unittest.TestCase):
    """run_workload wires verify_fn and raw setup/teardown through."""

    def test_verify_fn_reaches_spec_loop(self):
        client = FakeClient()
        h = WorkloadHarness(warmup=0, verbose=False)
        h._client = client
        client.output = "written=0"
        client.rc = 0
        with mock.patch.object(h, "measure_raw") as mr:
            mr.return_value = ([100.0], 0)
            r = h.run_workload(
                "W4", "new_1MiB", raw_cmd=["w4"], spec_command="w4",
                repeats=2, finalize_modes=["commit"],
                verify_fn=make_verify(r"written=1048576"))
        # all samples excluded: output never matches
        self.assertEqual(r.spec_excluded, 2)
        self.assertEqual(len(r.spec_run_ns), 0)

    def test_raw_gets_setup_teardown(self):
        h = WorkloadHarness(warmup=0, verbose=False)
        with mock.patch.object(h, "measure_raw") as mr, \
                mock.patch.object(h, "measure_spec") as ms:
            mr.return_value = ([1.0], 0)
            ms.return_value = ({"begin": [1.0], "run": [1.0],
                                "finalize": [1.0], "total": [1.0]}, 0)
            h.run_workload("W7", "files_x10", raw_cmd=["w7"],
                           spec_command="w7", repeats=1,
                           setup_fn=lambda: None, teardown_fn=lambda: None)
        kwargs = mr.call_args
        self.assertEqual(kwargs.kwargs["setup_fn"] is not None, True)
        self.assertEqual(kwargs.kwargs["teardown_fn"] is not None, True)


if __name__ == "__main__":
    unittest.main()
