#!/usr/bin/env python3
"""Unit tests for the overlayfs+CRIU baseline engine (root-free parts).

Covers:
  - promote_upper_to_lower: new files, modified files, whiteouts,
    symlinks, subdirectories, whiteout-of-file-replaced-by-dir
  - build_run_command: per-run taskset, pin_once single-wrapper policy
"""

import contextlib
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.baseline_engine import (
    OverlayCriuEngine, build_run_command, default_memhold_bin, is_whiteout,
    promote_upper_to_lower, sleeper_payload, _proc_rss_bytes, SLEEPER_ARGV0,
)


def make_whiteout(path):
    """Create an overlayfs-style whiteout (char device 0:0).

    Requires CAP_MKNOD (root); tests that use it are skipped otherwise.
    """
    os.mknod(path, 0o0600 | stat.S_IFCHR, 0)


requires_root = unittest.skipUnless(
    os.geteuid() == 0, "creating whiteout devices requires root (mknod)")


class PromoteTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rq3-baseline-test-")
        self.upper = os.path.join(self.tmp, "upper")
        self.lower = os.path.join(self.tmp, "lower")
        os.makedirs(os.path.join(self.upper, "sub"))
        os.makedirs(os.path.join(self.lower, "sub"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def w_upper(self, rel, data):
        p = os.path.join(self.upper, rel)
        with open(p, "w") as f:
            f.write(data)
        return p

    def w_lower(self, rel, data):
        p = os.path.join(self.lower, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(data)
        return p

    def read_lower(self, rel):
        with open(os.path.join(self.lower, rel)) as f:
            return f.read()

    def test_new_file_promoted(self):
        self.w_upper("newfile.bin", "spec")
        promote_upper_to_lower(self.upper, self.lower)
        self.assertEqual(self.read_lower("newfile.bin"), "spec")

    def test_modified_file_overwrites_lower(self):
        self.w_lower("existing.bin", "orig")
        self.w_upper("existing.bin", "modified")
        promote_upper_to_lower(self.upper, self.lower)
        self.assertEqual(self.read_lower("existing.bin"), "modified")

    @requires_root
    def test_whiteout_deletes_lower_file(self):
        self.w_lower("doomed.bin", "orig")
        make_whiteout(os.path.join(self.upper, "doomed.bin"))
        promote_upper_to_lower(self.upper, self.lower)
        self.assertFalse(
            os.path.exists(os.path.join(self.lower, "doomed.bin")))

    @requires_root
    def test_whiteout_removes_lower_directory(self):
        self.w_lower("doomeddir/a", "x")
        self.w_lower("doomeddir/b", "y")
        os.makedirs(os.path.join(self.upper, "doomeddir"))
        make_whiteout(os.path.join(self.upper, "doomeddir"))
        promote_upper_to_lower(self.upper, self.lower)
        self.assertFalse(os.path.exists(os.path.join(self.lower, "doomeddir")))

    def test_upper_dir_shadowing_lower_file(self):
        # A directory created in upper replaces a lower file of the same name
        self.w_lower("path", "file-content")
        os.makedirs(os.path.join(self.upper, "path"))
        self.w_upper("path/inner.bin", "z")
        promote_upper_to_lower(self.upper, self.lower)
        self.assertTrue(
            os.path.isdir(os.path.join(self.lower, "path")))
        self.assertEqual(self.read_lower("path/inner.bin"), "z")

    def test_nested_directories_promoted(self):
        os.makedirs(os.path.join(self.upper, "sub/deep/deeper"))
        self.w_upper("sub/deep/deeper/f.bin", "deep")
        promote_upper_to_lower(self.upper, self.lower)
        self.assertEqual(self.read_lower("sub/deep/deeper/f.bin"), "deep")

    def test_symlink_promoted(self):
        self.w_upper("target.bin", "t")
        os.symlink("target.bin", os.path.join(self.upper, "link"))
        promote_upper_to_lower(self.upper, self.lower)
        self.assertTrue(os.path.islink(os.path.join(self.lower, "link")))
        self.assertEqual(
            os.readlink(os.path.join(self.lower, "link")), "target.bin")

    def test_empty_upper_is_noop(self):
        self.w_lower("keep.bin", "keep")
        promote_upper_to_lower(self.upper, self.lower)
        self.assertEqual(self.read_lower("keep.bin"), "keep")

    def test_file_content_preserved_bytewise(self):
        data = bytes(range(256)) * 100
        p = os.path.join(self.upper, "blob.bin")
        with open(p, "wb") as f:
            f.write(data)
        promote_upper_to_lower(self.upper, self.lower)
        with open(os.path.join(self.lower, "blob.bin"), "rb") as f:
            self.assertEqual(f.read(), data)


class WhiteoutDetectionTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rq3-wh-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_regular_file_is_not_whiteout(self):
        p = os.path.join(self.tmp, "f")
        with open(p, "w") as f:
            f.write("x")
        self.assertFalse(is_whiteout(p))

    @requires_root
    def test_char_zero_device_is_whiteout(self):
        p = os.path.join(self.tmp, "w")
        make_whiteout(p)
        self.assertTrue(is_whiteout(p))

    def test_missing_path_is_not_whiteout(self):
        self.assertFalse(is_whiteout(os.path.join(self.tmp, "nope")))


class BuildRunCommandTestCase(unittest.TestCase):
    def test_single_command_with_pin(self):
        argv = build_run_command("w2_cpu 10", cpu_pin=2)
        self.assertEqual(argv, ["bash", "-c", "taskset -c 2 w2_cpu 10"])

    def test_single_command_without_pin(self):
        argv = build_run_command("w2_cpu 10", cpu_pin=None)
        self.assertEqual(argv, ["bash", "-c", "w2_cpu 10"])

    def test_pin_once_batch_single_wrapper(self):
        argv = build_run_command(None, cpu_pin=3,
                                 commands=["a 1", "b 2", "c 3"],
                                 pin_once=True)
        # ONE outer taskset + ONE bash: every command inherits the affinity,
        # matching the Penumbra epoch-level pin (no per-command wrapper).
        self.assertEqual(
            argv,
            ["taskset", "-c", "3", "bash", "-c",
             "set -e; a 1; b 2; c 3"])

    def test_pin_once_batch_without_pin(self):
        argv = build_run_command(None, cpu_pin=None,
                                 commands=["a 1", "b 2"], pin_once=True)
        self.assertEqual(argv, ["bash", "-c", "set -e; a 1; b 2"])


class SleeperSpawnTestCase(unittest.TestCase):
    """_spawn_sleeper must return only when the sleeper is READY (marker
    argv[0] visible in /proc/<pid>/cmdline), not merely forked.

    Regression test: fork → exec bash → bash startup → exec sleep takes
    ~2 ms; reading cmdline inside that window shows "bash" or "" and
    _sleeper_alive() misreported a healthy sleeper as dead (smoke test
    failure "sleeper process died before dump").
    """

    def test_spawn_waits_for_marker_argv0(self):
        with tempfile.TemporaryDirectory(prefix="rq3-sleeper-") as tmp:
            eng = OverlayCriuEngine(tmp, verbose=False)
            eng.setup()
            try:
                eng._spawn_sleeper()
                # Returned without raising => the marker argv[0] must
                # already be visible (no mid-exec race left for callers).
                self.assertTrue(eng._sleeper_alive())
                self.assertIsNotNone(eng._sleeper_pid)
            finally:
                eng._kill_sleeper()
            # Killed => tracked PID cleared => not alive
            self.assertFalse(eng._sleeper_alive())

    def test_spawn_failure_raises_not_hangs(self):
        """A sleeper that exits immediately must raise a clear error
        instead of timing out the 10 s readiness wait."""
        import time
        from unittest import mock
        import framework.baseline_engine as be

        fake = mock.Mock()
        fake.pid = 999999999      # nonexistent PID: _sleeper_alive() -> False
        fake.poll.return_value = 42   # child already exited with rc 42
        fake.returncode = 42
        with tempfile.TemporaryDirectory(prefix="rq3-sleeper-die-") as tmp:
            eng = be.OverlayCriuEngine(tmp, verbose=False)
            eng.setup()
            with mock.patch.object(be.subprocess, "Popen",
                                   return_value=fake):
                t0 = time.monotonic()
                with self.assertRaises(be.BaselineEngineError) as cm:
                    eng._spawn_sleeper()
            self.assertLess(time.monotonic() - t0, 5.0)
            self.assertIn("rc=42", str(cm.exception))


class CriuCommandLineTestCase(unittest.TestCase):
    """The constructed criu argv must use only flags that really exist in
    criu 4.2.1's CLI, with optional-argument values attached correctly.

    Regression: two fabricated/misused CLI spellings reached the smoke test
    before being caught — a nonexistent --log-level option, and
    '--verbosity 2' (space form): verbosity is an optional_argument in
    criu's getopt table, so the detached '2' survived as a positional
    argument → 'excessive parameter for command dump'.
    """

    # Flags verified against `criu --help` of the vendored 4.2.1 build.
    KNOWN_DUMP_FLAGS = {"-t", "--images-dir", "--leave-running",
                        "--verbosity=2", "--log-file"}
    KNOWN_RESTORE_FLAGS = {"--images-dir", "-d", "--verbosity=2",
                           "--log-file"}

    def _capture(self, engine_method, **patches):
        from unittest import mock
        captured = {}

        def fake_run_criu(args, timeout=None):
            captured["args"] = list(args)
            r = mock.Mock()
            r.returncode = 0
            r.stderr = ""
            return r

        ctxs = [mock.patch.object(patches["engine"], "_run_criu",
                                  side_effect=fake_run_criu)]
        for name, val in patches.get("als", {}).items():
            ctxs.append(mock.patch.object(patches["engine"], name,
                                          **val))
        with contextlib.ExitStack() as stack:
            for c in ctxs:
                stack.enter_context(c)
            engine_method()
        return captured["args"]

    def test_dump_command_uses_valid_cli(self):
        with tempfile.TemporaryDirectory(prefix="rq3-cli-") as tmp:
            eng = OverlayCriuEngine(tmp, verbose=False, criu_bin="/bin/true")
            eng.setup()
            eng._sleeper_pid = 12345
            args = self._capture(
                eng.timed_begin_epoch, engine=eng,
                als={"_sleeper_alive": {"return_value": True}})
            self.assertEqual(args[0], "dump")
            # optional-argument value must be attached with '='
            self.assertNotIn("--verbosity", args)
            self.assertIn("--verbosity=2", args)
            for a in args[1:]:
                if a.startswith("-"):
                    self.assertIn(
                        a, self.KNOWN_DUMP_FLAGS,
                        f"unknown or fabricated criu flag: {a!r}")

    def test_restore_command_uses_valid_cli(self):
        with tempfile.TemporaryDirectory(prefix="rq3-cli-") as tmp:
            eng = OverlayCriuEngine(tmp, verbose=False, criu_bin="/bin/true")
            eng.setup()
            eng._sleeper_pid = 12345
            args = self._capture(
                eng.timed_rollback, engine=eng,
                als={"_kill_sleeper": {},
                     "_find_sleeper_pid": {"return_value": 54321},
                     "_reset_upper": {}})
            self.assertEqual(args[0], "restore")
            self.assertNotIn("--verbosity", args)
            self.assertIn("--verbosity=2", args)
            self.assertIn("-d", args)
            for a in args[1:]:
                if a.startswith("-"):
                    self.assertIn(
                        a, self.KNOWN_RESTORE_FLAGS,
                        f"unknown or fabricated criu flag: {a!r}")


class TimedRunStreamsTestCase(unittest.TestCase):
    """timed_run must return stdout AND stderr concatenated.

    Regression: the Penumbra session log captures both streams (session_proxy
    dup2's the log fd onto fd 1 and 2), so verify_fn regexes match against
    combined text. The W9 benchmark (w10_output) prints its 'total=N
    writes=M' metadata to stderr on purpose; capturing stdout only made
    every W9 baseline sample fail verify (all-excluded).
    """

    def test_stdout_and_stderr_both_captured(self):
        with tempfile.TemporaryDirectory(prefix="rq3-run-") as tmp:
            eng = OverlayCriuEngine(tmp, verbose=False, criu_bin="/bin/true")
            eng.setup()
            rc, out, _ns = eng.timed_run(
                ["bash", "-c", "echo pattern-data; echo total=1024 writes=1 >&2"])
            self.assertEqual(rc, 0)
            self.assertIn("pattern-data", out)      # stdout
            self.assertIn("total=1024 writes=1", out)  # stderr


class SleeperPayloadTestCase(unittest.TestCase):
    """W10: the checkpointed session process carries a resident payload."""

    def test_default_payload_is_plain_sleeper(self):
        self.assertEqual(
            sleeper_payload(0),
            f"exec -a {SLEEPER_ARGV0} sleep infinity")

    def test_memory_payload_execs_memhold_with_exact_bytes(self):
        s = sleeper_payload(268435456, memhold_bin="/x/w10_memhold")
        self.assertIn(f"exec -a {SLEEPER_ARGV0} ", s)
        self.assertIn("/x/w10_memhold 268435456", s)

    def test_proc_rss_bytes_reads_a_live_process(self):
        self.assertGreater(_proc_rss_bytes(os.getpid()), 0)
        self.assertEqual(_proc_rss_bytes(-1), 0)

    def test_memhold_spawn_waits_for_full_rss(self):
        """_spawn_sleeper must not return until the payload is resident:
        criu dumps whatever RSS exists at dump time, so returning mid-touch
        would make the snapshot size depend on spawn timing."""
        binp = default_memhold_bin()
        if not os.path.isfile(binp):
            self.skipTest("w10_memhold not built (run make in benchmarks/)")
        with tempfile.TemporaryDirectory(prefix="rq3-mem-") as tmp:
            eng = OverlayCriuEngine(tmp, verbose=False, criu_bin="/bin/true")
            eng.setup()
            eng.sleeper_mem_bytes = 16 * 1024 * 1024
            try:
                eng._spawn_sleeper()   # must block until RSS >= 16 MiB
                self.assertTrue(eng._sleeper_alive())
                self.assertGreaterEqual(
                    _proc_rss_bytes(eng._sleeper_pid),
                    eng.sleeper_mem_bytes)
            finally:
                eng._kill_sleeper()


class KillSleeperPollGranularityTestCase(unittest.TestCase):
    """_kill_sleeper's non-child branch must poll at ~1ms granularity.

    Regression: that branch used time.sleep(0.05). Because the SIGKILLed
    restored sleeper lingers as a zombie until init reaps it, the first
    /proc check virtually always still sees it, so every shared-session
    rollback phase paid one full 50ms sleep (measured: 61ms shared vs
    11.6ms fresh sessions) — inflating the CRIU baseline's rollback
    numbers ~2x against Penumbra.
    """

    MARKER = "rq3-killtest"

    def _spawn_detached_marker(self):
        """Spawn a marker process that is NOT our child (setsid + shell
        exit reparents it), mimicking the post-restore sleeper."""
        import subprocess as sp
        sp.run(["bash", "-c",
                f"setsid bash -c 'exec -a {self.MARKER} sleep 30' "
                "</dev/null >/dev/null 2>&1 &"], check=True)
        import time as _t
        deadline = _t.time() + 5
        while _t.time() < deadline:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry}/cmdline", "rb") as f:
                        if f.read().split(b"\x00")[0] == self.MARKER.encode():
                            return int(entry)
                except OSError:
                    continue
            _t.sleep(0.01)
        return None

    def test_non_child_kill_polls_at_1ms(self):
        import time as _t
        from unittest import mock
        import framework.baseline_engine as be
        pid = self._spawn_detached_marker()
        self.assertIsNotNone(pid, "detached marker process not found")
        sleeps = []
        with tempfile.TemporaryDirectory(prefix="rq3-kill-") as tmp:
            eng = be.OverlayCriuEngine(tmp, verbose=False)
            eng._sleeper_pid = pid
            eng._sleeper_child = None          # force the non-child branch
            with mock.patch.object(be.time, "sleep",
                                   side_effect=lambda s: sleeps.append(s)):
                t0 = _t.perf_counter()
                eng._kill_sleeper()
                elapsed = _t.perf_counter() - t0
        # Belt and braces: no pathological spin, and the process is gone.
        self.assertLess(elapsed, 2.0)
        self.assertFalse(os.path.exists(f"/proc/{pid}"))
        # The actual regression check: every poll sleep must be ~1ms,
        # never the old 50ms quantization.
        self.assertTrue(sleeps, "kill loop never slept — process vanished "
                        "before the first check; test is vacuous")
        self.assertTrue(all(s <= 0.002 for s in sleeps),
                        f"poll granularity regressed: {sleeps}")


if __name__ == "__main__":
    unittest.main()
