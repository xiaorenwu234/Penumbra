#!/usr/bin/env python3
"""Unit tests for the try (OSDI'26) baseline engine (root-free parts).

Covers:
  - build_try_command: single-argument quoting survives try's `source`
    step (including single quotes, spaces, pin_once merged scripts)
  - is_overlay_whiteout: regular files/dirs are not whiteouts; char(0,0)
    devices are (root-only to create)
  - find_try_binary / find_try_utils_dir: $TRY_BIN / $TRY_UTILS_DIR
    override semantics and executable checks
  - TryEngine: constructor validation, merge_epoch_commands contract,
    _upperdir_remaining leftovers accounting (whiteouts and directory
    skeletons are expected; anything else means an unapplied effect)
"""

import contextlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.baseline_engine import BaselineEngineError, build_run_command
from framework.try_engine import (
    TryEngine, build_try_command, find_try_binary, find_try_utils_dir,
    is_overlay_whiteout,
)


@contextlib.contextmanager
def tmpenv(**kv):
    """Temporarily set/remove environment variables (None removes)."""
    old = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def make_executable(path):
    with open(path, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(path, 0o755)
    return path


requires_root = unittest.skipUnless(
    os.geteuid() == 0, "creating whiteout devices requires root (mknod)")


class BuildTryCommandTestCase(unittest.TestCase):
    """The built string is what try writes to script_to_execute.sh and
    *sources*; run it through `sh` as a source-equivalent and verify the
    command's effect survives quoting."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rq3-try-cmd-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_source_equiv(self, argv):
        cmd = build_try_command(argv)
        script = os.path.join(self.tmp, "script_to_execute.sh")
        with open(script, "w") as f:
            f.write(cmd)
        return subprocess.run(["sh", script], cwd=self.tmp,
                              capture_output=True, text=True)

    def test_single_quoted_inner_command(self):
        # harness pattern: bash -c "<cmd>"
        r = self.run_source_equiv(
            ["bash", "-c", "echo hi > out.txt"])
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.tmp, "out.txt")) as f:
            self.assertEqual(f.read().strip(), "hi")

    def test_embedded_single_quotes_survive(self):
        r = self.run_source_equiv(
            ["bash", "-c", "printf '%s' 'quoted value' > out2.txt"])
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.tmp, "out2.txt")) as f:
            self.assertEqual(f.read(), "quoted value")

    def test_merged_pin_once_script(self):
        # BaselineHarness pin_once path: one outer taskset around a
        # multi-command bash script.
        argv = build_run_command(
            None, None, commands=["echo a >> log.txt", "echo b >> log.txt"],
            pin_once=True)
        r = self.run_source_equiv(argv)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.tmp, "log.txt")) as f:
            self.assertEqual(f.read().split(), ["a", "b"])

    def test_shell_metachars_are_inert(self):
        r = self.run_source_equiv(
            ["bash", "-c", "echo '$HOME `whoami`' > meta.txt"])
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.tmp, "meta.txt")) as f:
            self.assertEqual(f.read().strip(), "$HOME `whoami`")


class FindTryTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rq3-try-find-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_try_bin_override_used(self):
        binpath = make_executable(os.path.join(self.tmp, "try"))
        with tmpenv(TRY_BIN=binpath):
            self.assertEqual(find_try_binary(), binpath)

    def test_try_bin_override_missing_yields_none(self):
        # An explicit override that is invalid must NOT silently fall back.
        with tmpenv(TRY_BIN=os.path.join(self.tmp, "nope")):
            self.assertIsNone(find_try_binary())

    def test_utils_dir_requires_both_binaries(self):
        utils = os.path.join(self.tmp, "utils")
        os.makedirs(utils)
        make_executable(os.path.join(utils, "try-commit"))
        with tmpenv(TRY_UTILS_DIR=utils):
            # try-summary missing -> rejected
            self.assertIsNone(find_try_utils_dir(None))
        make_executable(os.path.join(utils, "try-summary"))
        with tmpenv(TRY_UTILS_DIR=utils):
            self.assertEqual(find_try_utils_dir(None), utils)

    def test_utils_dir_inferred_next_to_binary(self):
        root = os.path.join(self.tmp, "tryroot")
        utils = os.path.join(root, "utils")
        os.makedirs(utils)
        binpath = make_executable(os.path.join(root, "try"))
        make_executable(os.path.join(utils, "try-commit"))
        make_executable(os.path.join(utils, "try-summary"))
        with tmpenv(TRY_UTILS_DIR=None):
            self.assertEqual(find_try_utils_dir(binpath), utils)


class WhiteoutTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rq3-try-wo-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_regular_file_is_not_whiteout(self):
        p = os.path.join(self.tmp, "f.txt")
        with open(p, "w") as f:
            f.write("x")
        self.assertFalse(is_overlay_whiteout(p))

    def test_directory_is_not_whiteout(self):
        p = os.path.join(self.tmp, "d")
        os.makedirs(p)
        self.assertFalse(is_overlay_whiteout(p))

    def test_missing_path_is_not_whiteout(self):
        self.assertFalse(is_overlay_whiteout(
            os.path.join(self.tmp, "missing")))

    @requires_root
    def test_char_device_00_is_whiteout(self):
        p = os.path.join(self.tmp, "wo")
        os.mknod(p, 0o0600 | stat.S_IFCHR, 0)
        self.assertTrue(is_overlay_whiteout(p))


class TryEngineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rq3-try-engine-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_engine(self):
        binpath = make_executable(os.path.join(self.tmp, "try"))
        with tmpenv(TRY_BIN=binpath):
            return TryEngine(os.path.join(self.tmp, "root"), verbose=False)

    def test_constructor_requires_try_binary(self):
        with tmpenv(TRY_BIN=os.path.join(self.tmp, "missing")):
            with self.assertRaises(BaselineEngineError):
                TryEngine(os.path.join(self.tmp, "root"), verbose=False)

    def test_harness_contract_attributes(self):
        engine = self.make_engine()
        # BaselineHarness reads these:
        self.assertEqual(engine.engine_name, "try")
        self.assertTrue(engine.merge_epoch_commands)
        self.assertEqual(engine.sleeper_mem_bytes, 0)
        self.assertEqual(engine.lower, engine.mnt)  # live tree is both
        # W10 payload assignment is accepted and ignored (interface compat)
        engine.sleeper_mem_bytes = 64 * 1024 * 1024
        self.assertEqual(engine.sleeper_mem_bytes, 64 * 1024 * 1024)

    def test_session_noops(self):
        engine = self.make_engine()
        engine.session_open()   # must not raise
        engine.session_close()
        engine.refresh()

    def test_run_without_begin_raises(self):
        engine = self.make_engine()
        with self.assertRaises(BaselineEngineError):
            engine.timed_run(["true"])
        with self.assertRaises(BaselineEngineError):
            engine.timed_commit()

    def test_upperdir_remaining_ignores_skeletons_and_whiteouts(self):
        engine = self.make_engine()
        sandbox = os.path.join(self.tmp, "sandbox")
        upper = os.path.join(sandbox, "upperdir")
        # Directory skeleton (per top-level mountpoint) — expected leftover
        os.makedirs(os.path.join(upper, "tmp", "work"))
        # An unapplied effect (regular file) — must be reported
        eff = os.path.join(upper, "tmp", "work", "pending.bin")
        with open(eff, "w") as f:
            f.write("x")
        engine._sandbox = sandbox
        self.assertEqual(engine._upperdir_remaining(), [eff])

    @requires_root
    def test_upperdir_remaining_skips_whiteout(self):
        engine = self.make_engine()
        sandbox = os.path.join(self.tmp, "sandbox2")
        upper = os.path.join(sandbox, "upperdir")
        os.makedirs(os.path.join(upper, "tmp"))
        os.mknod(os.path.join(upper, "tmp", "deleted.bin"),
                 0o0600 | stat.S_IFCHR, 0)
        engine._sandbox = sandbox
        self.assertEqual(engine._upperdir_remaining(), [])

    def test_discard_sandbox_is_idempotent(self):
        engine = self.make_engine()
        engine._discard_sandbox()  # no sandbox -> no-op
        engine._sandbox = os.path.join(self.tmp, "ghost")
        engine._discard_sandbox()  # missing dir -> no-op, no raise
        self.assertIsNone(engine._sandbox)


if __name__ == "__main__":
    unittest.main(verbosity=2)
