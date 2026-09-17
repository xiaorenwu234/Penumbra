#!/usr/bin/env python3
"""Unit tests for the hs (binpash/hs) baseline engine (root-free parts).

Covers:
  - unwrap_command: bash -c wrappers are unwrapped to the script text,
    other argvs round-trip through shlex quoting (executed to verify)
  - find_hs_root / hs_root_candidates: $HS_ROOT override semantics
  - upperdir_files: whiteouts and ignore-prefix entries are excluded
  - _rmtree_with_chmod: survives a kernel-style 000-mode subdir
  - HsEngine._base_env: the BASH_FUNC_* stubs are imported by child
    bash processes (this is how run_command.sh's scheduler callback and
    the JIT logging shim become no-ops without a daemon)
  - HsEngine: constructor paths, merge_epoch_commands contract, phase
    ordering errors
"""

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.baseline_engine import BaselineEngineError
from framework.hs_engine import (
    HsEngine, _rmtree_with_chmod, find_hs_root, hs_root_candidates,
    unwrap_command, upperdir_files,
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


def make_fake_hs(root: str) -> str:
    """Minimal tree that satisfies the constructor's discovery probe."""
    os.makedirs(os.path.join(root, "executor"), exist_ok=True)
    for rel in ("executor/run_command.sh", "executor/template_script_to_execute.sh",
                "jit_runtime/pash_declare_vars.sh", "deps/try/try"):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
    return root


class TestUnwrapCommand(unittest.TestCase):
    def test_bash_wrapper_is_unwrapped(self):
        self.assertEqual(
            unwrap_command(["bash", "-c", "taskset -c 2 echo hi"]),
            "taskset -c 2 echo hi")
        # merged pin_once form: outer taskset, then the bash -c wrapper
        self.assertEqual(
            unwrap_command(["taskset", "-c", "2", "bash", "-c",
                            "set -e; echo a; echo b"]),
            "taskset -c 2 bash -c 'set -e; echo a; echo b'")

    def test_other_argv_round_trips(self):
        argv = ["echo", "a b", "c'd", 'e"f']
        out = subprocess.run(["bash", "-c", unwrap_command(argv)],
                             capture_output=True, text=True)
        self.assertEqual(out.stdout, "a b c'd e\"f\n")

    def test_unwrapping_preserves_shell_semantics(self):
        script = "printf '%s;%s' 'x y' \"z's\""
        direct = subprocess.run(["bash", "-c", script],
                                capture_output=True, text=True)
        unwrapped = subprocess.run(
            ["bash", "-c", unwrap_command(["bash", "-c", script])],
            capture_output=True, text=True)
        self.assertEqual(direct.stdout, unwrapped.stdout)


class TestFindHsRoot(unittest.TestCase):
    def test_env_override_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = make_fake_hs(os.path.join(tmp, "hsmock"))
            with tmpenv(HS_ROOT=fake):
                self.assertEqual(find_hs_root(), os.path.abspath(fake))

    def test_missing_env_root_is_ignored(self):
        # A bogus HS_ROOT must not shadow discovery of other candidates.
        with tmpenv(HS_ROOT="/nonexistent/hs-root"):
            found = find_hs_root()
        # either nothing is installed, or a real tree is found elsewhere
        self.assertTrue(found is None or os.path.isfile(
            os.path.join(found, "executor", "run_command.sh")))

    def test_candidates_include_rq2_default(self):
        cands = hs_root_candidates()
        self.assertTrue(any(c.endswith(os.path.join("RQ2", "hs"))
                            for c in cands), cands)


class TestUpperdirFiles(unittest.TestCase):
    def test_filters_whiteouts_and_ignores(self):
        with tempfile.TemporaryDirectory() as tmp:
            upper = os.path.join(tmp, "upperdir")
            os.makedirs(os.path.join(upper, "run", "mount"))
            os.makedirs(os.path.join(upper, "data"))
            with open(os.path.join(upper, "data", "kept.txt"), "w") as f:
                f.write("k")
            with open(os.path.join(upper, "run", "mount", "runtime"), "w") as f:
                f.write("r")
            files = upperdir_files(str(upper), ignore_prefixes=("run/mount",))
            self.assertEqual(files, [os.path.join("data", "kept.txt")])

    def test_whiteout_forms_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            upper = os.path.join(tmp, "upperdir")
            os.makedirs(upper)
            wo = os.path.join(upper, "deleted.txt")
            with open(wo, "w") as f:
                f.write("")
            try:
                os.setxattr(wo, "user.overlay.whiteout", b"y")
            except OSError:
                self.skipTest("filesystem does not support user xattrs")
            kept = os.path.join(upper, "kept.txt")
            with open(kept, "w") as f:
                f.write("k")
            files = upperdir_files(str(upper))
            self.assertEqual(files, ["kept.txt"])


class TestRmtreeWithChmod(unittest.TestCase):
    def test_removes_000_mode_subdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sandbox")
            work = os.path.join(target, "workdir", "mnt", "work")
            os.makedirs(work)
            os.chmod(work, 0o000)
            try:
                os.listdir(work)
                self.skipTest("running as root — 000 dirs are readable")
            except PermissionError:
                pass
            _rmtree_with_chmod(target)
            self.assertFalse(os.path.exists(target))


class TestBaseEnvStubs(unittest.TestCase):
    def test_stub_functions_visible_in_child_bash(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = make_fake_hs(os.path.join(tmp, "hsmock"))
            engine = HsEngine(os.path.join(tmp, "engine"),
                              hs_root=fake, verbose=False)
            env = engine._base_env()
            out = subprocess.run(
                ["bash", "-c",
                 "declare -F pash_redir_output "
                 "pash_spec_communicate_scheduler_just_send"],
                env=env, capture_output=True, text=True)
            self.assertIn("pash_redir_output", out.stdout)
            self.assertIn("pash_spec_communicate_scheduler_just_send",
                          out.stdout)
            # and calling them must succeed as no-ops
            call = subprocess.run(
                ["bash", "-c",
                 "pash_redir_output echo ignored; "
                 "pash_spec_communicate_scheduler_just_send msg"],
                env=env, capture_output=True, text=True)
            self.assertEqual(call.returncode, 0)

    def test_runtime_environment_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = make_fake_hs(os.path.join(tmp, "hsmock"))
            engine = HsEngine(os.path.join(tmp, "engine"),
                              hs_root=fake, verbose=False)
            env = engine._base_env()
            self.assertEqual(env["PASH_SPEC_TOP"], fake)
            self.assertTrue(env["RUNTIME_DIR"].endswith("jit_runtime"))
            self.assertTrue(env["RUNTIME_LIBRARY_DIR"].endswith("executor"))


class TestHsEngineContract(unittest.TestCase):
    def test_engine_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = make_fake_hs(os.path.join(tmp, "hsmock"))
            engine = HsEngine(os.path.join(tmp, "engine"),
                              hs_root=fake, verbose=False)
            self.assertEqual(engine.engine_name, "hs")
            # hs's native model is one sandbox per command; only the
            # harness's pin_once workloads merge a multi-command epoch.
            self.assertFalse(engine.merge_epoch_commands)
            self.assertEqual(engine.sleeper_mem_bytes, 0)

    def test_phase_ordering_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = make_fake_hs(os.path.join(tmp, "hsmock"))
            engine = HsEngine(os.path.join(tmp, "engine"),
                              hs_root=fake, verbose=False)
            with self.assertRaises(BaselineEngineError):
                engine.timed_run(["bash", "-c", "true"])
            with self.assertRaises(BaselineEngineError):
                engine.timed_commit()
            with self.assertRaises(BaselineEngineError):
                engine.timed_rollback()
            # session shims are safe no-ops
            engine.session_open()
            engine.refresh()
            engine.session_close()
            engine.recover_failed_epoch()

    def test_setup_reports_missing_prerequisites(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = make_fake_hs(os.path.join(tmp, "hsmock"))
            os.unlink(os.path.join(fake, "executor", "run_command.sh"))
            engine = HsEngine(os.path.join(tmp, "engine"),
                              hs_root=fake, verbose=False)
            with self.assertRaises(BaselineEngineError):
                engine.setup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
