#!/usr/bin/env python3
"""Kernel-side effect decision tests for ShadowProc's BPF hooks.

These tests are disabled by default because they require a live ShadowProc daemon,
root privileges, cgroup v2, and BPF LSM/fmod_ret support.  Enable with:

    SHADOW_RUN_KERNEL_EFFECT_TESTS=1 python3 -m unittest orchestrator.test_kernel_effect_decisions

The tests execute a real syscall (`unshare(0)`, syscall nr 272) from a monitored
cgroup.  `unshare(0)` normally succeeds and has no namespace side effect, so it
is a stable probe for whether the SYSTEM/NAMESPACE hook is actually enforcing
ShadowProc's three-state policy.
"""

import errno
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.policy_ir import CLASS_IDS  # noqa: E402


RUN_KERNEL_TESTS = os.environ.get("SHADOW_RUN_KERNEL_EFFECT_TESTS") == "1"
SOCK_PATH = os.environ.get("SHADOWPROC_SOCK", "/tmp/shadow_proc.sock")
CGROUP_ROOT = os.environ.get("SHADOW_CGROUP_ROOT", "/sys/fs/cgroup")


class ShadowProcClient:
    def __init__(self, sock_path):
        self.sock_path = sock_path

    def request(self, req):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.sock_path)
            f = s.makefile("rw", buffering=1)
            f.write(json.dumps(req) + "\n")
            f.flush()
            line = f.readline()
        if not line:
            raise RuntimeError(f"empty response for {req}")
        resp = json.loads(line)
        if resp.get("status") != "ok":
            raise RuntimeError(f"{req['action']} failed: {resp}")
        return resp


class TestKernelEffectDecisions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RUN_KERNEL_TESTS:
            raise unittest.SkipTest("set SHADOW_RUN_KERNEL_EFFECT_TESTS=1 to run live BPF tests")
        if os.geteuid() != 0:
            raise unittest.SkipTest("live BPF tests require root")
        if not os.path.exists(SOCK_PATH):
            raise unittest.SkipTest(f"ShadowProc socket not found: {SOCK_PATH}")
        if not os.path.isdir(CGROUP_ROOT) or not os.access(CGROUP_ROOT, os.W_OK):
            raise unittest.SkipTest(f"cgroup root not writable: {CGROUP_ROOT}")
        cls.client = ShadowProcClient(SOCK_PATH)

    def setUp(self):
        self.name = f"shadow-kernel-effect-{os.getpid()}-{int(time.time() * 1000)}"
        self.cgroup_path = os.path.join(CGROUP_ROOT, self.name)
        self.cgroup_id = f"/{self.name}"
        os.mkdir(self.cgroup_path)
        self.client.request({"action": "add_cgroup", "cgroup_path": self.cgroup_path})
        self.children = []

    def tearDown(self):
        for proc in self.children:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            self.client.request({"action": "kill_by_cgroup", "cgroup_id": self.cgroup_id})
        except Exception:
            pass
        try:
            self.client.request({"action": "clear_all_policies", "cgroup_path": self.cgroup_path})
        except Exception:
            pass
        try:
            self.client.request({"action": "remove_cgroup", "cgroup_path": self.cgroup_path})
        except Exception:
            pass
        shutil.rmtree(self.cgroup_path, ignore_errors=True)

    def _spawn_unshare_probe(self):
        read_fd, write_fd = os.pipe()
        code = r'''
import ctypes, errno, os, sys
fd = int(os.environ["SHADOW_GO_FD"])
os.read(fd, 1)
ctypes.set_errno(0)
ret = ctypes.CDLL(None, use_errno=True).syscall(272, 0)
err = ctypes.get_errno()
print(f"ret={ret} errno={err}", flush=True)
sys.exit(0 if ret == 0 else min(err or 1, 125))
'''
        env = dict(os.environ, SHADOW_GO_FD=str(read_fd))
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            pass_fds=(read_fd,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        os.close(read_fd)
        self.children.append(proc)
        with open(os.path.join(self.cgroup_path, "cgroup.procs"), "w") as fh:
            fh.write(str(proc.pid))
        return proc, write_fd

    def _release_probe(self, write_fd):
        os.write(write_fd, b"x")
        os.close(write_fd)

    def test_speculative_mode_fences_system_namespace_syscall(self):
        proc, write_fd = self._spawn_unshare_probe()
        self._release_probe(write_fd)
        deadline = time.time() + 3
        frozen = []
        while time.time() < deadline:
            frozen = self.client.request({"action": "list_frozen", "cgroup_id": self.cgroup_id}).get("frozen", [])
            if frozen:
                break
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        self.assertTrue(frozen, "SYSTEM/NAMESPACE syscall was not fenced by BPF")
        self.assertEqual(frozen[0].get("syscall"), "unshare")
        self.assertEqual(frozen[0].get("event_type"), "SYSTEM")

    def test_enforced_mode_denies_system_without_policy(self):
        self.client.request({"action": "set_epoch_mode", "cgroup_path": self.cgroup_path, "mode": 2})
        proc, write_fd = self._spawn_unshare_probe()
        self._release_probe(write_fd)
        out, err = proc.communicate(timeout=3)
        self.assertNotEqual(proc.returncode, 0, f"unshare unexpectedly succeeded: stdout={out} stderr={err}")
        self.assertIn(f"errno={errno.EPERM}", out)

    def test_enforced_mode_allows_system_with_explicit_class_policy(self):
        self.client.request({
            "action": "install_class_policy",
            "cgroup_path": self.cgroup_path,
            "effect_class": CLASS_IDS["SYSTEM"],
            "allow": 1,
        })
        self.client.request({"action": "set_epoch_mode", "cgroup_path": self.cgroup_path, "mode": 2})
        proc, write_fd = self._spawn_unshare_probe()
        self._release_probe(write_fd)
        out, err = proc.communicate(timeout=3)
        self.assertEqual(proc.returncode, 0, f"unshare denied despite SYSTEM allow: stdout={out} stderr={err}")
        self.assertIn("ret=0 errno=0", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
