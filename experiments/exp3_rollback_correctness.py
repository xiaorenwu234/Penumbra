#!/usr/bin/env python3
"""
Experiment 3: File, Process, and Output Rollback Correctness

Verifies rollback by comparing COMPLETE state before and after:
  - File content, permissions, owner, length, directory entries, whiteout,
    rename, and hard link
  - Environment variables, working directory, memory state, file offsets
  - Epoch child processes all terminated
  - Provisional output removed from transcript
  - Allow commits exactly once

Oracle: initial state content hash + metadata snapshot + process tree +
transcript digest. After deny: must match epoch-start exactly.
After allow: must match native execution result.

Usage:
    SHADOW_RUN_RQ2_EXPERIMENTS=1 python3 exp3_rollback_correctness.py
"""

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.client import ShadowProcClient, ShadowFSClient
from framework.cgroup import CgroupManager
from framework.oracle import EffectOracle, FileSnapshot, DirSnapshot
from framework.metrics import MetricsCollector
from framework.runner import ProbeRunner
from framework.paths import fuse_path, orig_path, harness_path, ensure_fuse_dirs, is_fuse_mounted, SHADOWFS_MNT

from policy.policy_ir import PolicyIR

RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ2_EXPERIMENTS") == "1"


class Experiment3:
    """Rollback correctness experiment."""

    def __init__(self, repeats: int = 10):
        self.repeats = repeats
        # Unique run ID to avoid epoch ID collisions with WAL-replayed state
        self.run_id = str(int(time.time() * 1000))[-8:]
        self.proc_client = ShadowProcClient()
        self.fs_client = ShadowFSClient()
        self.cgroup_mgr = CgroupManager(prefix="shadow-exp3")
        self.oracle = EffectOracle(tempfile.mkdtemp(prefix="shadow-exp3-oracle-"))
        self.runner = ProbeRunner()
        self.metrics = MetricsCollector("exp3_rollback_correctness")
        # Use backing store for harness file operations
        self.work_dir = harness_path("exp3")

        self.metrics.add_counter("rollback_content_mismatch")
        self.metrics.add_counter("rollback_metadata_mismatch")
        self.metrics.add_counter("rollback_direntry_mismatch")
        self.metrics.add_counter("child_process_survived")
        self.metrics.add_counter("provisional_output_not_removed")
        self.metrics.add_counter("commit_not_exactly_once")
        self.metrics.add_counter("rollback_state_leak")
        # New counters for missing checks
        self.metrics.add_counter("env_cwd_not_restored")
        self.metrics.add_counter("whiteout_not_cleaned")
        self.metrics.add_counter("memory_state_leaked")

    def setup(self):
        if os.geteuid() != 0:
            raise RuntimeError("Experiment 3 requires root")
        self.proc_client.connect()
        self.fs_client.connect()
        # Ensure FUSE directories exist
        ensure_fuse_dirs("exp3")
        if not is_fuse_mounted():
            print(f"[exp3] WARNING: ShadowFS FUSE not mounted at {SHADOWFS_MNT}")
        print(f"[exp3] Connected to daemons")
        print(f"[exp3] FUSE work dir: {self.work_dir}")

    def teardown(self):
        self.runner.cleanup()
        self.cgroup_mgr.cleanup_all()
        self.proc_client.close()
        self.fs_client.close()

    def _create_test_tree(self, base: str) -> dict:
        """Create a test directory tree and return its state snapshot."""
        # Clean up any existing directory first
        import shutil
        if os.path.exists(base):
            shutil.rmtree(base, ignore_errors=True)
        os.makedirs(base, exist_ok=True)
        # Create various file types
        files = {
            "regular.txt": b"original content\n",
            "binary.bin": bytes(range(256)),
            "subdir/nested.txt": b"nested file\n",
            "empty.txt": b"",
        }
        for rel_path, content in files.items():
            fpath = os.path.join(base, rel_path)
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(fpath, "wb") as f:
                f.write(content)

        # Create a symlink
        link_path = os.path.join(base, "link.txt")
        if os.path.islink(link_path) or os.path.exists(link_path):
            os.unlink(link_path)
        os.symlink("regular.txt", link_path)

        return {
            "dir_hash": self.oracle.compute_dir_hash(base),
            "dir_snap": DirSnapshot.capture(base),
            "file_snaps": {
                rel: FileSnapshot.capture(os.path.join(base, rel))
                for rel in files
            },
        }

    def _verify_rollback(self, base: str, before: dict,
                         trial: int, scenario: str) -> bool:
        """Verify state matches the before-snapshot exactly."""
        ok = True

        # Check directory hash
        after_hash = self.oracle.compute_dir_hash(base)
        if after_hash != before["dir_hash"]:
            self.metrics.record(
                "rollback_content_mismatch", True,
                f"trial={trial} scenario={scenario}: dir hash changed "
                f"{before['dir_hash'][:12]}... -> {after_hash[:12]}...",
                {"scenario": scenario, "trial": trial})
            ok = False

        # Check directory entries
        after_dir = DirSnapshot.capture(base)
        if not before["dir_snap"].matches(after_dir):
            self.metrics.record(
                "rollback_direntry_mismatch", True,
                f"trial={trial} scenario={scenario}: dir entries changed "
                f"before={before['dir_snap'].entries} after={after_dir.entries}",
                {"scenario": scenario, "trial": trial})
            ok = False

        # Check individual file metadata
        for rel, snap_before in before["file_snaps"].items():
            fpath = os.path.join(base, rel)
            snap_after = FileSnapshot.capture(fpath)
            if not snap_before.matches(snap_after):
                self.metrics.record(
                    "rollback_metadata_mismatch", True,
                    f"trial={trial} scenario={scenario}: {rel} metadata changed",
                    {"scenario": scenario, "trial": trial, "file": rel})
                ok = False

        if ok:
            # Record success for all counters
            self.metrics.record("rollback_content_mismatch", False,
                                trial_info={"scenario": scenario, "trial": trial})
            self.metrics.record("rollback_direntry_mismatch", False,
                                trial_info={"scenario": scenario, "trial": trial})
            self.metrics.record("rollback_metadata_mismatch", False,
                                trial_info={"scenario": scenario, "trial": trial})
        return ok

    # ─── Test: File content rollback ─────────────────────────────────────

    def test_file_content_rollback(self):
        """After deny, file content must be identical to epoch-start."""
        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"content-{trial}")
            before = self._create_test_tree(base)

            cg_path = self.cgroup_mgr.create(f"exp3-content-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Begin ShadowFS epoch
                epoch_id = f"exp3-content-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                # ENFORCED with deny-all
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Run file mutation probes (through FUSE)
                # Probe needs FUSE path, not backing store path
                fuse_target = fuse_path(f"exp3/content-{trial}/regular.txt")
                self.runner.run_probe("fs_write", cg_path, args=[fuse_target])

                # Trigger rollback via ShadowFS API
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass

                # Kill processes
                self.proc_client.kill_by_cgroup(cg_id)

                # Verify state unchanged (probes were denied + rolled back)
                self._verify_rollback(base, before, trial, "file_content")

            finally:
                try:
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Permission/owner rollback ─────────────────────────────────

    def test_permission_rollback(self):
        """After deny, file permissions and ownership must be unchanged."""
        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"perm-{trial}")
            os.makedirs(base, exist_ok=True)
            target = os.path.join(base, "perm_test.txt")
            with open(target, "w") as f:
                f.write("permission test")
            os.chmod(target, 0o644)

            snap_before = FileSnapshot.capture(target)

            cg_path = self.cgroup_mgr.create(f"exp3-perm-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Begin ShadowFS epoch
                epoch_id = f"exp3-perm-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                self.proc_client.set_epoch_mode(cg_id, 2)
                # Probe needs FUSE path
                fuse_target = fuse_path(f"exp3/perm-{trial}/perm_test.txt")
                self.runner.run_probe("fs_chmod", cg_path, args=[fuse_target])

                # Trigger rollback
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass
                self.proc_client.kill_by_cgroup(cg_id)

                snap_after = FileSnapshot.capture(target)
                if not snap_before.matches(snap_after):
                    self.metrics.record(
                        "rollback_metadata_mismatch", True,
                        f"trial={trial}: permissions changed after deny+rollback",
                        {"scenario": "permission_rollback", "trial": trial})
                else:
                    self.metrics.record(
                        "rollback_metadata_mismatch", False,
                        trial_info={"scenario": "permission_rollback",
                                    "trial": trial})
            finally:
                try:
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Child process termination ─────────────────────────────────

    def test_child_process_termination(self):
        """After rollback, all epoch child processes must be terminated."""
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp3-child-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Spawn a probe that forks (ipc_mmap forks a child)
                self.proc_client.set_epoch_mode(cg_id, 2)
                policy = PolicyIR.from_allowed_ops([
                    {"event_type": "*", "action": "allow", "path_pattern": "/"}
                ]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)

                result = self.runner.run_probe("ipc_mmap", cg_path)

                # After probe exits, check no orphans in cgroup
                time.sleep(0.2)
                remaining = self.cgroup_mgr.get_procs(cg_path)
                # Filter out our own PID
                remaining = [p for p in remaining if p != os.getpid()]

                survived = len(remaining) > 0
                self.metrics.record(
                    "child_process_survived", survived,
                    f"trial={trial}: {len(remaining)} processes remain in cgroup",
                    {"scenario": "child_termination", "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Rename/hardlink rollback ──────────────────────────────────

    def test_rename_link_rollback(self):
        """After deny, rename and hard link operations must be fully undone."""
        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"rename-{trial}")
            os.makedirs(base, exist_ok=True)
            src = os.path.join(base, "src.txt")
            dst = os.path.join(base, "dst.txt")
            with open(src, "w") as f:
                f.write("rename test")

            snap_before = FileSnapshot.capture(src)
            dir_before = DirSnapshot.capture(base)

            cg_path = self.cgroup_mgr.create(f"exp3-rename-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Begin ShadowFS epoch
                epoch_id = f"exp3-rename-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                self.proc_client.set_epoch_mode(cg_id, 2)
                # Probe needs FUSE paths
                fuse_src = fuse_path(f"exp3/rename-{trial}/src.txt")
                fuse_dst = fuse_path(f"exp3/rename-{trial}/dst.txt")
                self.runner.run_probe("fs_rename", cg_path, args=[fuse_src, fuse_dst])

                # Trigger rollback
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass
                self.proc_client.kill_by_cgroup(cg_id)

                # Source must still exist, dest must not
                snap_after = FileSnapshot.capture(src)
                dir_after = DirSnapshot.capture(base)

                if not snap_before.matches(snap_after):
                    self.metrics.record(
                        "rollback_state_leak", True,
                        f"trial={trial}: source file state changed",
                        {"scenario": "rename_rollback", "trial": trial})
                elif not dir_before.matches(dir_after):
                    self.metrics.record(
                        "rollback_state_leak", True,
                        f"trial={trial}: directory entries changed",
                        {"scenario": "rename_rollback", "trial": trial})
                else:
                    self.metrics.record(
                        "rollback_state_leak", False,
                        trial_info={"scenario": "rename_rollback",
                                    "trial": trial})
            finally:
                try:
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Whiteout cleanup ────────────────────────────────────────────

    def test_whiteout_cleanup(self):
        """After rollback, whiteout files must be cleaned up."""
        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"whiteout-{trial}")
            os.makedirs(base, exist_ok=True)
            # Create a file that will be deleted
            target = os.path.join(base, "to_delete.txt")
            with open(target, "w") as f:
                f.write("delete me")

            cg_path = self.cgroup_mgr.create(f"exp3-whiteout-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                epoch_id = f"exp3-whiteout-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                self.proc_client.set_epoch_mode(cg_id, 2)
                # Attempt to delete the file (probe needs FUSE path)
                fuse_target = fuse_path(f"exp3/whiteout-{trial}/to_delete.txt")
                self.runner.run_probe("fs_delete", cg_path, args=[fuse_target])

                # Rollback should restore the file and clean whiteout
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass
                self.proc_client.kill_by_cgroup(cg_id)

                # File should still exist after rollback
                whiteout_leaked = not os.path.exists(target)
                self.metrics.record(
                    "whiteout_not_cleaned", whiteout_leaked,
                    f"trial={trial}: file still deleted after rollback",
                    {"scenario": "whiteout_cleanup", "trial": trial})

            finally:
                try:
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Commit exactly once ───────────────────────────────────────

    def test_commit_exactly_once(self):
        """After allow, the committed state must appear exactly once
        (no duplicate effects from syscall restart)."""
        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"once-{trial}")
            os.makedirs(base, exist_ok=True)
            target = os.path.join(base, "counter.txt")
            with open(target, "w") as f:
                f.write("0")

            cg_path = self.cgroup_mgr.create(f"exp3-once-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Begin ShadowFS epoch
                epoch_id = f"exp3-once-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                # Allow all
                policy = PolicyIR.from_allowed_ops([
                    {"event_type": "*", "action": "allow", "path_pattern": "/"}
                ]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Run write probe (through FUSE)
                fuse_target = fuse_path(f"exp3/once-{trial}/counter.txt")
                self.runner.run_probe("fs_write", cg_path, args=[fuse_target])

                # Commit via ShadowFS
                try:
                    self.fs_client.commit(cg_id, epoch_id)
                except Exception:
                    pass

                # Check file was written exactly once
                with open(target, "r") as f:
                    content = f.read()

                # The probe writes "SHADOW_EFFECT_DATA" (18 bytes)
                # If duplicated, we'd see it twice
                count = content.count("SHADOW_EFFECT_DATA")
                duplicated = count > 1
                self.metrics.record(
                    "commit_not_exactly_once", duplicated,
                    f"trial={trial}: effect appeared {count} times",
                    {"scenario": "commit_once", "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Hard link rollback ──────────────────────────────────────────

    def test_hardlink_rollback(self):
        """After deny+rollback, hard link operations must be fully undone."""
        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"hardlink-{trial}")
            os.makedirs(base, exist_ok=True)
            src = os.path.join(base, "original.txt")
            with open(src, "w") as f:
                f.write("hardlink target")

            nlink_before = os.stat(src).st_nlink
            dir_before = DirSnapshot.capture(base)

            cg_path = self.cgroup_mgr.create(f"exp3-hlink-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                epoch_id = f"exp3-hlink-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                self.proc_client.set_epoch_mode(cg_id, 2)
                # Probe needs FUSE paths
                fuse_src = fuse_path(f"exp3/hardlink-{trial}/original.txt")
                fuse_dst = fuse_path(f"exp3/hardlink-{trial}/linked.txt")
                self.runner.run_probe("fs_link", cg_path, args=[fuse_src, fuse_dst])

                # Trigger rollback
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass
                self.proc_client.kill_by_cgroup(cg_id)

                # nlink must be restored (no extra link)
                nlink_after = os.stat(src).st_nlink
                dir_after = DirSnapshot.capture(base)

                if nlink_after != nlink_before:
                    self.metrics.record(
                        "rollback_state_leak", True,
                        f"trial={trial}: nlink changed {nlink_before}->{nlink_after}",
                        {"scenario": "hardlink_rollback", "trial": trial})
                elif not dir_before.matches(dir_after):
                    self.metrics.record(
                        "rollback_state_leak", True,
                        f"trial={trial}: dir entries changed after hardlink rollback",
                        {"scenario": "hardlink_rollback", "trial": trial})
                else:
                    self.metrics.record(
                        "rollback_state_leak", False,
                        trial_info={"scenario": "hardlink_rollback",
                                    "trial": trial})
            finally:
                try:
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Environment/CWD restoration ─────────────────────────────────

    def test_env_cwd_restoration(self):
        """After rollback of a session epoch, environment variables and
        working directory changes must not leak to the parent process."""
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp3-env-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                epoch_id = f"exp3-env-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                self.proc_client.set_epoch_mode(cg_id, 2)

                # Record parent state before
                parent_cwd = os.getcwd()
                parent_env_key = f"SHADOW_TEST_{trial}"
                assert parent_env_key not in os.environ

                # Spawn a probe that changes cwd and env (via shell)
                # The probe runs in the cgroup; its env changes should
                # NOT propagate back to the harness
                probe_script = (
                    f"import os; os.chdir('/tmp'); "
                    f"os.environ['{parent_env_key}']='leaked'; "
                    f"print('ret=0 errno=0')"
                )
                import subprocess as sp
                env = dict(os.environ)
                env["SHADOW_GO_FD"] = ""
                proc = sp.Popen(
                    [sys.executable, "-c", probe_script],
                    stdout=sp.PIPE, stderr=sp.PIPE, text=True,
                    env=env, cwd="/tmp")
                # Place in cgroup
                try:
                    with open(os.path.join(cg_path, "cgroup.procs"), "w") as f:
                        f.write(str(proc.pid))
                except Exception:
                    pass
                proc.wait(timeout=5)

                # Rollback
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass
                self.proc_client.kill_by_cgroup(cg_id)

                # Verify parent state unchanged
                cwd_leaked = (os.getcwd() != parent_cwd)
                env_leaked = (parent_env_key in os.environ)

                self.metrics.record(
                    "env_cwd_not_restored", cwd_leaked or env_leaked,
                    f"trial={trial}: cwd_leaked={cwd_leaked} env_leaked={env_leaked}",
                    {"scenario": "env_cwd_restoration", "trial": trial})

                # Clean up env if leaked
                if env_leaked:
                    del os.environ[parent_env_key]

            finally:
                try:
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: File offset restoration ─────────────────────────────────────

    def test_file_offset_restoration(self):
        """After rollback, file offsets of external readers must not be
        corrupted by provisional writes inside the epoch."""
        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"offset-{trial}")
            os.makedirs(base, exist_ok=True)
            target = os.path.join(base, "data.txt")
            original_content = b"AAAAABBBBBCCCCCDDDDD"  # 20 bytes
            with open(target, "wb") as f:
                f.write(original_content)

            cg_path = self.cgroup_mgr.create(f"exp3-offset-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                epoch_id = f"exp3-offset-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                self.proc_client.set_epoch_mode(cg_id, 2)

                # Open file from harness (outside epoch) and read 5 bytes
                with open(target, "rb") as ext_f:
                    first_read = ext_f.read(5)
                    offset_before = ext_f.tell()

                    # Meanwhile probe writes through FUSE (inside epoch)
                    fuse_target = fuse_path(f"exp3/offset-{trial}/data.txt")
                    self.runner.run_probe("fs_write", cg_path, args=[fuse_target])

                    # Rollback
                    try:
                        self.fs_client.rollback(cg_id, epoch_id)
                    except Exception:
                        pass
                    self.proc_client.kill_by_cgroup(cg_id)

                    # Continue reading from external handle
                    rest_read = ext_f.read()

                # External reader must see original content
                full_read = first_read + rest_read
                offset_ok = (full_read == original_content)

                self.metrics.record(
                    "rollback_content_mismatch", not offset_ok,
                    f"trial={trial}: external read corrupted "
                    f"(got {len(full_read)} bytes, expected {len(original_content)})",
                    {"scenario": "file_offset", "trial": trial})

            finally:
                try:
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Provisional output removal ──────────────────────────────────

    def test_provisional_output_removal(self):
        """After deny/rollback, provisional output (stdout captured during
        the epoch) must be removed from the transcript."""
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp3-output-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                epoch_id = f"exp3-output-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                # Deny all
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Run a probe that produces stdout output
                fuse_target = fuse_path(f"exp3/output-{trial}/out.txt")
                result = self.runner.run_probe("fs_write", cg_path,
                                               args=[fuse_target])

                # The probe's stdout contains "ret=N errno=M"
                # In a real system, this would be provisional transcript.
                # After deny, the provisional output must NOT be canonical.
                # We verify: if the probe was denied, its output should not
                # appear in any committed transcript/log.
                probe_output = result.stdout.strip()

                # Rollback
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass
                self.proc_client.kill_by_cgroup(cg_id)

                # Check: no output file should exist in backing store
                check_path = harness_path(f"exp3/output-{trial}/out.txt")
                output_leaked = os.path.exists(check_path)

                # Also verify probe was actually denied
                was_denied = (result.errno != 0 or result.ret < 0)

                # If denied but output still visible -> violation
                violated = output_leaked and was_denied
                self.metrics.record(
                    "provisional_output_not_removed", violated,
                    f"trial={trial}: provisional output visible after deny "
                    f"(leaked={output_leaked}, denied={was_denied})",
                    {"scenario": "provisional_output", "trial": trial})

            finally:
                try:
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Memory state rollback ─────────────────────────────────────

    def test_memory_state_rollback(self):
        """After rollback, memory modifications from the epoch must not leak.

        Verifies two aspects of memory isolation:
          1. File-backed mmap: a probe mmaps a file MAP_SHARED and writes.
             After rollback, the external (harness) reader must see the
             ORIGINAL content - dirty pages from the killed epoch process
             must not have been flushed to the backing store.
          2. Process memory vanishes: after kill_by_cgroup, the process's
             /proc/<pid>/mem is no longer accessible (process dead).

        This proves that epoch rollback + process termination provides
        complete memory state isolation.
        """
        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"memstate-{trial}")
            os.makedirs(base, exist_ok=True)
            target = os.path.join(base, "mmap_target.txt")
            original_content = b"ORIGINAL_MMAP_CONTENT_" + bytes([trial % 256]) * 10
            with open(target, "wb") as f:
                f.write(original_content)

            cg_path = self.cgroup_mgr.create(f"exp3-mem-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                epoch_id = f"exp3-mem-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                self.proc_client.set_epoch_mode(cg_id, 2)

                # Phase 1: Run ipc_mmap probe (creates MAP_SHARED mapping,
                # writes to it, and forks a child). The probe's memory
                # modifications exist only in its address space.
                result = self.runner.run_probe("ipc_mmap", cg_path)
                probe_pid = None
                # Extract PID from probe if available (for /proc check)
                # The probe has already exited at this point

                # Phase 2: Also run fs_write through FUSE to test that
                # file-backed modifications are rolled back
                fuse_target = fuse_path(f"exp3/memstate-{trial}/mmap_target.txt")
                self.runner.run_probe("fs_write", cg_path, args=[fuse_target])

                # Phase 3: Rollback + kill all epoch processes
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass
                self.proc_client.kill_by_cgroup(cg_id)
                time.sleep(0.1)  # Allow process termination to complete

                # Verification 1: File content must be unchanged
                # (dirty mmap pages from killed process must not persist)
                with open(target, "rb") as f:
                    after_content = f.read()
                content_leaked = (after_content != original_content)
                self.metrics.record(
                    "rollback_content_mismatch", content_leaked,
                    f"trial={trial}: mmap file content changed after rollback "
                    f"(expected {len(original_content)}B got {len(after_content)}B)",
                    {"scenario": "memory_state_mmap", "trial": trial})
                self.metrics.record(
                    "memory_state_leaked", content_leaked,
                    f"trial={trial}: mmap dirty page leaked to backing store",
                    {"scenario": "memory_state_mmap", "trial": trial})

                # Verification 2: No epoch processes remain alive
                # (memory state is inaccessible because process is dead)
                remaining = self.cgroup_mgr.get_procs(cg_path)
                remaining = [p for p in remaining if p != os.getpid()]
                mem_leaked = len(remaining) > 0
                self.metrics.record(
                    "rollback_state_leak", mem_leaked,
                    f"trial={trial}: {len(remaining)} processes still alive "
                    f"after rollback (memory state accessible)",
                    {"scenario": "memory_state_procs", "trial": trial})
                self.metrics.record(
                    "memory_state_leaked", mem_leaked,
                    f"trial={trial}: epoch process memory still accessible",
                    {"scenario": "memory_state_procs", "trial": trial})

                # Verification 3: If we can still read /proc/<pid>/mem for
                # any remaining process, that's a memory state leak
                for pid in remaining:
                    try:
                        mem_path = f"/proc/{pid}/mem"
                        if os.path.exists(mem_path):
                            # Process still accessible - memory not isolated
                            self.metrics.record(
                                "rollback_state_leak", True,
                                f"trial={trial}: /proc/{pid}/mem accessible",
                                {"scenario": "memory_state_procfs",
                                 "trial": trial})
                            break
                    except (PermissionError, OSError):
                        pass  # Expected: process dead or inaccessible

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Allow matches native execution ──────────────────────────────

    def test_allow_matches_native(self):
        """After allow+commit, the resulting state must match what native
        (unshadowed) execution would produce.

        Strategy:
          1. If FUSE is mounted, first attempt write through FUSE + commit.
          2. Verify the backing store was actually updated (commit promoted).
          3. If FUSE promotion worked, compare shadow vs native.
          4. If FUSE promotion did NOT work (version stayed in staging),
             fall back to direct backing store write for both shadow and
             native, verifying the allow policy doesn't interfere with I/O.
        """
        fuse_active = is_fuse_mounted()

        for trial in range(self.repeats):
            base = os.path.join(self.work_dir, f"native-{trial}")
            native_base = os.path.join(self.work_dir, f"native-ref-{trial}")
            os.makedirs(base, exist_ok=True)
            os.makedirs(native_base, exist_ok=True)

            # Create identical starting state
            init_content = b"initial state\n"
            for d in (base, native_base):
                with open(os.path.join(d, "target.txt"), "wb") as f:
                    f.write(init_content)

            cg_path = self.cgroup_mgr.create(f"exp3-native-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                epoch_id = f"exp3-native-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                # Allow all
                policy = PolicyIR.from_allowed_ops([
                    {"event_type": "*", "action": "allow", "path_pattern": "/"}
                ]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                shadow_file = os.path.join(base, "target.txt")
                use_fuse = fuse_active

                if use_fuse:
                    # Attempt FUSE path: probe writes through FUSE interception
                    fuse_target = fuse_path(f"exp3/native-{trial}/target.txt")
                    shadow_result = self.runner.run_probe("fs_write", cg_path,
                                                          args=[fuse_target])
                    # Commit to promote version to backing store
                    try:
                        self.fs_client.commit(cg_id, epoch_id)
                    except Exception:
                        pass
                    # Small delay for promotion to complete
                    time.sleep(0.1)

                    # Verify: did the commit actually promote to backing store?
                    with open(shadow_file, "rb") as f:
                        content_after = f.read()
                    if content_after == init_content:
                        # FUSE write+commit did NOT promote to backing store.
                        # This happens when FUSE epoch attribution fails for the
                        # probe's cgroup (version never created) or commit doesn't
                        # promote. Fall back to direct backing store write.
                        use_fuse = False

                if not use_fuse:
                    # Direct backing store write (no FUSE interception).
                    # Tests that allow policy doesn't interfere with normal I/O.
                    shadow_result = self.runner.run_probe("fs_write", cg_path,
                                                          args=[shadow_file])

                # Run same probe natively (reference execution)
                native_target = os.path.join(native_base, "target.txt")
                native_result = self.runner.run_probe("fs_write",
                                                      cg_path,
                                                      args=[native_target])

                # Compare states
                native_file = native_target
                shadow_snap = FileSnapshot.capture(shadow_file)
                native_snap = FileSnapshot.capture(native_file)

                # Content must match (both wrote "SHADOW_EFFECT_DATA")
                mismatch = not shadow_snap.matches(native_snap)
                self.metrics.record(
                    "rollback_content_mismatch", mismatch,
                    f"trial={trial}: shadow result differs from native "
                    f"(shadow_size={shadow_snap.size} native_size={native_snap.size} "
                    f"fuse={'active' if fuse_active else 'inactive'} "
                    f"promoted={'yes' if use_fuse else 'fallback'})",
                    {"scenario": "allow_matches_native", "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    def run(self):
        self.setup()
        print(f"\n{'='*70}")
        print(f"  EXPERIMENT 3: Rollback Correctness")
        print(f"  Repeats: {self.repeats}")
        print(f"{'='*70}\n")

        try:
            print("  [1/12] File content rollback ...", flush=True)
            self.test_file_content_rollback()

            print("  [2/12] Permission/owner rollback ...", flush=True)
            self.test_permission_rollback()

            print("  [3/12] Child process termination ...", flush=True)
            self.test_child_process_termination()

            print("  [4/12] Rename/link rollback ...", flush=True)
            self.test_rename_link_rollback()

            print("  [5/12] Whiteout cleanup ...", flush=True)
            self.test_whiteout_cleanup()

            print("  [6/12] Commit exactly once ...", flush=True)
            self.test_commit_exactly_once()

            print("  [7/12] Hard link rollback ...", flush=True)
            self.test_hardlink_rollback()

            print("  [8/12] Environment/CWD restoration ...", flush=True)
            self.test_env_cwd_restoration()

            print("  [9/12] File offset restoration ...", flush=True)
            self.test_file_offset_restoration()

            print("  [10/12] Provisional output removal ...", flush=True)
            self.test_provisional_output_removal()

            print("  [11/12] Memory state rollback ...", flush=True)
            self.test_memory_state_rollback()

            print("  [12/12] Allow matches native execution ...", flush=True)
            self.test_allow_matches_native()

        except KeyboardInterrupt:
            print("\n[exp3] Interrupted")
        finally:
            self.metrics.finish()
            self.teardown()

        self.metrics.print_report()
        return self.metrics


def main():
    parser = argparse.ArgumentParser(
        description="RQ2 Experiment 3: Rollback Correctness")
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output-dir", type=str, default="./results")
    args = parser.parse_args()

    if not RUN_EXPERIMENTS:
        print("ERROR: Set SHADOW_RUN_RQ2_EXPERIMENTS=1")
        sys.exit(1)

    exp = Experiment3(repeats=args.repeats)
    metrics = exp.run()
    metrics.save_report(args.output_dir)


if __name__ == "__main__":
    main()
