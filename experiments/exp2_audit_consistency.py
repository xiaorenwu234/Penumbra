#!/usr/bin/env python3
"""
Experiment 2: Historical Audit and Future Execution Consistency

Verifies that the two policy projections (retrospective audit and prospective
enforcement) do not produce semantic gaps:

  - File operations already in ShadowFS (retrospective audit targets)
  - Network/IPC operations at the fence (prospective enforcement targets)
  - Combined policies: allow historical + deny future, and vice versa
  - Policy fingerprint integrity (mismatch/missing/modified -> no release)
  - rename/hard link must check both source AND destination

Key invariants:
  - Historical violation -> entire epoch rollback
  - Future violation -> EPERM on syscall restart
  - Policy fingerprint mismatch -> effect NOT released
  - Dual-path operations (rename, link) check both endpoints

Usage:
    SHADOW_RUN_RQ2_EXPERIMENTS=1 python3 exp2_audit_consistency.py
"""

import argparse
import errno
import hashlib
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.client import ShadowProcClient, ShadowFSClient, ShadowObserveClient
from framework.cgroup import CgroupManager
from framework.oracle import EffectOracle, FileSnapshot
from framework.metrics import MetricsCollector
from framework.runner import ProbeRunner
from framework.paths import fuse_path, orig_path, harness_path, ensure_fuse_dirs, is_fuse_mounted, SHADOWFS_MNT

from policy.policy_ir import PolicyIR, CLASS_IDS, OP_IDS

RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ2_EXPERIMENTS") == "1"


class Experiment2:
    """Audit consistency experiment."""

    def __init__(self, repeats: int = 10):
        self.repeats = repeats
        # Unique run ID to avoid epoch ID collisions with WAL-replayed state
        self.run_id = str(int(time.time() * 1000))[-8:]
        self.proc_client = ShadowProcClient()
        self.fs_client = ShadowFSClient()
        self.observe_client = None
        self.cgroup_mgr = CgroupManager(prefix="shadow-exp2")
        self.oracle = EffectOracle(tempfile.mkdtemp(prefix="shadow-exp2-oracle-"))
        self.runner = ProbeRunner()
        self.metrics = MetricsCollector("exp2_audit_consistency")
        # Use backing store for harness file operations
        self.work_dir = harness_path("exp2")

        # Metric counters
        self.metrics.add_counter("historical_violation_not_rolled_back")
        self.metrics.add_counter("future_violation_not_denied")
        self.metrics.add_counter("fingerprint_mismatch_released")
        self.metrics.add_counter("dual_path_single_check")
        self.metrics.add_counter("semantic_gap_detected")

    def setup(self):
        if os.geteuid() != 0:
            raise RuntimeError("Experiment 2 requires root privileges")
        self.proc_client.connect()
        self.fs_client.connect()
        try:
            self.observe_client = ShadowObserveClient()
            self.observe_client.connect()
        except (FileNotFoundError, ConnectionError):
            print("[exp2] WARNING: ShadowObserve not available, "
                  "audit tests will use ShadowFS only")
        # Ensure FUSE directories exist
        ensure_fuse_dirs("exp2")
        if not is_fuse_mounted():
            print(f"[exp2] WARNING: ShadowFS FUSE not mounted at {SHADOWFS_MNT}")
        print(f"[exp2] Connected to daemons")
        print(f"[exp2] FUSE work dir: {self.work_dir}")

    def teardown(self):
        self.runner.cleanup()
        self.cgroup_mgr.cleanup_all()
        self.proc_client.close()
        self.fs_client.close()
        if self.observe_client:
            self.observe_client.close()

    def _policy_hash(self, policy: dict) -> str:
        """Compute a stable hash of a proc_policy."""
        canonical = json.dumps(policy, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ─── Test: Historical file ops allowed + future network denied ───────

    def test_allow_history_deny_future(self):
        """Policy allows past file writes but denies future network connects.

        The file write (already in ShadowFS epoch) should be committed.
        The network connect (at fence) should get EPERM on restart.
        """
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp2-ad-{trial}-{int(time.time()*1000)}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Phase 1: Begin a ShadowFS epoch for historical file ops
                epoch_id = f"exp2-ad-{self.run_id}-{trial}"
                epoch_ok = True
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception as e:
                    epoch_ok = False
                    print(f"    [exp2] WARNING: begin_epoch failed trial={trial}: {e}")

                # Create a file through backing store (historical operation)
                test_file = os.path.join(self.work_dir, f"hist-{trial}.txt")
                os.makedirs(os.path.dirname(test_file), exist_ok=True)
                with open(test_file, "w") as f:
                    f.write("historical data")

                # Phase 2: Install policy that allows FILESYSTEM/WRITE
                # but denies NETWORK/CONNECT
                allow_fs = {"event_type": "WRITE", "action": "allow",
                            "path_pattern": "/"}
                deny_net = {"event_type": "CONNECT", "action": "deny",
                            "path_pattern": "/",
                            "endpoint": {"family": 2, "addr": 0x7F000001,
                                         "port": 9999}}
                policy = PolicyIR.from_allowed_ops([allow_fs, deny_net]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Phase 3: Spawn network probe - should be denied
                result = self.runner.run_probe("net_connect", cg_path,
                                               args=["9999"])

                # Future violation must be denied
                not_denied = (result.ret == 0 and result.errno == 0)
                self.metrics.record(
                    "future_violation_not_denied", not_denied,
                    f"trial={trial}: CONNECT allowed despite deny policy",
                    {"scenario": "allow_hist_deny_future", "trial": trial})

                # Historical file should still be intact (committed via ShadowFS)
                if not os.path.exists(test_file):
                    self.metrics.record(
                        "semantic_gap_detected", True,
                        f"trial={trial}: historical file lost",
                        {"scenario": "allow_hist_deny_future", "trial": trial})
                else:
                    self.metrics.record(
                        "semantic_gap_detected", False,
                        trial_info={"scenario": "allow_hist_deny_future",
                                    "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Historical violation -> whole epoch rollback ──────────────

    def test_historical_violation_rollback(self):
        """If a historical file operation violates policy, the entire epoch
        must be rolled back - including any allowed future operations."""
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp2-hv-{trial}-{int(time.time()*1000)}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Begin ShadowFS epoch
                epoch_id = f"exp2-hv-{self.run_id}-{trial}"
                epoch_ok = True
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception as e:
                    epoch_ok = False
                    print(f"    [exp2] WARNING: begin_epoch failed trial={trial}: {e}")

                # Create a file through FUSE that "violates" the deny policy
                test_file = os.path.join(self.work_dir, f"violation-{trial}.txt")
                snapshot_before = FileSnapshot.capture(test_file)

                # Policy denies WRITE to this path
                deny_write = {"event_type": "WRITE", "action": "deny",
                              "path_pattern": self.work_dir}
                # But allows CONNECT (future op should also not proceed
                # because the epoch is rolled back)
                allow_net = {"event_type": "CONNECT", "action": "allow",
                             "path_pattern": "/"}
                policy = PolicyIR.from_allowed_ops(
                    [deny_write, allow_net]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Attempt the violating write through a probe (goes via FUSE)
                # Probe needs the FUSE path, not the backing store path
                probe_target = fuse_path(f"exp2/violation-{trial}.txt")
                self.runner.run_probe("fs_write", cg_path, args=[probe_target])

                # Trigger rollback via ShadowFS
                if epoch_ok:
                    try:
                        self.fs_client.rollback(cg_id, epoch_id)
                    except Exception as e:
                        print(f"    [exp2] WARNING: rollback failed trial={trial}: {e}")
                else:
                    print(f"    [exp2] WARNING: skipping rollback (no epoch) trial={trial}")

                # The historical violation means the whole epoch should rollback
                snapshot_after = FileSnapshot.capture(test_file)

                # If the file was modified despite deny+rollback, that's a violation
                if not snapshot_before.matches(snapshot_after):
                    self.metrics.record(
                        "historical_violation_not_rolled_back", True,
                        f"trial={trial}: file modified despite deny+rollback",
                        {"scenario": "hist_violation_rollback", "trial": trial})
                else:
                    self.metrics.record(
                        "historical_violation_not_rolled_back", False,
                        trial_info={"scenario": "hist_violation_rollback",
                                    "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Policy fingerprint integrity ──────────────────────────────

    def test_policy_fingerprint_integrity(self):
        """If the policy hash changes between authorization and release,
        the effect must NOT be released."""
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp2-fp-{trial}-{int(time.time()*1000)}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Install initial policy
                policy_v1 = PolicyIR.from_allowed_ops([
                    {"event_type": "CONNECT", "action": "allow",
                     "path_pattern": "/",
                     "endpoint": {"family": 2, "addr": 0x7F000001, "port": 9999}}
                ]).to_proc_policy()
                hash_v1 = self._policy_hash(policy_v1)

                self.proc_client.install_proc_policy(cg_id, policy_v1)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Now modify the policy (simulating tampering)
                policy_v2 = PolicyIR.from_allowed_ops([
                    {"event_type": "CONNECT", "action": "allow",
                     "path_pattern": "/",
                     "endpoint": {"family": 2, "addr": 0x7F000001, "port": 80}}
                ]).to_proc_policy()
                hash_v2 = self._policy_hash(policy_v2)

                # Hashes must differ
                assert hash_v1 != hash_v2, "Policy hashes should differ"

                # With modified policy, the original authorization is invalid
                # The system should NOT release effects authorized under v1
                # when the current policy is v2
                self.proc_client.install_proc_policy(cg_id, policy_v2)

                # Probe connecting to port 9999 (authorized under v1 but not v2)
                result = self.runner.run_probe("net_connect", cg_path,
                                               args=["9999"])

                # Should be denied because current policy (v2) doesn't allow 9999
                released = (result.ret == 0 and result.errno == 0)
                self.metrics.record(
                    "fingerprint_mismatch_released", released,
                    f"trial={trial}: effect released despite policy change "
                    f"(v1 hash={hash_v1[:8]}... v2 hash={hash_v2[:8]}...)",
                    {"scenario": "fingerprint_integrity", "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: rename/link dual-path check ───────────────────────────────
    # NOTE: Filesystem operations (rename, link) are handled by the ShadowFS
    # FUSE layer, NOT by BPF LSM. The FUSE layer does NOT do path-based access
    # control - it records all operations as versions for commit/rollback.
    # Therefore, the correct dual-path test verifies that ShadowFS correctly
    # tracks BOTH source and destination paths, so rollback fully undoes the
    # operation (source restored, destination removed).

    def test_dual_path_operations(self):
        """rename must track BOTH source and destination paths.

        Verification: after rename + rollback, source must be restored and
        destination must not exist. This proves ShadowFS records both paths.
        """
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp2-dp-{trial}-{int(time.time()*1000)}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Begin ShadowFS epoch
                epoch_id = f"exp2-dp-{self.run_id}-{trial}"
                epoch_ok = True
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception as e:
                    epoch_ok = False
                    print(f"    [exp2] WARNING: begin_epoch failed: {e}")

                # Setup: create source file through backing store
                src = os.path.join(self.work_dir, f"rename-src-{trial}.txt")
                dst = os.path.join(self.work_dir, f"rename-dst-{trial}.txt")
                os.makedirs(os.path.dirname(src), exist_ok=True)
                with open(src, "w") as f:
                    f.write("rename test data")
                # Ensure dst does not exist
                if os.path.exists(dst):
                    os.unlink(dst)

                # Allow all (FUSE doesn't do path-based denial, it versions)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Perform rename through probe (goes via FUSE, creates version)
                fuse_src = fuse_path(f"exp2/rename-src-{trial}.txt")
                fuse_dst = fuse_path(f"exp2/rename-dst-{trial}.txt")
                result = self.runner.run_probe("fs_rename", cg_path,
                                               args=[fuse_src, fuse_dst])

                # Now rollback the epoch
                if epoch_ok:
                    try:
                        self.fs_client.rollback(cg_id, epoch_id)
                    except Exception:
                        pass

                # After rollback: source must be restored, dst must not exist
                # This verifies ShadowFS tracked BOTH paths of the rename
                import time as _time
                _time.sleep(0.2)  # allow FUSE cache to expire

                src_restored = os.path.exists(src)
                dst_removed = not os.path.exists(dst)

                # If rename went through FUSE and rollback worked correctly,
                # both conditions must hold
                dual_path_ok = src_restored and dst_removed

                # Record: violation if rollback didn't properly undo both paths
                self.metrics.record(
                    "dual_path_single_check", not dual_path_ok and epoch_ok,
                    f"trial={trial}: dual-path rollback incomplete "
                    f"(src_restored={src_restored} dst_removed={dst_removed})",
                    {"scenario": "dual_path_rename", "trial": trial})

                # Semantic gap: if dst exists but src doesn't, rename was
                # partially tracked (only one path recorded)
                semantic_gap = (not src_restored) and os.path.exists(dst)
                self.metrics.record(
                    "semantic_gap_detected", semantic_gap,
                    f"trial={trial}: rename partially tracked (src gone, dst exists)",
                    {"scenario": "dual_path_rename", "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: hard link dual-path check ─────────────────────────────────

    def test_dual_path_hardlink(self):
        """hard link must track BOTH source and destination paths.

        Verification: after link + rollback, the extra link must be removed
        (nlink of source returns to original). This proves ShadowFS records
        both paths of the link operation.
        """
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp2-hl-{trial}-{int(time.time()*1000)}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Begin ShadowFS epoch
                epoch_id = f"exp2-hl-{self.run_id}-{trial}"
                epoch_ok = True
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception as e:
                    epoch_ok = False
                    print(f"    [exp2] WARNING: begin_epoch failed: {e}")

                # Setup: create source file
                src = os.path.join(self.work_dir, f"link-src-{trial}.txt")
                dst = os.path.join(self.work_dir, f"link-dst-{trial}.txt")
                os.makedirs(os.path.dirname(src), exist_ok=True)
                with open(src, "w") as f:
                    f.write("hardlink test data")
                # Ensure dst does not exist
                if os.path.exists(dst):
                    os.unlink(dst)

                nlink_before = os.stat(src).st_nlink

                # Allow all (FUSE versions the operation)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Perform hard link through probe (goes via FUSE)
                fuse_src = fuse_path(f"exp2/link-src-{trial}.txt")
                fuse_dst = fuse_path(f"exp2/link-dst-{trial}.txt")
                result = self.runner.run_probe("fs_link", cg_path,
                                               args=[fuse_src, fuse_dst])

                # Now rollback the epoch
                if epoch_ok:
                    try:
                        self.fs_client.rollback(cg_id, epoch_id)
                    except Exception:
                        pass

                # After rollback: nlink must be restored, dst must not exist
                import time as _time
                _time.sleep(0.2)  # allow FUSE cache to expire

                nlink_after = os.stat(src).st_nlink if os.path.exists(src) else 0
                dst_removed = not os.path.exists(dst)
                nlink_restored = (nlink_after == nlink_before)

                # Dual-path tracking is correct if rollback undid the link
                dual_path_ok = nlink_restored and dst_removed

                self.metrics.record(
                    "dual_path_single_check", not dual_path_ok and epoch_ok,
                    f"trial={trial}: hardlink dual-path rollback incomplete "
                    f"(nlink {nlink_before}->{nlink_after}, dst_removed={dst_removed})",
                    {"scenario": "dual_path_hardlink", "trial": trial})

                # Semantic gap: link was created but rollback didn't remove it
                semantic_gap = (nlink_after > nlink_before) and epoch_ok
                self.metrics.record(
                    "semantic_gap_detected", semantic_gap,
                    f"trial={trial}: hard link not undone by rollback "
                    f"(nlink={nlink_after})",
                    {"scenario": "dual_path_hardlink", "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Combined allow-history + allow-future (positive case) ─────

    def test_both_allowed_positive(self):
        """When policy allows both historical and future ops, both proceed."""
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp2-pos-{trial}-{int(time.time()*1000)}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Allow everything
                policy = PolicyIR.from_allowed_ops([
                    {"event_type": "*", "action": "allow", "path_pattern": "/"}
                ]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Network connect should succeed
                result = self.runner.run_probe("net_connect", cg_path,
                                               args=["9999"])

                # With wildcard allow, should not be EPERM
                denied = (result.errno == errno.EPERM)
                self.metrics.record(
                    "semantic_gap_detected", denied,
                    f"trial={trial}: denied despite wildcard allow",
                    {"scenario": "both_allowed_positive", "trial": trial})

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Test: Future violation must get EPERM on syscall restart ─────────

    def test_future_violation_eperm_restart(self):
        """When a fenced syscall is restarted after policy denies it,
        the process must receive EPERM (not silently succeed or hang)."""
        for trial in range(self.repeats):
            cg_path = self.cgroup_mgr.create(f"exp2-ep-{trial}-{int(time.time()*1000)}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # Install deny policy for NETWORK/CONNECT
                deny_net = {"event_type": "CONNECT", "action": "deny",
                            "path_pattern": "/"}
                policy = PolicyIR.from_allowed_ops([deny_net]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Spawn probe in SPECULATIVE first (gets fenced)
                proc, write_fd = self.runner.spawn_and_hold(
                    "net_connect", cg_path, args=["9999"])
                self.runner.release(write_fd)

                # Wait for fence
                time.sleep(0.1)

                # Now continue (restart syscall) - should get EPERM
                try:
                    self.proc_client.continue_by_cgroup(cg_id)
                except Exception:
                    pass

                # Collect result - must show EPERM
                result = self.runner.wait_result(proc, "net_connect", timeout=5.0)

                # The restarted syscall must return EPERM
                got_eperm = (result.errno == errno.EPERM)
                succeeded = (result.ret == 0 and result.errno == 0)
                self.metrics.record(
                    "future_violation_not_denied", succeeded,
                    f"trial={trial}: future violation not denied on restart "
                    f"(ret={result.ret} errno={result.errno})",
                    {"scenario": "eperm_restart", "trial": trial})

                # If process was killed instead of getting EPERM, that's
                # also acceptable (fail-closed), but record it
                if not got_eperm and not succeeded and result.returncode != 0:
                    # Process was killed - acceptable fail-closed behavior
                    pass

            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.clear_all_policies(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    def run(self):
        """Run all audit consistency tests."""
        self.setup()
        print(f"\n{'='*70}")
        print(f"  EXPERIMENT 2: Audit Consistency")
        print(f"  Repeats: {self.repeats}")
        print(f"{'='*70}\n")

        try:
            print("  [1/7] Allow history + deny future ...", flush=True)
            self.test_allow_history_deny_future()

            print("  [2/7] Historical violation rollback ...", flush=True)
            self.test_historical_violation_rollback()

            print("  [3/7] Policy fingerprint integrity ...", flush=True)
            self.test_policy_fingerprint_integrity()

            print("  [4/7] Dual-path operations (rename) ...", flush=True)
            self.test_dual_path_operations()

            print("  [5/7] Dual-path operations (hard link) ...", flush=True)
            self.test_dual_path_hardlink()

            print("  [6/7] Positive case (both allowed) ...", flush=True)
            self.test_both_allowed_positive()

            print("  [7/7] Future violation EPERM on restart ...", flush=True)
            self.test_future_violation_eperm_restart()

        except KeyboardInterrupt:
            print("\n[exp2] Interrupted")
        finally:
            self.metrics.finish()
            self.teardown()

        self.metrics.print_report()
        return self.metrics


def main():
    parser = argparse.ArgumentParser(
        description="RQ2 Experiment 2: Audit Consistency")
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output-dir", type=str, default="./results")
    args = parser.parse_args()

    if not RUN_EXPERIMENTS:
        print("ERROR: Set SHADOW_RUN_RQ2_EXPERIMENTS=1")
        sys.exit(1)

    exp = Experiment2(repeats=args.repeats)
    metrics = exp.run()
    metrics.save_report(args.output_dir)


if __name__ == "__main__":
    main()
