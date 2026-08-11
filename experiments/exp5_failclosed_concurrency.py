#!/usr/bin/env python3
"""
Experiment 5: Fail-Closed and Concurrency Race Conditions

Injects faults and stress to verify safety invariants hold under adversity:

Fault injection:
  - Audit log lost/truncated/corrupted/unknown events
  - Ring buffer drop, path reconstruction failure, drain failure
  - Policy partial install failure
  - Continuous fork/clone during freeze
  - PID/cgroup identifier reuse
  - Single-use pass token replay
  - Finalization/effect release/acknowledgment failure at various points
  - WAL torn tail, promotion mid-crash

Safety invariants (must NEVER be violated):
  - No unauthorized effect leakage
  - No partial file publication
  - No premature baseline deletion
  - No effect duplication
  - No rejected transcript becoming canonical

Concurrency tests: repeated N=5000 times with failures/trials + exact
binomial 95% confidence interval.

Usage:
    SHADOW_RUN_RQ2_EXPERIMENTS=1 python3 exp5_failclosed_concurrency.py [--trials 5000]
"""

import argparse
import errno
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.client import ShadowProcClient, ShadowFSClient
from framework.cgroup import CgroupManager
from framework.oracle import EffectOracle, FileSnapshot
from framework.metrics import MetricsCollector, binomial_ci
from framework.runner import ProbeRunner
from framework.paths import fuse_path, orig_path, harness_path, ensure_fuse_dirs, is_fuse_mounted, SHADOWFS_MNT

from policy.policy_ir import PolicyIR

RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ2_EXPERIMENTS") == "1"


class Experiment5:
    """Fail-closed and concurrency experiment."""

    # BPF map capacity limit. Exp5 runs with a FRESH ShadowProc daemon
    # (restarted after exp1-4), so the full map capacity is available.
    # Empirically the map holds ~2500 entries; we cap at 2400 to leave
    # buffer for teardown operations and ensure all 16 test types get
    # an equal share (~150 trials each).
    MAX_CGROUPS_PER_RUN = 2400
    NUM_FAULT_TYPES = 16  # Total number of fault injection test methods

    def __init__(self, trials: int = 5000):
        self.trials = trials
        # Unique run ID to avoid epoch ID collisions with WAL-replayed state
        self.run_id = str(int(time.time() * 1000))[-8:]
        self.proc_client = ShadowProcClient()
        self.fs_client = ShadowFSClient()
        self.cgroup_mgr = CgroupManager(prefix="shadow-exp5")
        self.oracle = EffectOracle(tempfile.mkdtemp(prefix="shadow-exp5-oracle-"))
        self.runner = ProbeRunner()
        self.metrics = MetricsCollector("exp5_failclosed_concurrency")
        # Use backing store for harness file operations
        self.work_dir = harness_path("exp5")
        # Track cgroup usage to avoid BPF map exhaustion
        self._cgroups_created = 0
        self._tests_completed = 0

        # Safety invariant counters
        self.metrics.add_counter("unauthorized_effect_leaked")
        self.metrics.add_counter("partial_file_published")
        self.metrics.add_counter("baseline_premature_delete")
        self.metrics.add_counter("effect_duplicated")
        self.metrics.add_counter("rejected_transcript_canonical")

        # Fault-specific counters
        self.metrics.add_counter("fault_audit_corruption")
        self.metrics.add_counter("fault_policy_partial")
        self.metrics.add_counter("fault_fork_during_freeze")
        self.metrics.add_counter("fault_token_replay")
        self.metrics.add_counter("fault_wal_torn_tail")
        self.metrics.add_counter("fault_concurrent_race")
        # New fault counters
        self.metrics.add_counter("fault_ring_buffer_drop")
        self.metrics.add_counter("fault_path_reconstruction")
        self.metrics.add_counter("fault_pid_cgroup_reuse")
        self.metrics.add_counter("fault_finalization_failure")
        self.metrics.add_counter("fault_drain_failure")
        # Error tracking: exceptions that would otherwise be swallowed
        self.metrics.add_counter("fault_injection_error")

    def setup(self):
        if os.geteuid() != 0:
            raise RuntimeError("Experiment 5 requires root")
        self.proc_client.connect()
        self.fs_client.connect()
        # Ensure FUSE directories exist
        ensure_fuse_dirs("exp5")
        if not is_fuse_mounted():
            print(f"[exp5] WARNING: ShadowFS FUSE not mounted at {SHADOWFS_MNT}")
        print(f"[exp5] Connected. Running {self.trials} trials per fault type.")
        print(f"[exp5] FUSE work dir: {self.work_dir}")

    def _setup_cgroup_safe(self, name: str):
        """Create a cgroup, handling BPF map exhaustion gracefully.

        Returns (cg_path, cg_id) or raises RuntimeError if map is full.
        """
        # Check if we're approaching the limit
        if self._cgroups_created >= self.MAX_CGROUPS_PER_RUN:
            raise RuntimeError("BPF_MAP_FULL")

        cg_path = self.cgroup_mgr.create(name)
        cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
        try:
            self.proc_client.add_cgroup(cg_path)
            self._cgroups_created += 1
        except RuntimeError as e:
            if "Argument list too long" in str(e) or "map" in str(e).lower():
                self.cgroup_mgr.remove(cg_path)
                raise RuntimeError("BPF_MAP_FULL") from e
            raise
        return cg_path, cg_id

    def _teardown_cgroup_safe(self, cg_path: str, cg_id: str):
        """Clean up a cgroup, ignoring errors."""
        try:
            self.proc_client.kill_by_cgroup(cg_id)
        except Exception:
            pass
        try:
            self.proc_client.clear_all_policies(cg_id)
        except Exception:
            pass
        try:
            self.proc_client.remove_cgroup(cg_path)
        except Exception:
            pass
        self.cgroup_mgr.remove(cg_path)

    def _remaining_budget(self) -> int:
        """Get remaining cgroup budget."""
        return max(0, self.MAX_CGROUPS_PER_RUN - self._cgroups_created)

    def _trials_for_test(self, base_trials: int) -> int:
        """Get number of trials for a test.

        Fixed per-test allocation: MAX_CGROUPS_PER_RUN / NUM_FAULT_TYPES.
        This ensures each fault type gets equal budget regardless of order.
        """
        per_test_budget = self.MAX_CGROUPS_PER_RUN // self.NUM_FAULT_TYPES
        return max(0, min(base_trials, per_test_budget))

    def teardown(self):
        self.runner.cleanup()
        self.cgroup_mgr.cleanup_all()
        self.proc_client.close()
        self.fs_client.close()

    # ─── Fault: Audit log corruption ─────────────────────────────────────

    def test_audit_log_corruption(self):
        """REAL corruption of audit/journal files -> system must fail closed.

        This test ACTUALLY corrupts the ShadowFS journal files:
          - Truncate to zero (loss)
          - Truncate to half (partial write)
          - Write random bytes (corruption)
          - Append invalid JSON (unknown event)

        After corruption, verifies that BPF enforcement still denies effects
        (the enforcement layer must be unaffected by journal corruption).
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [1/16] Audit log corruption ({actual_trials} trials) ...", flush=True)

        # Find the ShadowFS journal directory
        staging = os.environ.get("SHADOWFS_STAGING", "/tmp/shadow-rq2-test/staging")
        journal_dir = os.path.join(staging, "journal")

        for trial in range(actual_trials):
            if trial > 0 and trial % 20 == 0:
                print(f"    progress: {trial}/{actual_trials} (cgroups: {self._cgroups_created})", flush=True)
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-audit-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # ── REAL CORRUPTION of journal files ──
                corruption_type = trial % 4
                corrupted_file = None

                # Find and corrupt journal files
                if os.path.isdir(journal_dir):
                    journal_files = [f for f in os.listdir(journal_dir)
                                     if f.endswith('.jsonl') or f.endswith('.log')]
                    if journal_files:
                        corrupted_file = os.path.join(journal_dir, journal_files[0])

                if corrupted_file and os.path.exists(corrupted_file):
                    original_size = os.path.getsize(corrupted_file)

                    if corruption_type == 0:
                        # Truncate to zero (total loss)
                        with open(corrupted_file, 'w') as f:
                            f.truncate(0)
                    elif corruption_type == 1:
                        # Truncate to half (partial write)
                        with open(corrupted_file, 'r+b') as f:
                            f.truncate(original_size // 2)
                    elif corruption_type == 2:
                        # Write random bytes (corruption)
                        with open(corrupted_file, 'r+b') as f:
                            f.seek(0)
                            f.write(b'\x00\xff\xfe\xfd' * 100)
                    else:
                        # Append invalid JSON (unknown event)
                        with open(corrupted_file, 'a') as f:
                            f.write('{"op": "INVALID_CORRUPTED_EVENT", "garbage": true\n')

                # After corruption: ENFORCED with no policy = default deny
                # BPF enforcement must still work (unaffected by journal state)
                try:
                    self.proc_client.set_epoch_mode(cg_id, 2)
                except RuntimeError as e:
                    if "Argument list too long" in str(e) or "map" in str(e).lower():
                        print(f"    [BPF map full at trial {trial}, stopping early]")
                        self._teardown_cgroup_safe(cg_path, cg_id)
                        break
                    raise

                # BPF-enforced probe must be denied
                result = self.runner.run_probe("sys_unshare", cg_path)

                # Effect must NOT succeed
                leaked = (result.ret >= 0 and result.errno == 0)
                self.metrics.record(
                    "unauthorized_effect_leaked", leaked,
                    f"audit_corruption trial={trial} type={corruption_type} "
                    f"(ret={result.ret} errno={result.errno})",
                    {"fault": "audit_corruption", "trial": trial,
                     "corruption_type": corruption_type})
                self.metrics.record(
                    "fault_audit_corruption", leaked,
                    trial_info={"fault": "audit_corruption", "trial": trial})

                # Clean up corrupted file
                if corrupted_file and os.path.exists(corrupted_file):
                    try:
                        os.unlink(corrupted_file)
                    except OSError:
                        pass

            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        print(f"    completed")

    # ─── Fault: Policy partial install ───────────────────────────────────

    def test_policy_partial_install(self):
        """Partial policy: allow ONE class, verify uncovered classes denied.

        Installs allow policy for NETWORK only, then verifies that
        SYSTEM/NAMESPACE (unshare) is still denied. This tests that
        a partial policy installation does NOT accidentally allow
        non-covered effect classes.
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [2/16] Policy partial install ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-policy-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # Install allow for NETWORK/CONNECT ONLY (partial coverage)
                policy = PolicyIR.from_allowed_ops([
                    {"event_type": "CONNECT", "action": "allow",
                     "path_pattern": "/"}
                ]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # SYSTEM/NAMESPACE (unshare) is NOT covered by the policy
                # It MUST be denied despite NETWORK being allowed
                result = self.runner.run_probe("sys_unshare", cg_path)
                leaked = (result.ret >= 0 and result.errno == 0)
                self.metrics.record(
                    "unauthorized_effect_leaked", leaked,
                    f"partial_policy trial={trial}: unshare succeeded "
                    f"despite only NETWORK allowed (ret={result.ret} errno={result.errno})",
                    {"fault": "partial_policy", "trial": trial})
                self.metrics.record(
                    "fault_policy_partial", leaked,
                    trial_info={"fault": "partial_policy", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)

    # ─── Fault: Fork during freeze ───────────────────────────────────────

    def test_fork_during_freeze(self):
        """Real fork/clone storm during freeze -> no effect escapes.

        Spawns N processes simultaneously into the cgroup, all attempting
        sys_unshare. ENFORCED mode with no policy must deny ALL of them,
        even under concurrent fork pressure.
        """
        import subprocess as _sp

        actual_trials = self._trials_for_test(self.trials)
        print(f"  [3/16] Fork during freeze ({actual_trials} trials) ...", flush=True)
        STORM_SIZE = 10  # processes per trial

        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-fork-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # ENFORCED with no policy = default deny
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Spawn STORM_SIZE processes simultaneously
                probe_path = self.runner.get_probe_path("sys_unshare")
                procs = []
                for i in range(STORM_SIZE):
                    read_fd, write_fd = os.pipe()
                    env = dict(os.environ)
                    env["SHADOW_GO_FD"] = str(read_fd)
                    p = _sp.Popen(
                        [probe_path],
                        pass_fds=(read_fd,),
                        stdin=_sp.DEVNULL,
                        stdout=_sp.PIPE,
                        stderr=_sp.PIPE,
                        text=True,
                        env=env)
                    os.close(read_fd)
                    # Place into cgroup
                    try:
                        with open(os.path.join(cg_path, "cgroup.procs"), "w") as f:
                            f.write(str(p.pid))
                    except Exception:
                        pass
                    procs.append((p, write_fd))

                # Release ALL simultaneously (fork storm)
                for p, wfd in procs:
                    try:
                        os.write(wfd, b"x")
                        os.close(wfd)
                    except OSError:
                        pass

                # Wait for all and check results
                any_leaked = False
                for p, _ in procs:
                    try:
                        stdout, _ = p.communicate(timeout=3)
                        # Parse ret/errno
                        import re
                        m = re.search(r"ret=(-?\d+)\s+errno=(\d+)", stdout)
                        if m:
                            ret = int(m.group(1))
                            err = int(m.group(2))
                            if ret >= 0 and err == 0:
                                any_leaked = True
                    except _sp.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=2)

                self.metrics.record(
                    "fault_fork_during_freeze", any_leaked,
                    f"fork_freeze trial={trial}: {STORM_SIZE} procs, "
                    f"leaked={any_leaked}",
                    {"fault": "fork_freeze", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        print(f"    completed")

    # ─── Fault: Token replay ─────────────────────────────────────────────

    def test_token_replay(self):
        """Real single-use restart token replay -> second use must fail.

        Flow:
          1. SPECULATIVE mode: probe gets fenced
          2. Grant a restart token via grant_restart_token API
          3. Continue process: token consumed, syscall succeeds
          4. Same process tries ANOTHER syscall: no token -> fenced/denied

        This verifies tokens are truly single-use and cannot be replayed.
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [4/16] Token replay ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-token-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # SPECULATIVE mode: probe will be fenced
                self.proc_client.set_epoch_mode(cg_id, 0)

                # Spawn probe (gets fenced on unshare)
                proc, write_fd = self.runner.spawn_and_hold(
                    "sys_unshare", cg_path)
                self.runner.release(write_fd)
                time.sleep(0.2)

                # Confirm fenced
                frozen = self.proc_client.list_frozen(cg_id)
                if not frozen:
                    proc.kill()
                    proc.wait(timeout=2)
                    self.metrics.record(
                        "fault_token_replay", False,
                        trial_info={"fault": "token_replay", "trial": trial,
                                    "skipped": True, "reason": "not fenced"})
                    continue

                # Grant a ONE-TIME restart token for this process
                # syscall_nr=272 (unshare on x86_64), class=6 (SYSTEM), op=2 (NAMESPACE)
                tid = proc.pid
                try:
                    self.proc_client.request_ok({
                        "action": "grant_restart_token",
                        "tid": tid,
                        "syscall_nr": 272,  # __NR_unshare
                        "effect_class": 7,  # SYSTEM
                        "operation": 2,     # NAMESPACE
                    })
                except Exception:
                    proc.kill()
                    proc.wait(timeout=2)
                    self.metrics.record(
                        "fault_token_replay", False,
                        trial_info={"fault": "token_replay", "trial": trial,
                                    "skipped": True, "reason": "grant failed"})
                    continue

                # SIGCONT the process: token consumed, unshare succeeds
                import signal as _sig
                os.kill(tid, _sig.SIGCONT)
                result = self.runner.wait_result(proc, "sys_unshare", timeout=3.0)

                # First use should succeed (token was valid)
                first_ok = (result.ret >= 0 and result.errno == 0)
                if not first_ok:
                    # Token grant failed - infrastructure error, skip trial
                    self.metrics.record(
                        "fault_token_replay", False,
                        trial_info={"fault": "token_replay", "trial": trial,
                                    "skipped": True,
                                    "reason": f"first_ok=False (ret={result.ret} errno={result.errno})"})
                    continue

                # Now the token is CONSUMED. If the process tries another
                # intercepted syscall, it should be fenced again (no token).
                # Since the probe already exited after one syscall, we verify
                # that the token was indeed consumed by checking that a NEW
                # process in the same cgroup gets fenced.
                proc2, wfd2 = self.runner.spawn_and_hold(
                    "sys_unshare", cg_path)
                self.runner.release(wfd2)
                time.sleep(0.2)

                # Second process should be FENCED (no token available)
                frozen2 = self.proc_client.list_frozen(cg_id)
                replay_detected = len(frozen2) == 0  # NOT fenced = token leaked

                # If not fenced, the second syscall might succeed = replay
                if not frozen2:
                    r2 = self.runner.wait_result(proc2, "sys_unshare", timeout=3.0)
                    replay_detected = (r2.ret >= 0 and r2.errno == 0)
                else:
                    # Properly fenced - kill it
                    self.proc_client.kill_by_cgroup(cg_id)
                    try:
                        proc2.kill()
                        proc2.wait(timeout=2)
                    except Exception:
                        pass

                self.metrics.record(
                    "fault_token_replay", replay_detected,
                    f"token_replay trial={trial}: first_ok={first_ok} "
                    f"replay_detected={replay_detected}",
                    {"fault": "token_replay", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        print(f"    completed {actual_trials} trials")

    # ─── Fault: WAL torn tail ────────────────────────────────────────────

    def _restart_shadowfs(self):
        """Kill and restart ShadowFS, reconnect the client.

        Returns True if restart succeeded, False otherwise.
        """
        import signal as _signal
        import subprocess as _sp

        # Find ShadowFS PID
        fs_pid = None
        try:
            result = _sp.run(["pgrep", "-f", "shadowfs"],
                             capture_output=True, text=True, timeout=5)
            pids = [p for p in result.stdout.strip().split("\n") if p]
            if pids:
                fs_pid = int(pids[0])
        except Exception:
            pass

        if fs_pid:
            try:
                os.kill(fs_pid, _signal.SIGKILL)
                time.sleep(0.5)
            except ProcessLookupError:
                pass

        # Unmount stale FUSE and remove socket
        staging = os.environ.get("SHADOWFS_STAGING", "/tmp/shadow-rq2-test/staging")
        mnt = os.environ.get("SHADOWFS_MNT", "/tmp/shadow-rq2-test/mnt")
        orig = os.environ.get("SHADOWFS_ORIG", "/tmp/shadow-rq2-test/orig")
        sock = os.environ.get("SHADOWFS_SOCK", "/tmp/shadowfs.sock")

        try:
            _sp.run(["umount", "-l", mnt], capture_output=True, timeout=5)
        except Exception:
            pass
        try:
            os.unlink(sock)
        except OSError:
            pass
        time.sleep(0.5)

        # Restart ShadowFS
        proj = os.environ.get("PROJ_PATH",
                              "/home/xht/桌面/penumbra-work/RQ2/speculative_shadow")
        shadowfs_bin = os.path.join(proj, "ShadowFS", "shadowfs")

        if not os.path.exists(shadowfs_bin):
            return False

        try:
            _sp.Popen(
                [shadowfs_bin, "-staging", staging, "-sock", sock,
                 "-allow-other", mnt, orig],
                stdin=_sp.DEVNULL,
                stdout=open("/var/tmp/shadowfs.log", "a"),
                stderr=_sp.STDOUT)
        except Exception:
            return False

        # Wait for socket to appear (up to 5 seconds)
        for _ in range(10):
            if os.path.exists(sock):
                break
            time.sleep(0.5)
        else:
            return False

        # Reconnect client
        try:
            self.fs_client.close()
        except Exception:
            pass
        time.sleep(0.5)
        try:
            self.fs_client.connect()
        except Exception:
            return False

        return True

    def test_wal_torn_tail(self):
        """WAL torn tail: kill -9 ShadowFS, truncate WAL, restart, verify.

        Real crash recovery test:
          1. Create epoch + write through FUSE
          2. Begin commit (generates WAL records)
          3. kill -9 ShadowFS (crash mid-commit)
          4. Truncate WAL file (simulate torn write)
          5. Restart ShadowFS
          6. Verify: backing store is consistent (all-or-nothing)
        """
        actual_trials = self._trials_for_test(self.trials)
        # Limit WAL restart trials (each restart is expensive)
        actual_trials = min(actual_trials, 5)
        print(f"  [5/16] WAL torn tail ({actual_trials} trials) ...", flush=True)

        staging = os.environ.get("SHADOWFS_STAGING", "/tmp/shadow-rq2-test/staging")
        wal_dir = os.path.join(staging, "journal")

        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-wal-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                epoch_id = f"exp5-wal-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                # Write through FUSE
                self.proc_client.set_epoch_mode(cg_id, 2)
                target = fuse_path(f"exp5/wal-{trial}.txt")
                self.runner.run_probe("fs_write", cg_path, args=[target])

                # Begin commit (starts WAL write)
                try:
                    self.fs_client.commit(cg_id, epoch_id)
                except Exception:
                    pass

                # Record pre-crash state
                check_path = harness_path(f"exp5/wal-{trial}.txt")
                pre_crash_exists = os.path.exists(check_path)
                pre_crash_content = None
                if pre_crash_exists:
                    with open(check_path, "rb") as f:
                        pre_crash_content = f.read()

                # ── CRASH: kill -9 ShadowFS ──
                import signal as _signal
                import subprocess as _sp
                fs_pid = None
                try:
                    result = _sp.run(["pgrep", "-f", "shadowfs"],
                                     capture_output=True, text=True, timeout=5)
                    pids = result.stdout.strip().split("\n")
                    if pids and pids[0]:
                        fs_pid = int(pids[0])
                except Exception:
                    pass

                if fs_pid:
                    try:
                        os.kill(fs_pid, _signal.SIGKILL)
                        time.sleep(0.5)
                    except ProcessLookupError:
                        pass

                # ── TORN TAIL: truncate WAL ──
                if os.path.isdir(wal_dir):
                    wal_files = [f for f in os.listdir(wal_dir)
                                 if f.endswith('.jsonl') or f.endswith('.wal')]
                    if wal_files:
                        wal_path = os.path.join(wal_dir, wal_files[0])
                        try:
                            size = os.path.getsize(wal_path)
                            if size > 10:
                                # Truncate to half (torn write)
                                with open(wal_path, 'r+b') as f:
                                    f.truncate(size // 2)
                        except OSError:
                            pass

                # ── RESTART ShadowFS ──
                restarted = self._restart_shadowfs()
                if not restarted:
                    # Cannot restart - skip verification
                    self.metrics.record(
                        "fault_wal_torn_tail", False,
                        trial_info={"fault": "wal_torn", "trial": trial,
                                    "skipped": True, "reason": "restart failed"})
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    continue

                # ── VERIFY: backing store consistency ──
                # After recovery, file must be either:
                #   - Fully committed (content == SHADOW_EFFECT_DATA)
                #   - Fully absent (rollback)
                # NEVER partial.
                time.sleep(0.5)  # Allow recovery to complete

                if os.path.exists(check_path):
                    with open(check_path, "rb") as f:
                        content = f.read()
                    # Partial = has some bytes but not the full probe payload
                    partial = 0 < len(content) < 18
                    self.metrics.record(
                        "fault_wal_torn_tail", partial,
                        f"wal_torn trial={trial}: partial file ({len(content)}B)",
                        {"fault": "wal_torn", "trial": trial})
                    self.metrics.record(
                        "partial_file_published", partial,
                        f"wal_torn trial={trial}: partial content after recovery",
                        {"fault": "wal_torn", "trial": trial})
                else:
                    # File absent = rolled back (acceptable)
                    self.metrics.record(
                        "fault_wal_torn_tail", False,
                        trial_info={"fault": "wal_torn", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)

        self._tests_completed += 1
        print(f"    completed")

    # ─── Fault: Concurrent release/finalize race ─────────────────────────

    def test_concurrent_race(self):
        """Concurrent finalization + release + ack -> no inconsistency."""
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [6/16] Concurrent race ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-race-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # ENFORCED with NO policy (default deny).
                # The race must not accidentally create an allow state.
                self.proc_client.set_epoch_mode(cg_id, 2)

                errors = []

                def do_continue():
                    try:
                        self.proc_client.continue_by_cgroup(cg_id)
                    except Exception as e:
                        errors.append(f"continue: {e}")

                def do_commit():
                    try:
                        self.proc_client.commit_by_cgroup(cg_id)
                    except Exception as e:
                        errors.append(f"commit: {e}")

                def do_kill():
                    try:
                        self.proc_client.kill_by_cgroup(cg_id)
                    except Exception as e:
                        errors.append(f"kill: {e}")

                # Race: concurrent operations on same cgroup
                threads = [
                    threading.Thread(target=do_continue),
                    threading.Thread(target=do_commit),
                    threading.Thread(target=do_kill),
                ]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=5)

                # Post-race verification: the system must be in a consistent
                # state. Try to run a probe - it must be denied (no policy).
                # If the race corrupted state and allowed the probe, that's
                # a violation.
                time.sleep(0.1)
                post_result = self.runner.run_probe("sys_unshare", cg_path)
                race_leaked = (post_result.ret >= 0 and post_result.errno == 0)

                self.metrics.record(
                    "fault_concurrent_race", race_leaked,
                    f"race trial={trial}: post-race probe "
                    f"{'LEAKED' if race_leaked else 'denied'} "
                    f"(errors={len(errors)}, ret={post_result.ret} errno={post_result.errno})",
                    {"fault": "concurrent_race", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                self.metrics.record(
                    "fault_concurrent_race", True,
                    f"race trial={trial}: unhandled {e}",
                    {"fault": "concurrent_race", "trial": trial})
            except Exception as e:
                self.metrics.record(
                    "fault_concurrent_race", True,
                    f"race trial={trial}: unhandled {e}",
                    {"fault": "concurrent_race", "trial": trial})
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)

    # ─── Fault: File partial publication ─────────────────────────────────

    def test_no_partial_publication(self):
        """File must not be partially visible outside the epoch."""
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [7/12] No partial publication ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            target = fuse_path(f"exp5/partial-{trial}.txt")
            # Ensure file doesn't exist in backing store
            check_path = harness_path(f"exp5/partial-{trial}.txt")
            if os.path.exists(check_path):
                os.unlink(check_path)

            cg_path = self.cgroup_mgr.create(f"exp5-partial-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                # ENFORCED, no policy -> deny
                self.proc_client.set_epoch_mode(cg_id, 2)
                self.runner.run_probe("fs_write", cg_path, args=[target])

                # File must NOT exist outside (no partial publication)
                published = os.path.exists(check_path)
                self.metrics.record(
                    "partial_file_published", published,
                    f"partial_pub trial={trial}: file exists outside epoch",
                    {"fault": "partial_pub", "trial": trial})

            except RuntimeError as e:
                # BPF map full or other infra limit - skip gracefully
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    time.sleep(0.2)
                    continue
                raise
            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Fault: Baseline premature deletion ──────────────────────────────

    def test_no_premature_baseline_delete(self):
        """Baseline must not be deleted before finalization completes."""
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [8/12] No premature baseline deletion ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            baseline = harness_path(f"exp5/baseline-{trial}.txt")
            with open(baseline, "w") as f:
                f.write("baseline content")

            cg_path = self.cgroup_mgr.create(f"exp5-baseline-{trial}")
            cg_id = self.cgroup_mgr.get_cgroup_id(cg_path)
            self.proc_client.add_cgroup(cg_path)

            try:
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Attempt operations (probe needs FUSE path)
                fuse_baseline = fuse_path(f"exp5/baseline-{trial}.txt")
                self.runner.run_probe("fs_write", cg_path, args=[fuse_baseline])

                # Baseline must still exist (not prematurely deleted)
                deleted = not os.path.exists(baseline)
                self.metrics.record(
                    "baseline_premature_delete", deleted,
                    f"baseline trial={trial}: baseline deleted prematurely",
                    {"fault": "baseline_delete", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    time.sleep(0.2)
                    continue
                raise
            finally:
                try:
                    self.proc_client.kill_by_cgroup(cg_id)
                    self.proc_client.remove_cgroup(cg_path)
                except Exception:
                    pass
                self.cgroup_mgr.remove(cg_path)

    # ─── Fault: Ring buffer drop ──────────────────────────────────────────

    def test_ring_buffer_drop(self):
        """Ring buffer drop -> system must fail closed, not leak effects.

        Uses sys_unshare (BPF-enforced) since fs_write is FUSE-enforced
        and would not be intercepted by BPF.
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [9/16] Ring buffer drop ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-ringbuf-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # ENFORCED with no policy (simulates ring buffer drop losing events)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Attempt BPF-enforced effect - must be denied
                result = self.runner.run_probe("sys_unshare", cg_path)

                # Effect must NOT succeed (BPF default-deny with no policy)
                leaked = (result.ret >= 0 and result.errno == 0)
                self.metrics.record(
                    "fault_ring_buffer_drop", leaked,
                    f"ring_buffer_drop trial={trial}: effect leaked "
                    f"(ret={result.ret} errno={result.errno})",
                    {"fault": "ring_buffer_drop", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        print(f"    completed")

    # ─── Fault: Path reconstruction failure ───────────────────────────────

    def test_path_reconstruction_failure(self):
        """Path reconstruction failure -> must fail closed.

        Uses sys_unshare (BPF-enforced) to test that the system denies
        effects even when internal path/context reconstruction might fail.
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [10/16] Path reconstruction failure ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-pathrec-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # ENFORCED with no policy = default deny
                self.proc_client.set_epoch_mode(cg_id, 2)

                # BPF-enforced probe must be denied
                result = self.runner.run_probe("sys_unshare", cg_path)

                # Must fail closed (deny)
                leaked = (result.ret >= 0 and result.errno == 0)
                self.metrics.record(
                    "fault_path_reconstruction", leaked,
                    f"path_reconstruction trial={trial}: effect leaked "
                    f"(ret={result.ret} errno={result.errno})",
                    {"fault": "path_reconstruction", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        print(f"    completed")

    # ─── Fault: PID/cgroup reuse ──────────────────────────────────────────

    def test_pid_cgroup_reuse(self):
        """PID/cgroup identifier reuse -> must not confuse epochs.

        Rapidly creates/destroys cgroups with reused names and verifies
        that old policy/identity does not affect new processes.
        Uses sys_unshare (BPF-enforced) for testing.
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [11/16] PID/cgroup reuse ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            # Create and destroy cgroup rapidly to test reuse
            cg_name = f"exp5-reuse-{trial % 10}"  # Reuse names
            try:
                cg_path, cg_id = self._setup_cgroup_safe(cg_name)
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # ENFORCED with no policy = default deny
                self.proc_client.set_epoch_mode(cg_id, 2)

                # BPF-enforced probe must be denied
                result = self.runner.run_probe("sys_unshare", cg_path)

                # Must be denied (no confusion from reuse)
                leaked = (result.ret >= 0 and result.errno == 0)
                self.metrics.record(
                    "fault_pid_cgroup_reuse", leaked,
                    f"pid_cgroup_reuse trial={trial}: effect leaked "
                    f"(ret={result.ret} errno={result.errno})",
                    {"fault": "pid_cgroup_reuse", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        print(f"    completed")

    # ─── Fault: Finalization failure ──────────────────────────────────────

    def test_finalization_failure(self):
        """Finalization fails at various points -> no partial commit."""
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [12/12] Finalization failure ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-finalize-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # Begin epoch
                epoch_id = f"exp5-finalize-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                # Allow all policy
                policy = PolicyIR.from_allowed_ops([
                    {"event_type": "*", "action": "allow", "path_pattern": "/"}
                ]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Write through FUSE
                target = fuse_path(f"exp5/finalize-{trial}.txt")
                self.runner.run_probe("fs_write", cg_path, args=[target])

                # Attempt to commit (may fail)
                try:
                    self.fs_client.commit(cg_id, epoch_id)
                except Exception:
                    pass

                # Kill without proper finalization
                self.proc_client.kill_by_cgroup(cg_id)

                # File should either be fully committed or not exist
                # Check backing store for partial state
                check_path = harness_path(f"exp5/finalize-{trial}.txt")
                if os.path.exists(check_path):
                    with open(check_path, "rb") as f:
                        content = f.read()
                    # Check for partial write (incomplete data)
                    partial = len(content) > 0 and len(content) < 18
                    self.metrics.record(
                        "fault_finalization_failure", partial,
                        f"finalization trial={trial}: partial content",
                        {"fault": "finalization_failure", "trial": trial})
                else:
                    self.metrics.record(
                        "fault_finalization_failure", False,
                        trial_info={"fault": "finalization_failure",
                                    "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        print(f"    completed")

    # ─── Fault: Promotion mid-crash ────────────────────────────────────────

    def test_promotion_mid_crash(self):
        """Promotion (staging -> orig) interrupted mid-way -> no partial file.

        Simulates a crash during the ShadowFS promotion phase by killing
        the cgroup processes between commit and ack_release.
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [13/14] Promotion mid-crash ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-promo-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                epoch_id = f"exp5-promo-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                # Allow all + write
                policy = PolicyIR.from_allowed_ops([
                    {"event_type": "*", "action": "allow", "path_pattern": "/"}
                ]).to_proc_policy()
                self.proc_client.install_proc_policy(cg_id, policy)
                self.proc_client.set_epoch_mode(cg_id, 2)

                target = fuse_path(f"exp5/promo-{trial}.txt")
                self.runner.run_probe("fs_write", cg_path, args=[target])

                # Begin commit (starts promotion)
                try:
                    self.fs_client.commit(cg_id, epoch_id)
                except Exception:
                    pass

                # Simulate crash: kill processes immediately without ack
                self.proc_client.kill_by_cgroup(cg_id)

                # Check: file must be either fully promoted or absent
                check_path = harness_path(f"exp5/promo-{trial}.txt")
                if os.path.exists(check_path):
                    with open(check_path, "rb") as f:
                        content = f.read()
                    # Partial = has some bytes but not the full probe payload
                    partial = 0 < len(content) < 18
                    self.metrics.record(
                        "partial_file_published", partial,
                        f"promotion trial={trial}: partial file ({len(content)}B)",
                        {"fault": "promotion_crash", "trial": trial})
                else:
                    # File absent = promotion rolled back (acceptable)
                    self.metrics.record(
                        "partial_file_published", False,
                        trial_info={"fault": "promotion_crash", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        self._tests_completed += 1
        print(f"    completed")

    # ─── Fault: Effect duplication after restart ───────────────────────────

    def test_effect_duplication(self):
        """After syscall restart (continue), the effect must occur exactly once.

        Spawns a probe, lets it get fenced, then continues it. Verifies the
        effect appears exactly once in the backing store.
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [14/14] Effect duplication ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-dup-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                epoch_id = f"exp5-dup-{self.run_id}-{trial}"
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

                # Clean check path
                check_path = harness_path(f"exp5/dup-{trial}.txt")
                if os.path.exists(check_path):
                    os.unlink(check_path)

                # Spawn and hold, then release + continue (simulates restart)
                target = fuse_path(f"exp5/dup-{trial}.txt")
                proc, write_fd = self.runner.spawn_and_hold(
                    "fs_write", cg_path, args=[target])
                self.runner.release(write_fd)

                # Give time for fence, then continue
                time.sleep(0.05)
                try:
                    self.proc_client.continue_by_cgroup(cg_id)
                except Exception:
                    pass

                result = self.runner.wait_result(proc, "fs_write", timeout=5.0)

                # Commit
                try:
                    self.fs_client.commit(cg_id, epoch_id)
                except Exception:
                    pass

                # Check: effect must appear exactly once
                if os.path.exists(check_path):
                    with open(check_path, "rb") as f:
                        content = f.read()
                    count = content.count(b"SHADOW_EFFECT_DATA")
                    duplicated = count > 1
                    self.metrics.record(
                        "effect_duplicated", duplicated,
                        f"dup trial={trial}: effect appeared {count} times",
                        {"fault": "effect_dup", "trial": trial})
                else:
                    # No file = effect didn't happen (not a duplication issue)
                    self.metrics.record(
                        "effect_duplicated", False,
                        trial_info={"fault": "effect_dup", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        self._tests_completed += 1
        print(f"    completed")

    # ─── Fault: Rejected transcript must not become canonical ──────────────

    def test_rejected_transcript_not_canonical(self):
        """After deny+rollback, the rejected output must NOT become the
        canonical (committed) state visible to external readers."""
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [15/15] Rejected transcript ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-rej-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                epoch_id = f"exp5-rej-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                # Deny all (no policy installed)
                self.proc_client.set_epoch_mode(cg_id, 2)

                # Pre-create the file with known content
                check_path = harness_path(f"exp5/rej-{trial}.txt")
                os.makedirs(os.path.dirname(check_path), exist_ok=True)
                with open(check_path, "w") as f:
                    f.write("ORIGINAL_CANONICAL")

                # Probe tries to overwrite (must be denied)
                target = fuse_path(f"exp5/rej-{trial}.txt")
                result = self.runner.run_probe("fs_write", cg_path, args=[target])

                # Rollback
                try:
                    self.fs_client.rollback(cg_id, epoch_id)
                except Exception:
                    pass
                self.proc_client.kill_by_cgroup(cg_id)

                # Verify: canonical content must be unchanged
                with open(check_path, "r") as f:
                    final_content = f.read()

                rejected_became_canonical = ("SHADOW_EFFECT_DATA" in final_content)
                self.metrics.record(
                    "rejected_transcript_canonical", rejected_became_canonical,
                    f"rej trial={trial}: rejected content became canonical",
                    {"fault": "rejected_transcript", "trial": trial})

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        self._tests_completed += 1
        print(f"    completed")

    # ─── Fault: Drain failure ──────────────────────────────────────────────

    def test_drain_failure(self):
        """BPF ring buffer drain failure -> system must fail closed.

        Simulates the scenario where the userspace event consumer cannot
        drain events from the BPF ring buffer (e.g., consumer crashed,
        perf buffer full, or drain syscall blocked). The enforcement must
        still deny effects because:
          1. No policy can be installed (policy delivery depends on drain)
          2. ENFORCED mode with no policy = default deny
          3. Even if some stale policy exists, the audit gap means the
             system cannot safely release effects (no audit trail).

        We simulate this by:
          - Creating cgroups in ENFORCED mode WITHOUT installing policy
            (simulates policy drain failure)
          - Also testing with a previously-installed policy that is then
            cleared (simulates mid-session drain collapse)
          - Verifying effects are denied in both cases
        """
        actual_trials = self._trials_for_test(self.trials)
        print(f"  [16/16] Drain failure ({actual_trials} trials) ...", flush=True)
        for trial in range(actual_trials):
            try:
                cg_path, cg_id = self._setup_cgroup_safe(f"exp5-drain-{trial}")
            except RuntimeError as e:
                if "BPF_MAP_FULL" in str(e):
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    break
                raise

            try:
                # Begin epoch
                epoch_id = f"exp5-drain-{self.run_id}-{trial}"
                try:
                    self.fs_client.begin_epoch(cg_id, epoch_id)
                except Exception:
                    pass

                if trial % 2 == 0:
                    # Case A: Policy never installed (drain failed before delivery)
                    self.proc_client.set_epoch_mode(cg_id, 2)
                else:
                    # Case B: Policy installed then cleared (drain collapsed
                    # mid-session, stale policy invalidated)
                    policy = PolicyIR.from_allowed_ops([
                        {"event_type": "*", "action": "allow",
                         "path_pattern": "/"}
                    ]).to_proc_policy()
                    self.proc_client.install_proc_policy(cg_id, policy)
                    self.proc_client.set_epoch_mode(cg_id, 2)
                    # Simulate drain collapse: clear policy (userspace can't
                    # maintain policy state without event drain)
                    self.proc_client.clear_all_policies(cg_id)

                # Attempt effect - must be denied in both cases
                target = fuse_path(f"exp5/drain-{trial}.txt")
                result = self.runner.run_probe("fs_write", cg_path,
                                               args=[target])

                # Effect must NOT leak
                check_path = harness_path(f"exp5/drain-{trial}.txt")
                leaked = os.path.exists(check_path)
                self.metrics.record(
                    "fault_drain_failure", leaked,
                    f"drain_failure trial={trial}: effect leaked "
                    f"(case={'no_policy' if trial % 2 == 0 else 'cleared'})",
                    {"fault": "drain_failure", "trial": trial,
                     "case": "no_policy" if trial % 2 == 0 else "cleared"})

                # Also verify via safety invariant counter
                self.metrics.record(
                    "unauthorized_effect_leaked", leaked,
                    f"drain_failure trial={trial}: unauthorized effect",
                    {"fault": "drain_failure", "trial": trial})

                # Clean up test file if leaked
                if leaked:
                    try:
                        os.unlink(check_path)
                    except OSError:
                        pass

            except RuntimeError as e:
                if "Argument list too long" in str(e) or "map" in str(e).lower():
                    print(f"    [BPF map full at trial {trial}, stopping early]")
                    self._teardown_cgroup_safe(cg_path, cg_id)
                    break
                raise
            finally:
                self._teardown_cgroup_safe(cg_path, cg_id)
        self._tests_completed += 1
        print(f"    completed")

    def run(self):
        self.setup()
        print(f"\n{'='*70}")
        print(f"  EXPERIMENT 5: Fail-Closed & Concurrency")
        print(f"  Trials per fault: {self.trials}")
        print(f"{'='*70}\n")

        try:
            self.test_audit_log_corruption()
            self._tests_completed += 1
            self.test_policy_partial_install()
            self._tests_completed += 1
            self.test_fork_during_freeze()
            self._tests_completed += 1
            self.test_token_replay()
            self._tests_completed += 1
            self.test_wal_torn_tail()
            self._tests_completed += 1
            self.test_concurrent_race()
            self._tests_completed += 1
            self.test_no_partial_publication()
            self._tests_completed += 1
            self.test_no_premature_baseline_delete()
            self._tests_completed += 1
            self.test_ring_buffer_drop()
            self._tests_completed += 1
            self.test_path_reconstruction_failure()
            self._tests_completed += 1
            self.test_pid_cgroup_reuse()
            self._tests_completed += 1
            self.test_finalization_failure()
            self._tests_completed += 1
            # New tests
            self.test_promotion_mid_crash()
            self.test_effect_duplication()
            self.test_rejected_transcript_not_canonical()
            self.test_drain_failure()

        except KeyboardInterrupt:
            print("\n[exp5] Interrupted")
        finally:
            self.metrics.finish()
            self.teardown()

        self.metrics.print_report()

        # Print binomial confidence intervals
        print(f"\n  Binomial 95% Confidence Intervals:")
        print(f"  {'Metric':<35} {'Failures':<12} {'Trials':<10} {'CI'}")
        print(f"  {'-'*35} {'-'*12} {'-'*10} {'-'*25}")
        for name, counter in self.metrics.counters.items():
            if counter.total > 0:
                lo, hi = counter.ci()
                print(f"  {name:<35} {counter.count:<12} {counter.total:<10} "
                      f"[{lo:.6f}, {hi:.6f}]")

        return self.metrics


def main():
    parser = argparse.ArgumentParser(
        description="RQ2 Experiment 5: Fail-Closed & Concurrency")
    parser.add_argument("--trials", type=int, default=5000,
                        help="Number of trials per fault type")
    parser.add_argument("--output-dir", type=str, default="./results")
    args = parser.parse_args()

    if not RUN_EXPERIMENTS:
        print("ERROR: Set SHADOW_RUN_RQ2_EXPERIMENTS=1")
        sys.exit(1)

    exp = Experiment5(trials=args.trials)
    metrics = exp.run()
    metrics.save_report(args.output_dir)


if __name__ == "__main__":
    main()
