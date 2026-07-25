use anyhow::{Context, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::fs;

use crate::bpf_loader::{BpfManager, IpcPolicyEntry, NetPolicyEntry, ProcPolicy, SigPolicyEntry};
use crate::event_handler::InterceptEvent;
use crate::memory_tracker::MemoryTracker;

fn effect_policy_parts_from_event(event: &InterceptEvent) -> (u8, u8) {
    use crate::policy_generated::*;
    // FORK (101) is a process-lifecycle event, not an effect encoded via
    // ENCODE_EVENT; it is never intercepted through do_intercept, so this
    // defensive fallback is not expected to authorize any real syscall.
    if event.event_type == 101 {
        return (CLASS_NETWORK, OP_CONNECT);
    }
    // All intercepted events carry the unified (class | op<<8) encoding. The
    // restart token must match both class and operation so one-shot resume for
    // CONNECT cannot authorize BIND, PTRACE cannot authorize KILL, etc.
    (
        event_class_of(event.event_type as u16),
        event_op_of(event.event_type as u16),
    )
}

/// State of a frozen process
#[derive(Debug, Clone)]
pub struct FrozenProcess {
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    pub event: InterceptEvent,
    pub checkpoint_path: Option<PathBuf>,
    pub cgroup_path: String,
}

/// A promotion record: a stale (baseline) pid now transparently resolves to
/// `canonical`. Because bare pids are recycled by the kernel, we also store the
/// /proc `starttime` of both endpoints captured when the promotion was created.
/// resolve_pid refuses to follow a hop whose endpoint pid is alive but carries a
/// DIFFERENT starttime — i.e. the number was reused by an unrelated process.
#[derive(Debug, Clone, Copy)]
struct Promotion {
    canonical: u32,
    /// starttime of the KEY (old) pid at promotion time.
    key_start: u64,
    /// starttime of the canonical pid at promotion time.
    canonical_start: u64,
}

#[allow(dead_code)]
/// Manages frozen processes - checkpoint, restore, continue, discard
pub struct ProcessManager {
    frozen: HashMap<u32, FrozenProcess>,
    checkpoint_dir: PathBuf,
    next_checkpoint_id: u32,
    bpf_manager: Arc<BpfManager>,
    memory_tracker: MemoryTracker,
    /// Maps an old (rejected/committed) baseline pid to the canonical pid its
    /// work was promoted to. Lets callers still holding a stale pid transparently
    /// address the live process. Each entry also records the /proc start time of
    /// BOTH endpoints so pid reuse is detected (see `Promotion` / resolve_pid).
    promoted: HashMap<u32, Promotion>,
}

impl ProcessManager {
    pub fn new(checkpoint_dir: PathBuf, bpf_manager: Arc<BpfManager>) -> Self {
        std::fs::create_dir_all(&checkpoint_dir).ok();
        ProcessManager {
            frozen: HashMap::new(),
            checkpoint_dir,
            next_checkpoint_id: 0,
            bpf_manager,
            memory_tracker: MemoryTracker::new(),
            promoted: HashMap::new(),
        }
    }

    /// Record a newly frozen process (it was already SIGSTOP'd by eBPF)
    pub fn record_frozen(&mut self, event: InterceptEvent) {
        let pid = event.tgid; // Use tgid as the main process identifier
        if self.frozen.contains_key(&pid) {
            return; // Already tracked
        }
        let cgroup_path = read_process_cgroup(pid).unwrap_or_else(|| format!("pid-{}", pid));
        let frozen = FrozenProcess {
            pid: event.pid,
            tgid: event.tgid,
            comm: event.comm_str(),
            event,
            checkpoint_path: None,
            cgroup_path,
        };
        self.frozen.insert(pid, frozen);
    }

    /// List all frozen processes
    pub fn list_frozen(&self) -> Vec<&FrozenProcess> {
        self.frozen.values().collect()
    }

    /// Continue a frozen process to completion (full release).
    ///
    /// In the three-state model, this transitions the cgroup to ENFORCED mode
    /// with allow-all class policies: every effect class is permitted, so the
    /// process runs to completion and exits (including the exit-hold sentinel,
    /// which is a network connect that passes under allow-all NETWORK policy).
    /// The pending syscall is allowed by policy_allows() on restart — no
    /// restart token is needed since ENFORCED + allow-all already permits it.
    pub fn continue_process(&mut self, pid: u32) -> Result<()> {
        let pid = self.resolve_pid(pid);
        let frozen = self.frozen.get(&pid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Process {} is not in frozen list", pid))?;

        // Transition to ENFORCED + allow-all: every effect class is permitted.
        if let Ok(cg_id) = self.bpf_manager.cgroup_id_from_path(&frozen.cgroup_path) {
            self.bpf_manager.enforce_allow_all(cg_id)?;
        }

        // Clear the stopped mark BEFORE SIGCONT so the restarted syscall
        // is not treated as an in-flight stop dedup.
        self.bpf_manager.clear_stopped_mark(pid)?;

        // SIGCONT: kernel auto-restarts the syscall via -ERESTARTSYS.
        // In ENFORCED + allow-all mode, check_policy returns DECISION_ALLOW.
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGCONT)
            .with_context(|| format!("Failed to send SIGCONT to pid {}", pid))?;

        self.frozen.remove(&pid);
        Ok(())
    }

    /// Resume a frozen process with a ONE-SHOT restart token (SPECULATIVE
    /// phase authorization): the token authorizes exactly ONE pending syscall
    /// pass. After the token is consumed, the next intercepted syscall is
    /// fenced again (SPECULATIVE mode) — no permanent bypass.
    ///
    /// This is the correct primitive for authorizing a single reviewed effect
    /// without releasing the whole epoch. For full release (run to completion),
    /// use `continue_process` (transitions to ENFORCED + allow-all).
    pub fn resume_process(&mut self, pid: u32) -> Result<()> {
        let pid = self.resolve_pid(pid);
        let frozen = self.frozen.get(&pid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Process {} is not in frozen list", pid))?;

        // Grant a one-shot restart token for the pending syscall (if any).
        // The token is consumed on the next matching syscall_nr, then deleted.
        if frozen.event.syscall_nr != 0 {
            let (effect_class, operation) = effect_policy_parts_from_event(&frozen.event);
            self.bpf_manager.grant_restart_token(
                frozen.event.pid,  // tid (thread that was intercepted)
                frozen.event.syscall_nr,
                effect_class,
                operation,
            )?;
        }

        // Clear the stopped mark BEFORE SIGCONT so the restarted syscall
        // is not treated as an in-flight stop dedup.
        self.bpf_manager.clear_stopped_mark(pid)?;

        // SIGCONT: kernel auto-restarts the syscall via -ERESTARTSYS.
        // check_policy finds the token, consumes it, returns DECISION_ALLOW.
        // The next intercepted syscall gets DECISION_FENCE (SPECULATIVE mode).
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGCONT)
            .with_context(|| format!("Failed to send SIGCONT to pid {}", pid))?;

        self.frozen.remove(&pid);
        Ok(())
    }

    /// Freeze a SINGLE process by SIGSTOP and register it as frozen, waiting
    /// briefly for it to actually reach the stopped state.
    ///
    /// Used by the one-shot `spec_fork` path to snapshot a running process at a
    /// boundary WITHOUT going through eBPF interception. Registering it in the
    /// frozen map is required so `register_candidate` can build the candidate's
    /// frozen record (it clones the baseline's). Idempotent: a pid already in
    /// the frozen map is left as-is.
    pub fn freeze_pid(&mut self, pid: u32) -> Result<()> {
        let pid = self.resolve_pid(pid);
        if self.frozen.contains_key(&pid) {
            return Ok(());
        }
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGSTOP)
            .with_context(|| format!("Failed to SIGSTOP pid {}", pid))?;
        // Wait for the SIGSTOP to land so the subsequent ptrace injection sees a
        // cleanly group-stopped task (best-effort; injection's SEIZE+INTERRUPT
        // can still stop it if this times out).
        wait_task_stopped(pid, 1000);

        let cgroup_path = read_process_cgroup(pid).unwrap_or_else(|| format!("pid-{}", pid));
        let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string();
        self.frozen.insert(
            pid,
            FrozenProcess {
                pid,
                tgid: pid,
                comm,
                event: InterceptEvent::dummy_freeze(pid),
                checkpoint_path: None,
                cgroup_path,
            },
        );
        Ok(())
    }

    /// Resume a candidate with a plain SIGCONT, touching NO eBPF map.
    ///
    /// The candidate is a freshly cloned tgid (not in any allow map, so armed
    /// by default) frozen at a NON-intercepted boundary (e.g. read()), so it
    /// needs no allow-pass to proceed — it just needs to be woken. Its later
    /// intercepted syscalls (connect/write/...) are caught normally. Used by
    /// the `spec_fork` path; deliberately does NOT call clear_stopped /
    /// rearm_intercept so the injection stays independent of the enforcement
    /// allow logic.
    pub fn resume_candidate_raw(&mut self, pid: u32) -> Result<()> {
        let pid = self.resolve_pid(pid);
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGCONT)
            .with_context(|| format!("Failed to SIGCONT candidate {}", pid))?;
        self.frozen.remove(&pid);
        Ok(())
    }

    /// Discard (kill) a frozen process
    pub fn discard_process(&mut self, pid: u32) -> Result<()> {
        // A stale pid (a process that was rejected/promoted) is transparently
        // redirected to its current canonical pid.
        let pid = self.resolve_pid(pid);
        // The pid may be a frozen (held) process, or a promoted canonical
        // process still running after a reject. Either way, SIGKILL it.
        if !self.frozen.contains_key(&pid) && !self.is_promoted_pid(pid) {
            anyhow::bail!("Process {} is not in frozen list", pid);
        }

        signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
            .with_context(|| format!("Failed to send SIGKILL to pid {}", pid))?;

        self.frozen.remove(&pid);
        // Drop any promotion records that pointed at this now-dead pid.
        self.promoted.retain(|_, v| v.canonical != pid);
        Ok(())
    }

    /// Checkpoint a frozen process using CRIU
    pub fn checkpoint(&mut self, pid: u32) -> Result<PathBuf> {
        if !self.frozen.contains_key(&pid) {
            anyhow::bail!("Process {} is not in frozen list", pid);
        }

        let checkpoint_id = self.next_checkpoint_id;
        self.next_checkpoint_id += 1;

        let dump_dir = self.checkpoint_dir.join(format!("checkpoint-{}", checkpoint_id));
        std::fs::create_dir_all(&dump_dir)
            .with_context(|| format!("Failed to create checkpoint dir: {:?}", dump_dir))?;

        // Run CRIU dump (leave the process stopped)
        let output = Command::new("criu")
            .args([
                "dump",
                "-t",
                &pid.to_string(),
                "-D",
                dump_dir.to_str().unwrap(),
                "--leave-stopped",
                "--shell-job",
            ])
            .output()
            .context("Failed to execute criu dump")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("CRIU dump failed: {}", stderr);
        }

        if let Some(frozen) = self.frozen.get_mut(&pid) {
            frozen.checkpoint_path = Some(dump_dir.clone());
        }

        Ok(dump_dir)
    }

    /// Restore a process from a CRIU checkpoint
    pub fn restore(&self, checkpoint_path: &Path) -> Result<u32> {
        let output = Command::new("criu")
            .args([
                "restore",
                "-D",
                checkpoint_path.to_str().unwrap(),
                "--shell-job",
                "-d",
            ])
            .output()
            .context("Failed to execute criu restore")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("CRIU restore failed: {}", stderr);
        }

        // CRIU restore output contains the new PID
        let _stdout = String::from_utf8_lossy(&output.stdout);
        // In detached mode, the restored process runs with its original PID
        // We return 0 to indicate success (original PID is restored)
        Ok(0)
    }

    /// Get info about a specific frozen process
    pub fn get_frozen(&self, pid: u32) -> Option<&FrozenProcess> {
        self.frozen.get(&pid)
    }

    /// Check if a process is in the frozen list
    pub fn is_frozen(&self, pid: u32) -> bool {
        self.frozen.contains_key(&pid)
    }

    /// List frozen processes filtered by cgroup path
    pub fn list_frozen_by_cgroup(&self, cgroup_path: &str) -> Vec<&FrozenProcess> {
        self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .collect()
    }

    /// Continue all frozen processes in a given cgroup to completion (full
    /// release). Returns Ok(resumed pids) only if EVERY frozen process in the
    /// cgroup was released; if any PID fails to continue it returns an Err
    /// naming the failures, so the caller can fail closed rather than acking a
    /// partial release. Already-released PIDs are still reflected via the error
    /// message for diagnostics.
    pub fn continue_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut resumed = Vec::new();
        let mut failed: Vec<u32> = Vec::new();
        for pid in pids {
            match self.continue_process(pid) {
                Ok(()) => resumed.push(pid),
                Err(_) => failed.push(pid),
            }
        }
        if !failed.is_empty() {
            anyhow::bail!(
                "continue_by_cgroup partial failure in {}: resumed {:?}, failed {:?}",
                cgroup_path, resumed, failed
            );
        }
        Ok(resumed)
    }

    /// Continue all frozen processes in a cgroup under a FINE-GRAINED
    /// process-layer policy (P0-5) instead of the allow-all class policy
    /// installed by continue_process().
    ///
    /// Fail-closed on BOTH axes:
    ///   * policy installation failure  -> nobody is SIGCONT'd;
    ///   * partial SIGCONT failure      -> Err naming the failures.
    ///
    /// `policy == None` keeps the legacy allow-all behavior.
    pub fn continue_by_cgroup_with_policy(
        &mut self,
        cgroup_path: &str,
        policy: Option<&ProcPolicy>,
    ) -> Result<Vec<u32>> {
        let Some(pol) = policy else {
            return self.continue_by_cgroup(cgroup_path);
        };

        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();

        // Install the fine-grained policy BEFORE releasing anyone. If this
        // fails the cgroup stays in its previous mode and no process is
        // resumed (fail-closed).
        let cg_id = self.bpf_manager.cgroup_id_from_path(cgroup_path)
            .with_context(|| format!(
                "continue_by_cgroup_with_policy: cannot resolve cgroup id for {}",
                cgroup_path
            ))?;
        self.bpf_manager.enforce_policy(cg_id, pol)
            .context("continue_by_cgroup_with_policy: policy installation failed; not releasing")?;

        let mut resumed = Vec::new();
        let mut failed: Vec<u32> = Vec::new();
        for pid in pids {
            match self.sigcont_enforced(pid) {
                Ok(()) => resumed.push(pid),
                Err(_) => failed.push(pid),
            }
        }
        if !failed.is_empty() {
            anyhow::bail!(
                "continue_by_cgroup_with_policy partial failure in {}: resumed {:?}, failed {:?}",
                cgroup_path, resumed, failed
            );
        }
        Ok(resumed)
    }

    /// SIGCONT a frozen process whose cgroup is ALREADY in ENFORCED mode
    /// with its policy installed by the caller. Unlike continue_process(),
    /// this does NOT install the allow-all class policy.
    fn sigcont_enforced(&mut self, pid: u32) -> Result<()> {
        let pid = self.resolve_pid(pid);
        if !self.frozen.contains_key(&pid) {
            anyhow::bail!("Process {} is not in frozen list", pid);
        }
        // Clear the stopped mark BEFORE SIGCONT so the restarted syscall
        // is not treated as an in-flight stop dedup.
        self.bpf_manager.clear_stopped_mark(pid)?;
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGCONT)
            .with_context(|| format!("Failed to send SIGCONT to pid {}", pid))?;
        self.frozen.remove(&pid);
        Ok(())
    }

    /// Parse a JSON fine-grained process policy into a ProcPolicy (P0-5).
    /// Fail-closed: any malformed entry aborts the whole parse so a partial
    /// policy can never reach the BPF maps.
    ///
    /// Schema (all integer fields; addr/port HOST order, 0 = wildcard):
    ///   {
    ///     "classes": [{"effect_class": 2, "operation": 1, "mode": 2}, ...],
    ///     "network": [{"operation": 1, "family": 2, "addr": u32, "port": u16, "allow": 1}, ...],
    ///     "ipc":     [{"operation": 3, "ipc_type": 1, "target": u64, "allow": 1}, ...],
    ///     "signal":  [{"operation": 1, "target_cgroup": u64, "allow": 1}, ...]
    ///   }
    pub fn parse_proc_policy(v: &serde_json::Value) -> Result<ProcPolicy> {
        fn req_u64(obj: &serde_json::Value, field: &str, max: u64) -> Result<u64> {
            let n = obj.get(field)
                .and_then(|x| x.as_u64())
                .ok_or_else(|| anyhow::anyhow!("policy entry missing/invalid '{}'", field))?;
            if n > max {
                anyhow::bail!("policy field '{}' = {} out of range (max {})", field, n, max);
            }
            Ok(n)
        }
        fn req_allow(obj: &serde_json::Value) -> Result<u8> {
            let n = req_u64(obj, "allow", 1)?;
            Ok(n as u8)
        }

        let mut out = ProcPolicy::default();

        if let Some(classes) = v.get("classes") {
            let arr = classes.as_array()
                .ok_or_else(|| anyhow::anyhow!("'classes' must be an array"))?;
            for c in arr {
                let cls = req_u64(c, "effect_class", 7)?;
                if cls < 1 {
                    anyhow::bail!("effect_class must be >= 1");
                }
                let op = req_u64(c, "operation", u8::MAX as u64)?;
                if op < 1 {
                    anyhow::bail!("operation must be >= 1");
                }
                let mode = req_u64(c, "mode", 2)?;
                if mode < 1 {
                    anyhow::bail!("operation mode must be 1 (allow) or 2 (fine-grained)");
                }
                out.classes.push((cls as u8, op as u8, mode as u8));
            }
        }

        if let Some(net) = v.get("network") {
            let arr = net.as_array()
                .ok_or_else(|| anyhow::anyhow!("'network' must be an array"))?;
            for e in arr {
                out.network.push(NetPolicyEntry {
                    operation: req_u64(e, "operation", u8::MAX as u64)? as u8,
                    family: req_u64(e, "family", u8::MAX as u64)? as u8,
                    addr: req_u64(e, "addr", u32::MAX as u64)? as u32,
                    port: req_u64(e, "port", u16::MAX as u64)? as u16,
                    allow: req_allow(e)?,
                });
            }
        }

        if let Some(ipc) = v.get("ipc") {
            let arr = ipc.as_array()
                .ok_or_else(|| anyhow::anyhow!("'ipc' must be an array"))?;
            for e in arr {
                let ipc_type = req_u64(e, "ipc_type", 5)?;
                if ipc_type < 1 {
                    anyhow::bail!("ipc_type must be >= 1");
                }
                out.ipc.push(IpcPolicyEntry {
                    operation: req_u64(e, "operation", u8::MAX as u64)? as u8,
                    ipc_type: ipc_type as u8,
                    target: req_u64(e, "target", u64::MAX)?,
                    allow: req_allow(e)?,
                });
            }
        }

        if let Some(sig) = v.get("signal") {
            let arr = sig.as_array()
                .ok_or_else(|| anyhow::anyhow!("'signal' must be an array"))?;
            for e in arr {
                out.signal.push(SigPolicyEntry {
                    operation: req_u64(e, "operation", u8::MAX as u64)? as u8,
                    target_cgroup: req_u64(e, "target_cgroup", u64::MAX)?,
                    allow: req_allow(e)?,
                });
            }
        }

        Ok(out)
    }

    /// Kill all frozen processes in a given cgroup
    pub fn kill_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut killed = Vec::new();
        for pid in pids {
            if self.discard_process(pid).is_ok() {
                killed.push(pid);
            }
        }
        Ok(killed)
    }

    // ═══════════════════════════════════════════════════════════════
    // COW Memory Tracking API
    // ═══════════════════════════════════════════════════════════════

    /// Begin a versioning epoch for a frozen process WITHOUT holding the
    /// ProcessManager lock across the multi-second ptrace clone injection.
    ///
    /// This is an associated function taking the shared `Arc<Mutex<Self>>`
    /// rather than `&mut self`: a `&mut self` method is inherently called with
    /// the lock already held by the caller and cannot release it mid-way (the
    /// MutexGuard lives in the caller's scope). By taking the Arc<Mutex> it can
    /// lock/unlock/relock internally and run the three-phase setup:
    ///   reserve (locked) -> inject (unlocked) -> finish/abort (locked)
    /// so concurrent socket clients and the event loop keep making progress
    /// during the slow injection.
    ///
    /// The ORIGINAL becomes the frozen pristine baseline; a COW candidate is
    /// forked to run the epoch speculatively. Subsequent resume/commit/rollback
    /// on the caller's pid are transparently redirected to the candidate.
    /// Returns the candidate pid (the live process for this epoch).
    pub fn begin_speculative_unlocked(
        pm: &Arc<Mutex<ProcessManager>>,
        pid: u32,
    ) -> Result<u32> {
        // Phase 1 (locked): resolve to the canonical baseline and reserve it so
        // no concurrent caller can start a second epoch for the same pid while
        // the lock is released for injection. reserve_speculative resolves the
        // pid internally.
        let baseline = { pm.lock().unwrap().reserve_speculative(pid)? };

        // Phase 2 (unlocked): the slow ptrace clone injection. Touches no
        // ProcessManager state, so it is safe to run with the lock released.
        let injected = ProcessManager::inject_speculative(baseline);

        // Phase 3 (locked): record the injected candidate and redirect the
        // baseline pid to it, or release the reservation if injection failed.
        let mut guard = pm.lock().unwrap();
        match injected {
            Ok((candidate, regs)) => Ok(guard.finish_speculative(baseline, candidate, regs)),
            Err(e) => {
                guard.abort_speculative(baseline);
                Err(e)
            }
        }
    }

    /// Lock-free epoch setup, phase 1 (call under the PM lock): resolve the
    /// caller's pid to its canonical baseline and reserve it. Returns the
    /// baseline pid to inject into. The caller then RELEASES the lock, calls
    /// `inject_speculative`, and re-acquires the lock for `finish_speculative`
    /// / `abort_speculative`.
    pub fn reserve_speculative(&mut self, pid: u32) -> Result<u32> {
        let pid = self.resolve_pid(pid);
        self.memory_tracker.reserve(pid)?;
        Ok(pid)
    }

    /// Reserve every frozen (non-baseline) process in `cgroup_path` for a new
    /// epoch. Returns the reserved baseline pids. Call under the PM lock.
    pub fn reserve_speculative_by_cgroup(&mut self, cgroup_path: &str) -> Vec<u32> {
        let pids: Vec<u32> = self
            .frozen
            .values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut reserved = Vec::new();
        for pid in pids {
            let r = self.resolve_pid(pid);
            if self.memory_tracker.reserve(r).is_ok() {
                reserved.push(r);
            }
        }
        reserved
    }

    /// Lock-free epoch setup, phase 2 (call WITHOUT the PM lock): the slow
    /// ptrace clone injection for a reserved baseline pid.
    pub fn inject_speculative(pid: u32) -> Result<(u32, libc::user_regs_struct)> {
        MemoryTracker::inject(pid)
    }

    /// Lock-free epoch setup, phase 3a (call under the PM lock): record the
    /// injected candidate and redirect the baseline pid to it. Returns the
    /// candidate pid (the live process for this epoch).
    pub fn finish_speculative(
        &mut self,
        baseline: u32,
        candidate: u32,
        orig_regs: libc::user_regs_struct,
    ) -> u32 {
        self.memory_tracker
            .finish_tracking(baseline, candidate, orig_regs);
        self.register_candidate(baseline, candidate);
        // Reset the cgroup to SPECULATIVE mode for the new epoch.
        // This clears any ENFORCED mode + allow-all policies left from a prior
        // epoch's continue/commit, so the candidate starts fenced (not
        // pre-authorized). The freshly cloned candidate has a new tgid and is
        // armed by default (SPECULATIVE = fence all external effects).
        if let Some(fp) = self.frozen.get(&candidate) {
            if let Ok(cg_id) = self.bpf_manager.cgroup_id_from_path(&fp.cgroup_path) {
                let _ = self.bpf_manager.clear_all_policies(cg_id);
            }
        }
        candidate
    }

    /// Lock-free epoch setup, phase 3b (call under the PM lock): release a
    /// reservation whose injection failed.
    pub fn abort_speculative(&mut self, baseline: u32) {
        self.memory_tracker.abort_reserve(baseline);
    }

    /// Redirect a baseline pid to its speculative candidate AND register the
    /// candidate as a resumable frozen process. The candidate (the COW fork) is
    /// the process that actually runs the epoch, so resume_pid / continue_pid /
    /// cgroup operations must be able to act on it. It inherits the baseline's
    /// frozen record (same cgroup) with the candidate pid/tgid substituted.
    fn register_candidate(&mut self, baseline: u32, candidate: u32) {
        // Capture both endpoints' process identity (pid + starttime) now, while
        // both are alive, so a later pid reuse of either number cannot silently
        // hijack this redirection (see resolve_pid).
        self.promoted.insert(
            baseline,
            Promotion {
                canonical: candidate,
                key_start: process_starttime(baseline).unwrap_or(0),
                canonical_start: process_starttime(candidate).unwrap_or(0),
            },
        );
        if let Some(fp) = self.frozen.get(&baseline).cloned() {
            let mut c = fp;
            c.pid = candidate;
            c.tgid = candidate;
            self.frozen.insert(candidate, c);
        }
    }

    /// Roll back a speculative epoch via the Frozen-Baseline model: discard the
    /// candidate (the speculative fork) AND its surviving epoch descendants,
    /// then RESUME the pristine baseline — the original process, which never
    /// executed the epoch's command. Returns the baseline pid, which is the
    /// canonical process from now on.
    ///
    /// Unlike splicing a stale memory image onto live registers, this can never
    /// crash the target and never changes the canonical pid: the original keeps
    /// its identity, session and parent lineage.
    pub fn reject_to_checkpoint(&mut self, pid: u32) -> Result<u32> {
        let live = self.resolve_pid(pid);
        let baseline = self.memory_tracker.reject_to_checkpoint(live)?;

        // Discard the candidate's surviving epoch descendants. The candidate
        // (just killed) may have forked children during the epoch; being born
        // inside the epoch they are part of the speculative work that, from the
        // baseline's point of view, never happened. When the candidate dies they
        // are reparented (NOT reaped), so we must kill them explicitly. Cleanup
        // is cgroup-scoped: kill every pid in the candidate's cgroup EXCEPT the
        // baseline we are about to resume (and any other epoch's pristine
        // baseline). This is the "discard the epoch as a unit" guarantee the
        // Frozen-Baseline model relies on.
        let cgroup_path = self
            .frozen
            .get(&baseline)
            .map(|fp| fp.cgroup_path.clone())
            .or_else(|| read_process_cgroup(baseline));
        if let Some(cg) = cgroup_path {
            let killed = self.kill_cgroup_descendants(&cg, baseline);
            if !killed.is_empty() {
                eprintln!(
                    "[cow] Rollback: discarded {} surviving epoch descendant(s): {:?}",
                    killed.len(),
                    killed
                );
            }
        }

        // The candidate is dead; drop its frozen record (if any).
        self.frozen.remove(&live);

        // The baseline was rewound onto its interrupted boundary syscall by
        // memory_tracker::reject_to_checkpoint and left group-stopped. Grant a
        // one-shot restart token for the pending syscall (if it was frozen at
        // an intercepted boundary), clear the stopped mark, and SIGCONT so it
        // re-executes that syscall and continues as the canonical process.
        // The token is consumed on restart; the next intercepted syscall is
        // fenced again (SPECULATIVE mode — no permanent bypass).
        if let Some(fp) = self.frozen.get(&baseline) {
            if fp.event.syscall_nr != 0 {
                let (effect_class, operation) = effect_policy_parts_from_event(&fp.event);
                let _ = self.bpf_manager.grant_restart_token(
                    fp.event.pid,
                    fp.event.syscall_nr,
                    effect_class,
                    operation,
                );
            }
        }
        let _ = self.bpf_manager.clear_stopped_mark(baseline);
        let _ = signal::kill(Pid::from_raw(baseline as i32), Signal::SIGCONT);

        // The baseline is live again under its own pid: drop the promotion that
        // had redirected it to the (now dead) candidate, and its frozen record.
        self.promoted.remove(&baseline);
        self.frozen.remove(&baseline);
        Ok(baseline)
    }

    /// Kill every process in `cgroup_path` EXCEPT `keep` and any versioning
    /// baseline (a pristine rollback copy). Used to discard a rejected
    /// candidate's surviving epoch descendants as a unit. Returns killed pids.
    fn kill_cgroup_descendants(&mut self, cgroup_path: &str, keep: u32) -> Vec<u32> {
        let cgroup_dir = if cgroup_path.starts_with('/') {
            format!("/sys/fs/cgroup{}/cgroup.procs", cgroup_path)
        } else {
            format!("/sys/fs/cgroup/{}/cgroup.procs", cgroup_path)
        };
        let mut killed = Vec::new();
        // Track pids we've already SIGKILL'd: a killed task can linger as a
        // zombie in cgroup.procs until reaped, and we must neither re-count it
        // nor spin on it.
        let mut done: HashSet<u32> = HashSet::new();
        // Loop to a fixpoint so descendants forked mid-teardown are also caught:
        // a killed parent cannot spawn more children, so once a pass kills
        // nothing new the subtree is drained. The 1000-pass cap bounds
        // pathological cases.
        for _ in 0..1000 {
            let data = match fs::read_to_string(&cgroup_dir) {
                Ok(d) => d,
                Err(_) => break,
            };
            let mut killed_new = false;
            for line in data.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let cpid: u32 = match line.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                // Never kill the baseline we are resuming, nor any other epoch's
                // pristine versioning baseline; skip pids already killed.
                if cpid == keep
                    || self.memory_tracker.is_shadow_pid(cpid)
                    || done.contains(&cpid)
                {
                    continue;
                }
                if signal::kill(Pid::from_raw(cpid as i32), Signal::SIGKILL).is_ok() {
                    self.frozen.remove(&cpid);
                    self.promoted.retain(|_, v| v.canonical != cpid);
                    killed.push(cpid);
                    done.insert(cpid);
                    killed_new = true;
                }
            }
            if !killed_new {
                break;
            }
        }
        killed
    }

    /// Roll back all speculative epochs whose baseline lives in `cgroup_path`:
    /// for each, discard the candidate (and its epoch descendants) and resume
    /// the pristine baseline. Returns the resumed baseline pids. Non-versioned
    /// frozen processes in the cgroup are left untouched (kill them separately
    /// via kill_by_cgroup if desired).
    pub fn reject_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        // Epochs are keyed by baseline pid. Select those whose baseline lives in
        // this cgroup (prefer the recorded frozen cgroup, fall back to /proc).
        let baselines: Vec<u32> = self
            .memory_tracker
            .tracked_pids()
            .into_iter()
            .filter(|&b| {
                self.frozen
                    .get(&b)
                    .map(|fp| fp.cgroup_path == cgroup_path)
                    .unwrap_or(false)
                    || read_process_cgroup(b)
                        .map(|c| c == cgroup_path)
                        .unwrap_or(false)
            })
            .collect();
        let mut resumed = Vec::new();
        for b in baselines {
            if let Ok(baseline) = self.reject_to_checkpoint(b) {
                resumed.push(baseline);
            }
        }
        Ok(resumed)
    }

    /// Resolve a possibly-stale pid to its current canonical pid by following
    /// the promotion chain produced by reject_to_checkpoint(). Returns the input
    /// pid unchanged when it was never promoted.
    pub fn resolve_pid(&self, pid: u32) -> u32 {
        let mut cur = pid;
        let mut hops = 0;
        while let Some(promo) = self.promoted.get(&cur) {
            // If `cur` is a currently-LIVE process whose start time differs from
            // the one recorded at promotion time, the pid has been reused by a
            // new, unrelated process. The caller means THAT process, so stop
            // following the (now stale) redirection.
            if let Some(st) = process_starttime(cur) {
                if st != promo.key_start {
                    break;
                }
            }
            // Likewise, if the canonical endpoint's pid is alive but was reused
            // (different starttime), the mapping is stale — do not redirect onto
            // an unrelated process.
            if let Some(cst) = process_starttime(promo.canonical) {
                if cst != promo.canonical_start {
                    break;
                }
            }
            cur = promo.canonical;
            hops += 1;
            if hops > 64 {
                break; // guard against accidental cycles
            }
        }
        cur
    }

    /// Check if a pid is a canonical process promoted from a rejected
    /// speculative process (i.e. it is the target of a promotion mapping).
    fn is_promoted_pid(&self, pid: u32) -> bool {
        self.promoted.values().any(|p| p.canonical == pid)
    }

    /// Commit a speculative epoch: accept the candidate as canonical and
    /// discard the pristine baseline. The candidate keeps running; the caller's
    /// pid stays redirected to it.
    pub fn commit_process(&mut self, pid: u32) -> Result<()> {
        let live = self.resolve_pid(pid);
        // commit() kills the baseline and keeps the candidate live; it returns
        // the discarded baseline pid.
        let baseline = self.memory_tracker.commit(live)?;
        // The baseline is gone (killed by memory_tracker.commit); drop its
        // frozen record and clean up its stopped_pids entry. The candidate
        // stays as-is (still frozen at its boundary, resumable via
        // continue_pid). The promotion baseline -> candidate is kept so any
        // lingering reference to the old pid resolves to the canonical candidate.
        let _ = self.bpf_manager.clear_stopped_mark(baseline);
        self.frozen.remove(&baseline);
        Ok(())
    }

    /// Commit all tracked processes in a cgroup.
    ///
    /// FAIL CLOSED on partial failure: if ANY tracked process fails to commit,
    /// this returns Err (listing every failed pid) instead of silently
    /// reporting partial success -- the orchestrator must keep the cgroup
    /// fenced and retry rather than release against a half-committed state.
    /// Already-committed pids are no longer tracked, so a retry is safe: it
    /// skips them and re-attempts only the failures.
    pub fn commit_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut committed = Vec::new();
        let mut failures = Vec::new();
        for pid in pids {
            if !self.memory_tracker.is_tracking(pid) {
                continue; // non-versioned frozen process: nothing to commit
            }
            match self.commit_process(pid) {
                Ok(()) => committed.push(pid),
                Err(e) => failures.push(format!("pid {}: {}", pid, e)),
            }
        }
        if !failures.is_empty() {
            anyhow::bail!(
                "commit_by_cgroup {}: {} process(es) failed to commit [{}] \
                 ({} committed before the failure; retry re-attempts only the \
                 failures)",
                cgroup_path, failures.len(), failures.join("; "), committed.len()
            );
        }
        Ok(committed)
    }

    /// Check if a process is being COW-tracked
    pub fn is_cow_tracking(&self, pid: u32) -> bool {
        self.memory_tracker.is_tracking(pid)
    }

    /// Check if a pid is a frozen versioning BASELINE (the pristine original
    /// copy held for rollback). Such pids must be excluded from cgroup-level
    /// freeze operations while their epoch is live.
    pub fn is_shadow_pid(&self, pid: u32) -> bool {
        self.memory_tracker.is_shadow_pid(pid)
    }

    /// Handle a fork event from eBPF: auto-track the child if parent is tracked.
    pub fn handle_fork_event(&mut self, parent_tgid: u32, child_tgid: u32) -> Result<bool> {
        self.memory_tracker.handle_fork_event(parent_tgid, child_tgid)
    }

    /// Enable or disable COW auto-tracking of child processes.
    pub fn set_cow_auto_track(&mut self, enabled: bool) {
        self.memory_tracker.set_auto_track(enabled);
    }

    /// Check if COW auto-tracking is enabled.
    pub fn is_cow_auto_track_enabled(&self) -> bool {
        self.memory_tracker.is_auto_track_enabled()
    }

    /// Actively freeze (SIGSTOP) all processes in a given cgroup.
    /// Reads pids from /sys/fs/cgroup/<cgroup_name>/cgroup.procs and sends SIGSTOP.
    /// Records them in the frozen list for later resume/kill.
    pub fn freeze_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        // Construct the cgroup.procs path from the cgroup_id
        // cgroup_path is like "/shadow-demo", map to /sys/fs/cgroup/shadow-demo/cgroup.procs
        let cgroup_dir = if cgroup_path.starts_with('/') {
            format!("/sys/fs/cgroup{}/cgroup.procs", cgroup_path)
        } else {
            format!("/sys/fs/cgroup/{}/cgroup.procs", cgroup_path)
        };

        let mut frozen_pids = Vec::new();
        // Loop to a fixpoint: a SIGSTOP'd parent cannot fork, so once a full pass
        // over cgroup.procs stops no new pids the whole subtree is quiescent.
        // This closes the TOCTOU/fork race where a child is forked between
        // reading cgroup.procs and SIGSTOP'ing its parent. The 1000-pass cap is
        // a safety bound; convergence normally takes 1-2 passes.
        for _ in 0..1000 {
            let data = fs::read_to_string(&cgroup_dir)
                .with_context(|| format!("Failed to read cgroup.procs: {}", cgroup_dir))?;

            let mut added = false;
            for line in data.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let pid: u32 = match line.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Skip if already frozen (also makes each pass act only on
                // genuinely new pids, so the loop converges).
                if self.frozen.contains_key(&pid) {
                    continue;
                }

                // Skip frozen versioning baselines: they live in the cgroup only
                // as pristine, ptrace-snapshotted rollback copies of a tracked
                // process. SIGSTOP'ing them again would disturb the versioning
                // machinery, so they must never be re-frozen as siblings. (The
                // candidate, i.e. the live fork, is NOT skipped — cgroup freeze
                // legitimately acts on it.)
                if self.memory_tracker.is_shadow_pid(pid) {
                    continue;
                }

                // Send SIGSTOP
                if signal::kill(Pid::from_raw(pid as i32), Signal::SIGSTOP).is_ok() {
                    let cgroup_id = read_process_cgroup(pid)
                        .unwrap_or_else(|| cgroup_path.to_string());
                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                        .unwrap_or_default()
                        .trim()
                        .to_string();

                    let frozen = FrozenProcess {
                        pid,
                        tgid: pid,
                        comm,
                        event: InterceptEvent::dummy_freeze(pid),
                        checkpoint_path: None,
                        cgroup_path: cgroup_id,
                    };
                    self.frozen.insert(pid, frozen);
                    frozen_pids.push(pid);
                    added = true;
                }
            }

            if !added {
                break;
            }
        }

        Ok(frozen_pids)
    }

    /// Shutdown helper: leave NO process stuck in SIGSTOP, and NEVER release an
    /// unauthorized pending effect.
    ///
    /// The BPF programs detach when the daemon exits, after which the LSM hooks
    /// no longer fire. Any process we already SIGSTOP'd would otherwise remain
    /// stopped forever as an orphaned, wedged task. We resolve this WITHOUT
    /// letting speculative or unauthorized side effects leak:
    ///
    ///   1. For every active speculative epoch, abandon the speculation the way
    ///      a reject would: discard the disposable candidate (and its epoch
    ///      descendants) and resume the pristine baseline as canonical. This is
    ///      the safe direction -- the baseline never ran the epoch's commands.
    ///   2. For every REMAINING plain frozen process (a non-versioned process
    ///      caught at an external effect that was never authorized): SIGKILL it.
    ///      Its pending syscall was blocked and is being auto-restarted on
    ///      SIGCONT -- so resuming it would let the unauthorized effect ESCAPE
    ///      once the hooks are gone. Killing discards the in-flight unauthorized
    ///      work (the effect never happened) and leaves no wedged task.
    ///
    /// Returns the number of processes handled (baselines resumed + frozen killed).
    pub fn release_all(&mut self) -> usize {
        let mut handled = 0;

        // 1. Abandon in-flight speculation: resume baselines, discard candidates.
        for b in self.memory_tracker.tracked_pids() {
            if self.reject_to_checkpoint(b).is_ok() {
                handled += 1;
            }
        }

        // 2. Kill every remaining frozen process: its pending external effect
        //    was never authorized, so it must NOT be resumed after the hooks
        //    detach. Clear its stopped mark first (best-effort) so nothing is
        //    left dangling in the maps, then SIGKILL.
        let pids: Vec<u32> = self.frozen.keys().copied().collect();
        for pid in pids {
            let _ = self.bpf_manager.clear_stopped_mark(pid);
            if signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL).is_ok() {
                handled += 1;
            }
            self.frozen.remove(&pid);
            self.promoted.retain(|_, v| v.canonical != pid);
        }

        handled
    }

    /// Drop bookkeeping for processes that have exited on their own.
    ///
    /// The eBPF `sched_process_exit` hook cleans the kernel-side maps, but the
    /// user-side `frozen` / `epochs` / `promoted` tables have no exit callback,
    /// so a process that crashes or is killed externally would otherwise leave
    /// a stale entry forever (shown by `list`, operated on by mistake, and — on
    /// pid reuse — able to misdirect a promotion). Called periodically from the
    /// main loop to keep those tables consistent.
    pub fn reap_dead(&mut self) {
        // 1. Drop frozen records whose process has exited.
        let dead: Vec<u32> = self
            .frozen
            .keys()
            .copied()
            .filter(|&p| !pid_is_alive(p))
            .collect();
        for p in &dead {
            self.frozen.remove(p);
        }

        // 2. Drop promotion mappings that can never legitimately fire again:
        //    the canonical target has exited or been reused (pid recycled), or
        //    the key pid is alive but reused by a different process. This bounds
        //    the map's growth and removes stale redirections.
        self.promoted.retain(|&key, promo| {
            match process_starttime(promo.canonical) {
                Some(st) if st == promo.canonical_start => {}
                _ => return false, // canonical dead or reused -> stale
            }
            if let Some(kst) = process_starttime(key) {
                if kst != promo.key_start {
                    return false; // key pid reused -> stale
                }
            }
            true
        });

        // 3. Tear down fully-dead epochs and clean their bookkeeping.
        let gone = self.memory_tracker.reap_dead();
        for b in gone {
            self.frozen.remove(&b);
            self.promoted.retain(|k, _| *k != b);
        }

        if !dead.is_empty() {
            eprintln!(
                "[reap] dropped {} exited frozen process(es): {:?}",
                dead.len(),
                dead
            );
        }
    }
}

/// Read the cgroup path for a given pid from /proc/<pid>/cgroup
fn read_process_cgroup(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/cgroup", pid);
    let data = fs::read_to_string(&path).ok()?;
    for line in data.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        // Prefer cgroup v2 (hierarchy-ID == "0", controller == "")
        if parts[0] == "0" && parts[1].is_empty() && !parts[2].is_empty() {
            return Some(parts[2].to_string());
        }
    }
    // Fallback to first non-root cgroup v1 entry
    for line in data.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 && !parts[2].is_empty() && parts[2] != "/" {
            return Some(parts[2].to_string());
        }
    }
    None
}

/// Returns false if `pid` has no /proc entry or its task is a zombie/dead. Used
/// to garbage-collect stale bookkeeping for processes that exited on their own.
fn pid_is_alive(pid: u32) -> bool {
    let stat = match fs::read_to_string(format!("/proc/{}/stat", pid)) {
        Ok(s) => s,
        Err(_) => return false, // no /proc entry -> gone
    };
    // /proc/<pid>/stat: "pid (comm) state ...". comm may contain spaces and
    // parens, so find the LAST ')' — the state char is the first non-space
    // token after it.
    match stat.rfind(')') {
        Some(idx) => {
            let state = stat[idx + 1..].trim_start().chars().next();
            !matches!(state, Some('Z') | Some('X') | Some('x'))
        }
        None => true, // unparseable but present: assume alive
    }
}

/// Read a process's start time (jiffies since boot; /proc/<pid>/stat field 22).
/// Combined with the pid this forms a stable process identity that survives pid
/// reuse: a recycled pid gets a fresh (larger) starttime. Returns None if the
/// process is gone or stat can't be parsed.
fn process_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Fields after the ")": state is field 3, ... starttime is field 22, i.e.
    // index 19 in the whitespace-split remainder (comm may contain spaces and
    // parens, so we anchor on the LAST ')').
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// Poll /proc/<pid>/stat until the task reaches a stopped state ('T' or 't'),
/// up to `timeout_ms`. Returns true if it stopped, false on timeout / gone.
/// Best-effort helper for freeze_pid: gives a SIGSTOP time to land before the
/// ptrace injection runs.
fn wait_task_stopped(pid: u32, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        let stat = match fs::read_to_string(format!("/proc/{}/stat", pid)) {
            Ok(s) => s,
            Err(_) => return false, // gone
        };
        if let Some(idx) = stat.rfind(')') {
            let state = stat[idx + 1..].trim_start().chars().next();
            if matches!(state, Some('T') | Some('t')) {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
