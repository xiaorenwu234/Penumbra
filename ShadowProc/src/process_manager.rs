use anyhow::{Context, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::fs;

use crate::bpf_loader::BpfManager;
use crate::event_handler::InterceptEvent;
use crate::memory_tracker::MemoryTracker;

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

#[allow(dead_code)]
/// Manages frozen processes - checkpoint, restore, continue, discard
pub struct ProcessManager {
    frozen: HashMap<u32, FrozenProcess>,
    checkpoint_dir: PathBuf,
    next_checkpoint_id: u32,
    bpf_manager: Arc<BpfManager>,
    memory_tracker: MemoryTracker,
    /// Maps an old (rejected, now-dead) pid to the canonical pid its checkpoint
    /// was promoted to by reject_to_checkpoint(). Lets callers still holding a
    /// stale pid transparently address the live process.
    promoted: HashMap<u32, u32>,
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

    /// Continue a frozen process:
    /// 1. Clear stopped_pids map entry (so hook will allow the restarted syscall)
    /// 2. Send SIGCONT (kernel auto-restarts the syscall via -ERESTARTSYS)
    pub fn continue_process(&mut self, pid: u32) -> Result<()> {
        let pid = self.resolve_pid(pid);
        if !self.frozen.contains_key(&pid) {
            anyhow::bail!("Process {} is not in frozen list", pid);
        }

        // MUST clear the map entry BEFORE sending SIGCONT
        // Otherwise the restarted syscall will be intercepted again
        self.bpf_manager.clear_stopped(pid)?;

        signal::kill(Pid::from_raw(pid as i32), Signal::SIGCONT)
            .with_context(|| format!("Failed to send SIGCONT to pid {}", pid))?;

        self.frozen.remove(&pid);
        Ok(())
    }

    /// Resume a frozen process for speculative execution:
    /// Temporarily allows the process to pass, then re-enables interception.
    /// This allows the process to be intercepted AGAIN on future syscalls (e.g., connect).
    pub fn resume_process(&mut self, pid: u32) -> Result<()> {
        let pid = self.resolve_pid(pid);
        if !self.frozen.contains_key(&pid) {
            anyhow::bail!("Process {} is not in frozen list", pid);
        }

        // Use clear_stopped_only which temporarily allows, then re-enables
        self.bpf_manager.clear_stopped_only(pid)?;

        signal::kill(Pid::from_raw(pid as i32), Signal::SIGCONT)
            .with_context(|| format!("Failed to send SIGCONT to pid {}", pid))?;

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
        self.promoted.retain(|_, v| *v != pid);
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

    /// Continue all frozen processes in a given cgroup
    pub fn continue_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut resumed = Vec::new();
        for pid in pids {
            if self.continue_process(pid).is_ok() {
                resumed.push(pid);
            }
        }
        Ok(resumed)
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

    /// Begin a versioning epoch for a frozen process.
    /// The process must be in SIGSTOP state at the snapshot boundary.
    ///
    /// The ORIGINAL becomes the frozen pristine baseline; a COW candidate is
    /// forked to run the epoch speculatively. Subsequent resume/commit/rollback
    /// on the caller's pid are transparently redirected to the candidate.
    pub fn begin_speculative(&mut self, pid: u32) -> Result<u32> {
        let pid = self.resolve_pid(pid);
        let candidate = self.memory_tracker.begin_tracking(pid)?;
        // The live/canonical handle for this epoch is the candidate; redirect
        // the caller's (baseline) pid to it and register it as resumable.
        self.register_candidate(pid, candidate);
        Ok(candidate)
    }

    /// Redirect a baseline pid to its speculative candidate AND register the
    /// candidate as a resumable frozen process. The candidate (the COW fork) is
    /// the process that actually runs the epoch, so resume_pid / continue_pid /
    /// cgroup operations must be able to act on it. It inherits the baseline's
    /// frozen record (same cgroup) with the candidate pid/tgid substituted.
    fn register_candidate(&mut self, baseline: u32, candidate: u32) {
        self.promoted.insert(baseline, candidate);
        if let Some(fp) = self.frozen.get(&baseline).cloned() {
            let mut c = fp;
            c.pid = candidate;
            c.tgid = candidate;
            self.frozen.insert(candidate, c);
        }
    }

    /// Begin a versioning epoch for all frozen processes in a cgroup.
    pub fn begin_speculative_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut tracked = Vec::new();
        for pid in pids {
            if let Ok(candidate) = self.memory_tracker.begin_tracking(pid) {
                // Redirect the baseline pid to its speculative candidate and
                // register the candidate as resumable.
                self.register_candidate(pid, candidate);
                tracked.push(pid);
            }
        }
        Ok(tracked)
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
        // memory_tracker::reject_to_checkpoint and left group-stopped. Clear its
        // eBPF stopped mark and SIGCONT it so it re-executes that syscall and
        // continues as the canonical process, re-guarded on future boundaries.
        let _ = self.bpf_manager.clear_stopped_only(baseline);
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
        let data = match fs::read_to_string(&cgroup_dir) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        let mut killed = Vec::new();
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
            // pristine versioning baseline.
            if cpid == keep || self.memory_tracker.is_shadow_pid(cpid) {
                continue;
            }
            if signal::kill(Pid::from_raw(cpid as i32), Signal::SIGKILL).is_ok() {
                self.frozen.remove(&cpid);
                self.promoted.retain(|_, v| *v != cpid);
                killed.push(cpid);
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
        while let Some(&next) = self.promoted.get(&cur) {
            cur = next;
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
        self.promoted.values().any(|&v| v == pid)
    }

    /// Commit a speculative epoch: accept the candidate as canonical and
    /// discard the pristine baseline. The candidate keeps running; the caller's
    /// pid stays redirected to it.
    pub fn commit_process(&mut self, pid: u32) -> Result<()> {
        let live = self.resolve_pid(pid);
        // commit() kills the baseline and keeps the candidate live; it returns
        // the discarded baseline pid.
        let baseline = self.memory_tracker.commit(live)?;
        // The baseline is gone; drop its frozen record and stale eBPF state. The
        // candidate stays as-is (still frozen at its boundary, resumable via
        // continue_pid). The promotion baseline -> candidate is kept so any
        // lingering reference to the old pid resolves to the canonical candidate.
        let _ = self.bpf_manager.clear_stopped(baseline);
        self.frozen.remove(&baseline);
        Ok(())
    }

    /// Commit all tracked processes in a cgroup.
    pub fn commit_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut committed = Vec::new();
        for pid in pids {
            if self.memory_tracker.is_tracking(pid) {
                if self.commit_process(pid).is_ok() {
                    committed.push(pid);
                }
            }
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

        let data = fs::read_to_string(&cgroup_dir)
            .with_context(|| format!("Failed to read cgroup.procs: {}", cgroup_dir))?;

        let mut frozen_pids = Vec::new();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let pid: u32 = match line.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Skip if already frozen
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
            }
        }

        Ok(frozen_pids)
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
