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
use crate::memory_tracker::{MemoryTracker, RollbackStats};

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
        if !self.frozen.contains_key(&pid) {
            anyhow::bail!("Process {} is not in frozen list", pid);
        }

        signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
            .with_context(|| format!("Failed to send SIGKILL to pid {}", pid))?;

        self.frozen.remove(&pid);
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

    /// Begin speculative COW tracking for a frozen process.
    /// The process must be in SIGSTOP state.
    pub fn begin_speculative(&mut self, pid: u32) -> Result<()> {
        self.memory_tracker.begin_tracking(pid)?;
        // Enable auto-tracking of child processes
        if !self.memory_tracker.is_auto_track_enabled() {
            self.memory_tracker.set_auto_track(true);
            // Enable eBPF fork event reporting
            self.bpf_manager.set_cow_enabled(true)?;
        }
        Ok(())
    }

    /// Begin speculative COW tracking for all frozen processes in a cgroup.
    pub fn begin_speculative_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<u32>> {
        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut tracked = Vec::new();
        for pid in pids {
            if self.memory_tracker.begin_tracking(pid).is_ok() {
                tracked.push(pid);
            }
        }
        // Enable auto-tracking if we tracked at least one process
        if !tracked.is_empty() && !self.memory_tracker.is_auto_track_enabled() {
            self.memory_tracker.set_auto_track(true);
            self.bpf_manager.set_cow_enabled(true)?;
        }
        Ok(tracked)
    }

    /// Rollback a single process's memory and kill it.
    /// Restores memory pages from the shadow process, then kills the target.
    pub fn rollback_process(&mut self, pid: u32) -> Result<RollbackStats> {
        let stats = self.memory_tracker.rollback(pid)?;
        // After restoring memory, kill the process
        let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        self.frozen.remove(&pid);
        Ok(stats)
    }

    /// Restore a process's memory only (no kill). Used for verification in demos.
    /// After calling this, the process is still frozen and can be inspected.
    pub fn restore_memory_only(&mut self, pid: u32) -> Result<RollbackStats> {
        self.memory_tracker.rollback(pid)
    }

    /// Rollback all tracked processes in a cgroup.
    /// Restores memory and kills each process.
    pub fn rollback_by_cgroup(&mut self, cgroup_path: &str) -> Result<Vec<(u32, RollbackStats)>> {
        let pids: Vec<u32> = self.frozen.values()
            .filter(|p| p.cgroup_path == cgroup_path)
            .map(|p| p.tgid)
            .collect();
        let mut results = Vec::new();
        for pid in pids {
            if self.memory_tracker.is_tracking(pid) {
                match self.memory_tracker.rollback(pid) {
                    Ok(stats) => {
                        let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
                        self.frozen.remove(&pid);
                        results.push((pid, stats));
                    }
                    Err(e) => {
                        eprintln!("[cow] Failed to rollback pid {}: {}", pid, e);
                    }
                }
            }
        }
        Ok(results)
    }

    /// Reject a speculative process via PROCESS VERSIONING: discard the live
    /// (speculative) process `pid` and resume its pristine checkpoint (the COW
    /// shadow) as the new canonical process. Returns the promoted (shadow) pid.
    ///
    /// This is the sound alternative to restore_memory_only for processes that
    /// were snapshotted at a different boundary than where they are rolled back:
    /// it never splices a stale memory image onto live registers, so it cannot
    /// crash the target. The promoted process keeps running from the exact
    /// coherent instant the checkpoint was taken.
    pub fn reject_to_checkpoint(&mut self, pid: u32) -> Result<u32> {
        let shadow_pid = self.memory_tracker.reject_to_checkpoint(pid)?;
        // The discarded speculative process is gone; drop its frozen record and
        // clear any stale eBPF stopped-state keyed on its (now dead) tgid.
        let _ = self.bpf_manager.clear_stopped(pid);
        self.frozen.remove(&pid);
        Ok(shadow_pid)
    }

    /// Commit speculative execution for a process (discard COW shadow).
    pub fn commit_process(&mut self, pid: u32) -> Result<()> {
        self.memory_tracker.commit(pid)
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
                if self.memory_tracker.commit(pid).is_ok() {
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

    /// Check if a pid is a COW shadow process (internal artifact). Such pids
    /// must be excluded from cgroup-level freeze/kill operations.
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

            // Skip COW shadow processes: they live in the cgroup only because
            // they were fork-injected from a tracked process, but they are
            // ptrace-managed snapshots. SIGSTOP'ing them corrupts the COW
            // rollback machinery, so they must never be frozen as siblings.
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
