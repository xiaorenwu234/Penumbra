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
}

impl ProcessManager {
    pub fn new(checkpoint_dir: PathBuf, bpf_manager: Arc<BpfManager>) -> Self {
        std::fs::create_dir_all(&checkpoint_dir).ok();
        ProcessManager {
            frozen: HashMap::new(),
            checkpoint_dir,
            next_checkpoint_id: 0,
            bpf_manager,
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
