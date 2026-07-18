//! COW (Copy-on-Write) Process-Versioning Tracker for ShadowProc
//!
//! Implements memory rollback via PROCESS VERSIONING on top of the kernel's
//! native COW mechanism:
//! 1. Inject clone() via ptrace into the target process → creates a coherent
//!    "shadow" checkpoint that shares physical pages with the parent (COW).
//! 2. The shadow is frozen (SIGSTOP) with the target's registers at the snapshot
//!    instant, so its memory + registers describe one coherent moment.
//! 3. On reject: discard the live (speculative) process and RESUME the shadow
//!    checkpoint as the new canonical process.
//! 4. On commit: discard the shadow checkpoint (accept all memory changes).

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};

/// State for a single tracked process
struct ShadowState {
    target_pid: u32,
    shadow_pid: u32,
}

impl Drop for ShadowState {
    fn drop(&mut self) {
        // Kill shadow child if still alive
        let _ = nix::sys::signal::kill(Pid::from_raw(self.shadow_pid as i32), Signal::SIGKILL);
        // Wait to reap zombie
        let _ = waitpid(Pid::from_raw(self.shadow_pid as i32), Some(WaitPidFlag::WNOHANG));
    }
}

/// COW Memory Tracker - manages shadow processes for memory rollback
pub struct MemoryTracker {
    shadows: HashMap<u32, ShadowState>,
    /// If true, auto-track new child processes when fork events arrive
    auto_track_enabled: bool,
}

impl MemoryTracker {
    pub fn new() -> Self {
        MemoryTracker {
            shadows: HashMap::new(),
            auto_track_enabled: false,
        }
    }

    /// Enable or disable auto-tracking of child processes.
    /// When enabled, fork events from eBPF will trigger automatic begin_tracking
    /// on the new child process.
    pub fn set_auto_track(&mut self, enabled: bool) {
        self.auto_track_enabled = enabled;
        eprintln!("[cow] Auto-track child processes: {}", if enabled { "enabled" } else { "disabled" });
    }

    /// Check if auto-tracking is enabled
    pub fn is_auto_track_enabled(&self) -> bool {
        self.auto_track_enabled
    }

    /// Handle a fork event: if the parent is being tracked, also track the child.
    /// The child process must be briefly stopped (SIGSTOP) for fork injection.
    /// Returns Ok(true) if tracking was initiated, Ok(false) if skipped.
    pub fn handle_fork_event(&mut self, parent_tgid: u32, child_tgid: u32) -> Result<bool> {
        if !self.auto_track_enabled {
            return Ok(false);
        }

        // Only auto-track if the parent is being tracked
        if !self.shadows.contains_key(&parent_tgid) {
            return Ok(false);
        }

        // Don't double-track
        if self.shadows.contains_key(&child_tgid) {
            return Ok(false);
        }

        // CRITICAL: Don't track shadow children created by our own fork injection!
        // Without this check, inject_fork_via_ptrace creates a shadow child which
        // triggers sched_process_fork, which calls handle_fork_event again,
        // causing infinite recursion.
        for state in self.shadows.values() {
            if state.shadow_pid == child_tgid {
                eprintln!(
                    "[cow] Skipping fork event: child {} is a shadow process (of pid {})",
                    child_tgid, state.target_pid
                );
                return Ok(false);
            }
        }

        // The child was just forked - we need to SIGSTOP it, then begin tracking
        // Send SIGSTOP to the child so we can ptrace it
        nix::sys::signal::kill(Pid::from_raw(child_tgid as i32), Signal::SIGSTOP)
            .with_context(|| format!("Failed to SIGSTOP child {} for COW tracking", child_tgid))?;

        // Give the child a moment to actually stop
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Begin tracking the child
        match self.begin_tracking(child_tgid) {
            Ok(()) => {
                eprintln!(
                    "[cow] Auto-tracked child pid {} (parent {})",
                    child_tgid, parent_tgid
                );
                // Resume the child after tracking is set up
                let _ = nix::sys::signal::kill(Pid::from_raw(child_tgid as i32), Signal::SIGCONT);
                Ok(true)
            }
            Err(e) => {
                eprintln!(
                    "[cow] Failed to auto-track child pid {}: {}",
                    child_tgid, e
                );
                // Resume the child even if tracking failed
                let _ = nix::sys::signal::kill(Pid::from_raw(child_tgid as i32), Signal::SIGCONT);
                Err(e)
            }
        }
    }

    /// Begin COW tracking for a process.
    /// The process MUST be in SIGSTOP state (already frozen by eBPF).
    ///
    /// This will:
    /// 1. Attach via ptrace
    /// 2. Inject a clone() syscall to create a coherent shadow checkpoint
    /// 3. Freeze the shadow permanently (with the target's snapshot registers)
    /// 4. Detach from the parent
    pub fn begin_tracking(&mut self, pid: u32) -> Result<()> {
        if self.shadows.contains_key(&pid) {
            anyhow::bail!("Process {} is already being tracked for COW", pid);
        }

        // Inject fork via ptrace to create the shadow checkpoint. The shadow
        // shares the parent's pages copy-on-write and is frozen with the
        // target's snapshot registers (see inject_fork_via_ptrace).
        let shadow_pid = inject_fork_via_ptrace(pid)
            .with_context(|| format!("Failed to inject fork into pid {}", pid))?;

        eprintln!("[cow] Started tracking pid {} -> shadow pid {}", pid, shadow_pid);

        self.shadows.insert(
            pid,
            ShadowState {
                target_pid: pid,
                shadow_pid,
            },
        );

        Ok(())
    }

    /// Commit: discard the shadow process (accept all memory changes).
    pub fn commit(&mut self, pid: u32) -> Result<()> {
        if self.shadows.remove(&pid).is_none() {
            anyhow::bail!("Process {} is not being COW-tracked", pid);
        }
        eprintln!("[cow] Committed pid {} - shadow discarded", pid);
        Ok(())
    }

    /// Reject the speculative version and roll back via PROCESS VERSIONING.
    ///
    /// Instead of splicing the checkpoint's memory pages onto the live process
    /// (restore_memory), which fails whenever the snapshot boundary and the
    /// rollback boundary differ (the live registers/stack reference heap/arena
    /// state that the page-restore reverts → dangling pointers → libc segfault),
    /// this discards the speculative process `pid` entirely and RESUMES its
    /// pristine checkpoint (the shadow) as the new canonical process.
    ///
    /// The shadow is a full fork-checkpoint whose registers, stack, heap, TLS
    /// and userspace runtime state all belong to a single coherent instant, so
    /// resuming it can never produce a T0/T1 mismatch. Returns the promoted
    /// (shadow) pid, which becomes the live canonical pid.
    pub fn reject_to_checkpoint(&mut self, pid: u32) -> Result<u32> {
        let state = self
            .shadows
            .remove(&pid)
            .ok_or_else(|| anyhow::anyhow!("Process {} is not being COW-tracked", pid))?;
        let shadow_pid = state.shadow_pid;
        // We are PROMOTING the shadow, so its ShadowState::Drop (which SIGKILLs
        // the shadow) must NOT run. Skip Drop via forget.
        std::mem::forget(state);

        // Discard the speculative (live) process and reap it.
        let _ = nix::sys::signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        let _ = waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG));

        // Promote the checkpoint: resume the shadow as the canonical process.
        // It was left SIGSTOP'd at begin_tracking with coherent registers, so a
        // plain SIGCONT continues it exactly from the snapshot instant.
        nix::sys::signal::kill(Pid::from_raw(shadow_pid as i32), Signal::SIGCONT)
            .with_context(|| format!("Failed to resume checkpoint (shadow) pid {}", shadow_pid))?;

        eprintln!(
            "[cow] Reject pid {}: killed speculative version, resumed checkpoint (shadow) pid {} as canonical",
            pid, shadow_pid
        );
        Ok(shadow_pid)
    }

    /// Check if a process is currently being COW-tracked
    pub fn is_tracking(&self, pid: u32) -> bool {
        self.shadows.contains_key(&pid)
    }

    /// Check if a pid is a COW shadow process (an internal artifact created by
    /// fork injection). Shadow processes happen to live inside the monitored
    /// cgroup, but must NEVER be frozen/killed by cgroup-level operations:
    /// they are ptrace-managed snapshots holding pristine memory for rollback.
    pub fn is_shadow_pid(&self, pid: u32) -> bool {
        self.shadows.values().any(|s| s.shadow_pid == pid)
    }

    /// Get all tracked PIDs
    pub fn tracked_pids(&self) -> Vec<u32> {
        self.shadows.keys().copied().collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════

/// Inject a fork() system call into the target process via ptrace.
///
/// The target process must be in a stopped state (SIGSTOP).
/// Returns the PID of the newly created shadow child (also stopped).
///
/// Uses PTRACE_O_TRACEFORK + PTRACE_CONT for reliable syscall injection
/// (PTRACE_SINGLESTEP is unreliable across `syscall` instructions on some kernels).
fn inject_fork_via_ptrace(pid: u32) -> Result<u32> {
    let target = Pid::from_raw(pid as i32);

    // 1. SEIZE the target WITHOUT injecting a SIGSTOP.
    //
    //    The target is already group-stopped (SIGSTOP from freeze_by_cgroup).
    //    The old code used ptrace::attach here, which sends a SECOND SIGSTOP on
    //    top of the freeze one — the two stop signals then race during injection
    //    ("Unexpected signal SIGSTOP during fork injection"), and a signal-aware
    //    process such as a shell would intermittently exit when resumed.
    //    PTRACE_SEIZE attaches with no injected stop signal, killing that race at
    //    the root. We arm fork/clone/vfork tracing at seize time.
    ptrace::seize(
        target,
        ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEVFORK,
    )
    .with_context(|| format!("ptrace seize {} failed", pid))?;

    // 1b. SEIZE does not create a ptrace-stop, so explicitly interrupt the
    //     (group-stopped) target to obtain a ptrace-stop we can operate on.
    //     PTRACE_INTERRUPT injects no signal either.
    ptrace::interrupt(target)
        .with_context(|| format!("ptrace interrupt {} failed", pid))?;

    match waitpid(target, None) {
        // Under SEIZE, the interrupt/group-stop is reported as an event stop.
        Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::Stopped(_, _)) => {}
        Ok(status) => {
            ptrace::detach(target, None).ok();
            anyhow::bail!("Unexpected wait status after seize/interrupt: {:?}", status);
        }
        Err(e) => {
            ptrace::detach(target, None).ok();
            anyhow::bail!("waitpid after seize/interrupt failed: {}", e);
        }
    }

    // 2. Get current registers
    let orig_regs = ptrace::getregs(target)
        .context("Failed to get registers")?;

    // 3. Find a syscall instruction in the process's memory
    let syscall_addr = find_syscall_instruction(pid, &orig_regs)?;
    eprintln!("[cow] Found syscall instruction at 0x{:x} for pid {}", syscall_addr, pid);

    // 4. Set up registers for clone(0, 0, 0, 0, 0) → a fork-like COW child with
    //    NO exit signal.
    //
    //    We deliberately pass exit_signal = 0 (NOT SIGCHLD). Without CLONE_VM the
    //    child still receives a full copy-on-write snapshot of the parent's
    //    address space (exactly what we need), and child_stack = NULL makes it
    //    resume on the parent's (COW) stack — i.e. identical memory semantics to
    //    fork(). The only difference from fork() is that the child sends NO
    //    signal to the parent when it stops or exits.
    //
    //    This is critical for tracking real, signal-aware processes such as a
    //    shell: with SIGCHLD as the exit signal, the shadow child appears as a
    //    mysterious child of the target, and the target's SIGCHLD handler / job
    //    control would waitpid() it and race with our inject/resume sequence,
    //    intermittently crashing the target. exit_signal = 0 makes the shadow
    //    completely invisible to the target's signal handling.
    let mut new_regs = orig_regs;
    new_regs.rip = syscall_addr;
    new_regs.rax = libc::SYS_clone as u64;  // __NR_clone = 56
    new_regs.rdi = 0;                        // flags = 0 (no CLONE_VM → COW; no exit_signal)
    new_regs.rsi = 0;                        // child_stack = NULL (use parent's stack)
    new_regs.rdx = 0;                        // parent_tidptr = NULL
    new_regs.r10 = 0;                        // child_tidptr = NULL
    new_regs.r8 = 0;                         // tls = NULL

    // 5. (Fork/clone/vfork trace options were already armed at PTRACE_SEIZE time.)
    ptrace::setregs(target, new_regs)
        .context("Failed to set registers for fork injection")?;

    // 6. Continue execution — process will execute the clone() syscall.
    //    With PTRACE_O_TRACECLONE/FORK, the kernel will stop the parent with
    //    a PTRACE_EVENT before it resumes after clone.
    ptrace::cont(target, None)
        .context("Failed to continue for fork injection")?;

    // 7. Wait for the fork/clone ptrace event
    let child_pid: u32 = loop {
        match waitpid(target, None) {
            Ok(WaitStatus::PtraceEvent(_, _, event)) => {
                // Under PTRACE_SEIZE a group-stop is reported as PTRACE_EVENT_STOP;
                // only FORK/VFORK/CLONE carry the new child pid via GETEVENTMSG.
                if event == libc::PTRACE_EVENT_FORK
                    || event == libc::PTRACE_EVENT_VFORK
                    || event == libc::PTRACE_EVENT_CLONE
                {
                    let child = ptrace::getevent(target)
                        .context("Failed to get event data (child pid)")?;
                    eprintln!(
                        "[cow] Got ptrace event {} (fork/clone/vfork), child pid = {}",
                        event, child
                    );
                    break child as u32;
                }
                // Any other event stop (e.g. group-stop): resume and keep waiting.
                eprintln!("[cow] Ignoring ptrace event {} during injection, continuing", event);
                ptrace::cont(target, None)
                    .context("Failed to continue after non-fork ptrace event")?;
            }
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
                // Could be syscall-stop without TRACESYSGOOD; just continue
                ptrace::cont(target, None)
                    .context("Failed to continue after SIGTRAP")?;
            }
            Ok(WaitStatus::Stopped(_, Signal::SIGCHLD)) => {
                // SIGCHLD from the fork itself; suppress and continue
                ptrace::cont(target, None)
                    .context("Failed to continue after SIGCHLD")?;
            }
            Ok(WaitStatus::Stopped(_, sig)) => {
                eprintln!("[cow] Unexpected signal {:?} during fork injection, suppressing", sig);
                ptrace::cont(target, None)
                    .context("Failed to continue after unexpected signal")?;
            }
            Ok(status) => {
                ptrace::setregs(target, orig_regs).ok();
                ptrace::detach(target, None).ok();
                anyhow::bail!(
                    "Unexpected wait status during fork injection: {:?}",
                    status
                );
            }
            Err(e) => {
                ptrace::setregs(target, orig_regs).ok();
                ptrace::detach(target, None).ok();
                anyhow::bail!("waitpid failed during fork injection: {}", e);
            }
        }
    };

    // 8. The child is auto-traced (PTRACE_O_TRACECLONE/FORK auto-attaches the child).
    //    Wait for the child's initial ptrace-stop, then detach it with SIGSTOP.
    match waitpid(Pid::from_raw(child_pid as i32), Some(WaitPidFlag::__WALL)) {
        Ok(WaitStatus::Stopped(_, _)) | Ok(WaitStatus::PtraceEvent(_, _, _)) => {}
        _ => {
            // Try a blocking wait if WNOHANG didn't catch it
            std::thread::sleep(std::time::Duration::from_millis(5));
            let _ = waitpid(
                Pid::from_raw(child_pid as i32),
                Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG),
            );
        }
    }

    // Send SIGSTOP and detach the child so it stays permanently frozen
    //
    // Before freezing it, promote it from a passive "memory donor" into a
    // fully COHERENT, RESUMABLE checkpoint by giving it the target's register
    // state at the snapshot instant (orig_regs). Left untouched, the shadow's
    // registers point at the injected clone site (rip = syscall_addr+2, rax = 0)
    // — fine for reading its memory, but garbage to actually run. With orig_regs
    // the shadow's MEMORY (a COW copy taken at the clone) and its REGISTERS
    // describe the SAME coherent moment, so it can later be SIGCONT'd to run as
    // the canonical process (process-versioning rollback: kill the speculative
    // version, resume this checkpoint) with no T0/T1 memory/register splicing.
    let _ = ptrace::setregs(Pid::from_raw(child_pid as i32), orig_regs);

    let _ = nix::sys::signal::kill(Pid::from_raw(child_pid as i32), Signal::SIGSTOP);
    ptrace::detach(Pid::from_raw(child_pid as i32), Some(Signal::SIGSTOP))
        .unwrap_or_else(|e| {
            eprintln!("[cow] Warning: detach from shadow child {} failed: {}", child_pid, e);
        });

    // 9. Restore original registers. The target was group-stopped inside its
    //    original (restartable) syscall, so orig_regs already carries the
    //    kernel's restart state (rax = -ERESTARTSYS with rip just past the
    //    `syscall` instruction). On resume the kernel's own signal-return path
    //    rewinds rip and reloads the syscall number, transparently restarting
    //    the interrupted syscall — so a plain restore is correct here. (A manual
    //    re-arm was tried and is exactly equivalent to this kernel behaviour; it
    //    did not affect the residual injection race, so it was removed to keep
    //    the resume path minimal.)
    ptrace::setregs(target, orig_regs)
        .context("Failed to restore original registers")?;

    // 10. Detach from parent (let it remain in SIGSTOP from eBPF)
    ptrace::detach(target, Some(Signal::SIGSTOP))
        .with_context(|| format!("Failed to detach from pid {}", pid))?;

    eprintln!("[cow] Injected fork: pid {} → shadow child {}", pid, child_pid);

    Ok(child_pid)
}

/// Find a `syscall` instruction (bytes 0x0f 0x05) accessible to the target process.
/// Strategy: look in vDSO or near current RIP.
fn find_syscall_instruction(pid: u32, regs: &libc::user_regs_struct) -> Result<u64> {
    // Strategy 1: Check if current RIP-2 is a syscall instruction
    // (process might be stopped right after a syscall)
    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = OpenOptions::new()
        .read(true)
        .open(&mem_path)
        .with_context(|| format!("Failed to open {}", mem_path))?;

    // Check RIP-2 (if process was stopped after a syscall)
    if regs.rip >= 2 {
        let mut buf = [0u8; 2];
        if mem_file.seek(SeekFrom::Start(regs.rip - 2)).is_ok() {
            if mem_file.read_exact(&mut buf).is_ok() && buf == [0x0f, 0x05] {
                return Ok(regs.rip - 2);
            }
        }
    }

    // Strategy 2: Scan the vDSO for a syscall instruction
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = fs::read_to_string(&maps_path)?;
    for line in maps.lines() {
        if line.contains("[vdso]") {
            let addr_parts: Vec<&str> = line.split_whitespace().next()
                .unwrap_or("")
                .split('-')
                .collect();
            if addr_parts.len() == 2 {
                let start = u64::from_str_radix(addr_parts[0], 16).unwrap_or(0);
                let end = u64::from_str_radix(addr_parts[1], 16).unwrap_or(0);
                // Scan vDSO for syscall instruction
                let scan_size = std::cmp::min(end - start, 4096) as usize;
                let mut vdso_buf = vec![0u8; scan_size];
                if mem_file.seek(SeekFrom::Start(start)).is_ok() {
                    if mem_file.read_exact(&mut vdso_buf).is_ok() {
                        for i in 0..vdso_buf.len() - 1 {
                            if vdso_buf[i] == 0x0f && vdso_buf[i + 1] == 0x05 {
                                return Ok(start + i as u64);
                            }
                        }
                    }
                }
            }
        }
    }

    // Strategy 3: Look for syscall in any executable region
    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let perms = parts[1];
        if perms.len() >= 3 && perms.as_bytes()[2] == b'x' {
            let addr_parts: Vec<&str> = parts[0].split('-').collect();
            if addr_parts.len() == 2 {
                let start = u64::from_str_radix(addr_parts[0], 16).unwrap_or(0);
                let end = u64::from_str_radix(addr_parts[1], 16).unwrap_or(0);
                let scan_size = std::cmp::min(end - start, 8192) as usize;
                let mut buf = vec![0u8; scan_size];
                if mem_file.seek(SeekFrom::Start(start)).is_ok() {
                    if let Ok(n) = mem_file.read(&mut buf) {
                        for i in 0..n.saturating_sub(1) {
                            if buf[i] == 0x0f && buf[i + 1] == 0x05 {
                                return Ok(start + i as u64);
                            }
                        }
                    }
                }
            }
        }
    }

    anyhow::bail!("Could not find syscall instruction in pid {}", pid)
}
