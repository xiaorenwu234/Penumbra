//! Frozen-Baseline + Speculative-Clone versioning for ShadowProc
//!
//! Implements memory rollback by PROCESS VERSIONING on top of the kernel's
//! native COW mechanism, using the "Frozen Baseline + Speculative Clone" model:
//!
//! 1. At an epoch boundary the ORIGINAL process is already SIGSTOP-frozen.
//!    We inject clone() via ptrace to fork a coherent COW copy of it.
//! 2. We keep the ORIGINAL frozen as the pristine **baseline** (it never runs
//!    the epoch's command) and let the **candidate** (the fork) run
//!    speculatively. Both share physical pages copy-on-write, and both carry
//!    the same snapshot registers (orig_regs), so either is a coherent moment.
//! 3. On ROLLBACK: discard the candidate (and its epoch descendants, cleaned at
//!    the cgroup level by ProcessManager) and RESUME the pristine baseline — the
//!    original process, with its real pid / session / parent lineage intact,
//!    which never executed the command, so rollback is lossless by construction.
//! 4. On COMMIT: discard the baseline; the candidate becomes the new canonical
//!    process. The next epoch clones a fresh candidate from it.
//!
//! The clone is created with CLONE_PARENT so it is a SIBLING of the original
//! (its parent is the original's parent), not a child. This keeps the
//! original's job-control / SIGCHLD handling undisturbed, and — crucially —
//! means that when the baseline is killed on commit, the surviving candidate is
//! NOT reparented to init: it keeps proper lineage under the launcher/supervisor.
//!
//! NOTE: lossless rollback requires the caller to take the snapshot at a
//! pre-command boundary (e.g. the stdin read() boundary driven by a Session
//! Proxy). The mechanism here is boundary-agnostic; boundary selection is the
//! caller's responsibility.

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};

/// Linux clone() flag: make the new task a sibling of the caller (its parent is
/// the caller's parent) instead of a child of the caller.
const CLONE_PARENT: u64 = 0x0000_8000;

/// State for a single tracked epoch.
///
/// `baseline_pid` is the ORIGINAL process, kept frozen as the pristine rollback
/// target. `candidate_pid` is the COW fork that runs the epoch speculatively.
struct EpochState {
    baseline_pid: u32,
    candidate_pid: u32,
}

impl Drop for EpochState {
    fn drop(&mut self) {
        // Safety net for abnormal teardown: the candidate (the speculative
        // fork) is the disposable one — kill and reap it. The baseline is the
        // real, original process and is never touched here.
        let _ = nix::sys::signal::kill(Pid::from_raw(self.candidate_pid as i32), Signal::SIGKILL);
        let _ = waitpid(Pid::from_raw(self.candidate_pid as i32), Some(WaitPidFlag::WNOHANG));
    }
}

/// COW Memory Tracker - manages baseline/candidate epochs for memory rollback
pub struct MemoryTracker {
    /// Keyed by baseline_pid (the original pid the caller knows at begin time).
    epochs: HashMap<u32, EpochState>,
    /// If true, fork events from eBPF are considered for descendant handling.
    /// In the Frozen-Baseline model descendants are NOT individually versioned;
    /// they are cleaned as a unit via the epoch cgroup, so this only gates
    /// logging.
    auto_track_enabled: bool,
}

impl MemoryTracker {
    pub fn new() -> Self {
        MemoryTracker {
            epochs: HashMap::new(),
            auto_track_enabled: false,
        }
    }

    /// Enable or disable descendant fork awareness.
    pub fn set_auto_track(&mut self, enabled: bool) {
        self.auto_track_enabled = enabled;
        eprintln!("[cow] Descendant fork awareness: {}", if enabled { "enabled" } else { "disabled" });
    }

    /// Check if descendant fork awareness is enabled
    pub fn is_auto_track_enabled(&self) -> bool {
        self.auto_track_enabled
    }

    /// Handle a fork event from eBPF.
    ///
    /// In the Frozen-Baseline + Speculative-Clone model we do NOT create a
    /// per-descendant COW checkpoint: a candidate's children are born inside
    /// the epoch cgroup and are discarded as a unit on rollback (cgroup kill)
    /// or kept as a unit on commit. So this is now purely informational and
    /// never injects a fork into the child. Returns Ok(false) (nothing tracked).
    pub fn handle_fork_event(&mut self, parent_tgid: u32, child_tgid: u32) -> Result<bool> {
        if !self.auto_track_enabled {
            return Ok(false);
        }
        // Only note descendants of a process we are actually versioning.
        let parent_is_tracked = self
            .epochs
            .values()
            .any(|e| e.baseline_pid == parent_tgid || e.candidate_pid == parent_tgid);
        if parent_is_tracked {
            eprintln!(
                "[cow] Epoch descendant pid {} (of {}) noted; cgroup-scoped cleanup applies (no per-child checkpoint)",
                child_tgid, parent_tgid
            );
        }
        Ok(false)
    }

    /// Begin a versioning epoch for a process.
    /// The process MUST be in SIGSTOP state (already frozen at the snapshot
    /// boundary).
    ///
    /// This will:
    /// 1. Attach via ptrace
    /// 2. Inject clone(CLONE_PARENT) to create a coherent COW sibling
    /// 3. Freeze both with the snapshot registers
    /// 4. Keep the ORIGINAL as the pristine baseline; return the CANDIDATE
    ///    (the fork) as the process that should run the epoch speculatively.
    pub fn begin_tracking(&mut self, pid: u32) -> Result<u32> {
        if let Some(e) = self.epochs.get(&pid) {
            anyhow::bail!(
                "Process {} already has an active epoch (candidate {})",
                pid, e.candidate_pid
            );
        }

        // Inject a clone via ptrace to create the candidate. It shares the
        // original's pages copy-on-write and is frozen with the snapshot
        // registers (see inject_fork_via_ptrace). With CLONE_PARENT it is a
        // sibling of the original, not a child.
        let candidate_pid = inject_fork_via_ptrace(pid)
            .with_context(|| format!("Failed to inject clone into pid {}", pid))?;

        eprintln!(
            "[cow] Epoch started: baseline (frozen) pid {} -> candidate (runs) pid {}",
            pid, candidate_pid
        );

        self.epochs.insert(
            pid,
            EpochState {
                baseline_pid: pid,
                candidate_pid,
            },
        );

        Ok(candidate_pid)
    }

    /// Resolve any pid belonging to an epoch (baseline OR candidate) to its
    /// baseline key.
    fn find_key(&self, pid: u32) -> Option<u32> {
        if self.epochs.contains_key(&pid) {
            return Some(pid);
        }
        self.epochs
            .iter()
            .find(|(_, e)| e.candidate_pid == pid)
            .map(|(k, _)| *k)
    }

    /// Commit: accept the speculative candidate as canonical and discard the
    /// pristine baseline. Accepts either the baseline or candidate pid.
    pub fn commit(&mut self, pid: u32) -> Result<u32> {
        let key = self
            .find_key(pid)
            .ok_or_else(|| anyhow::anyhow!("Process {} is not part of a tracked epoch", pid))?;
        let state = self.epochs.remove(&key).unwrap();
        let baseline = state.baseline_pid;
        let candidate = state.candidate_pid;
        // The candidate must SURVIVE the commit, so suppress EpochState::Drop
        // (which would SIGKILL the candidate) and kill the baseline instead.
        std::mem::forget(state);

        let _ = nix::sys::signal::kill(Pid::from_raw(baseline as i32), Signal::SIGKILL);
        let _ = waitpid(Pid::from_raw(baseline as i32), Some(WaitPidFlag::WNOHANG));

        eprintln!(
            "[cow] Commit: discarded baseline pid {}; candidate pid {} is now canonical",
            baseline, candidate
        );
        // Return the discarded baseline pid so the caller can clean up its
        // bookkeeping (the candidate stays live and resumable).
        Ok(baseline)
    }

    /// Roll back the speculative epoch: discard the candidate and return the
    /// pristine baseline (the original process) so the caller can resume it.
    /// Accepts either the baseline or candidate pid.
    ///
    /// The baseline never executed the epoch's command; its registers, stack,
    /// heap, TLS and cwd are exactly as they were at the snapshot instant, so
    /// resuming it is lossless — with no memory/register splicing and no pid
    /// change (the original keeps its identity, session and parent lineage).
    ///
    /// The candidate's epoch descendants are cleaned separately at the cgroup
    /// level by ProcessManager. Returns the baseline pid.
    pub fn reject_to_checkpoint(&mut self, pid: u32) -> Result<u32> {
        let key = self
            .find_key(pid)
            .ok_or_else(|| anyhow::anyhow!("Process {} is not part of a tracked epoch", pid))?;
        let state = self.epochs.remove(&key).unwrap();
        let baseline = state.baseline_pid;
        let candidate = state.candidate_pid;
        // Kill the candidate explicitly; suppress Drop to avoid a redundant
        // second kill/reap of the same pid.
        std::mem::forget(state);

        let _ = nix::sys::signal::kill(Pid::from_raw(candidate as i32), Signal::SIGKILL);
        let _ = waitpid(Pid::from_raw(candidate as i32), Some(WaitPidFlag::WNOHANG));

        eprintln!(
            "[cow] Rollback: killed candidate pid {}; baseline pid {} restored as canonical",
            candidate, baseline
        );
        Ok(baseline)
    }

    /// Check if a process is part of an active epoch (as baseline or candidate).
    pub fn is_tracking(&self, pid: u32) -> bool {
        self.find_key(pid).is_some()
    }

    /// Check if a pid is a frozen BASELINE (the pristine, original copy held for
    /// rollback). Baselines live inside the monitored cgroup but must NEVER be
    /// frozen/killed by cgroup-level operations while an epoch is live: they are
    /// ptrace-snapshotted pristine copies. (The candidate, by contrast, is the
    /// live process that cgroup freeze/kill legitimately acts on.)
    pub fn is_shadow_pid(&self, pid: u32) -> bool {
        self.epochs.values().any(|e| e.baseline_pid == pid)
    }

    /// Get all baseline PIDs with an active epoch.
    pub fn tracked_pids(&self) -> Vec<u32> {
        self.epochs.keys().copied().collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════

/// Inject a clone() system call into the target process via ptrace to create a
/// coherent COW copy (the candidate).
///
/// The target process must be in a stopped state (SIGSTOP).
/// Returns the PID of the newly created candidate (also stopped).
///
/// Uses PTRACE_O_TRACEFORK/CLONE/VFORK + PTRACE_CONT for reliable syscall
/// injection (PTRACE_SINGLESTEP is unreliable across `syscall` instructions on
/// some kernels).
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

    // 4. Set up registers for clone(CLONE_PARENT, 0, 0, 0, 0) → a fork-like COW
    //    SIBLING with NO exit signal.
    //
    //    Raw x86-64 clone() arg order is clone(flags, stack, ptid, ctid, tls).
    //    Without CLONE_VM the child still receives a full copy-on-write snapshot
    //    of the parent's address space (exactly what we need), and
    //    child_stack = NULL makes it resume on the parent's (COW) stack — i.e.
    //    identical memory semantics to fork().
    //
    //    CLONE_PARENT makes the candidate a SIBLING of the original (its real
    //    parent is the original's parent), not a child. Two payoffs:
    //      - the original's SIGCHLD / job-control / wait() logic is never
    //        disturbed by the appearance of a mystery child, and
    //      - when the baseline (original) is killed on commit, the surviving
    //        candidate is NOT reparented to init — it keeps proper lineage
    //        under the launcher/supervisor.
    //    exit_signal is left 0 (low byte of flags) so the candidate sends no
    //    signal to that parent either; a real supervisor would instead use
    //    SIGCHLD + pidfd to reap it deterministically.
    let mut new_regs = orig_regs;
    new_regs.rip = syscall_addr;
    new_regs.rax = libc::SYS_clone as u64;   // __NR_clone = 56
    new_regs.rdi = CLONE_PARENT;             // flags = CLONE_PARENT (COW; exit_signal = 0)
    new_regs.rsi = 0;                        // child_stack = NULL (use parent's stack)
    new_regs.rdx = 0;                        // parent_tidptr = NULL
    new_regs.r10 = 0;                        // child_tidptr = NULL
    new_regs.r8 = 0;                         // tls = NULL

    // 5. (Fork/clone/vfork trace options were already armed at PTRACE_SEIZE time.)
    ptrace::setregs(target, new_regs)
        .context("Failed to set registers for clone injection")?;

    // 6. Continue execution — process will execute the clone() syscall.
    //    With PTRACE_O_TRACECLONE/FORK, the kernel will stop the parent with
    //    a PTRACE_EVENT before it resumes after clone.
    ptrace::cont(target, None)
        .context("Failed to continue for clone injection")?;

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
                        "[cow] Got ptrace event {} (fork/clone/vfork), candidate pid = {}",
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
                eprintln!("[cow] Unexpected signal {:?} during clone injection, suppressing", sig);
                ptrace::cont(target, None)
                    .context("Failed to continue after unexpected signal")?;
            }
            Ok(status) => {
                ptrace::setregs(target, orig_regs).ok();
                ptrace::detach(target, None).ok();
                anyhow::bail!(
                    "Unexpected wait status during clone injection: {:?}",
                    status
                );
            }
            Err(e) => {
                ptrace::setregs(target, orig_regs).ok();
                ptrace::detach(target, None).ok();
                anyhow::bail!("waitpid failed during clone injection: {}", e);
            }
        }
    };

    // 8. The candidate is auto-traced (PTRACE_O_TRACECLONE/FORK auto-attaches
    //    the child to the tracer). Wait for its initial ptrace-stop, then detach
    //    it with SIGSTOP.
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

    // Give the candidate the SAME snapshot registers as the original (orig_regs)
    // so that its MEMORY (a COW copy taken at the clone) and its REGISTERS
    // describe the SAME coherent moment. Then SIGSTOP + detach it so it stays
    // frozen and resumable: either it (the candidate) is SIGCONT'd to run the
    // epoch speculatively, or — on commit — it is promoted, or — on rollback —
    // it is discarded while the baseline is resumed instead.
    let _ = ptrace::setregs(Pid::from_raw(child_pid as i32), orig_regs);

    let _ = nix::sys::signal::kill(Pid::from_raw(child_pid as i32), Signal::SIGSTOP);
    ptrace::detach(Pid::from_raw(child_pid as i32), Some(Signal::SIGSTOP))
        .unwrap_or_else(|e| {
            eprintln!("[cow] Warning: detach from candidate {} failed: {}", child_pid, e);
        });

    // 9. Restore original registers. The target was group-stopped inside its
    //    original (restartable) syscall, so orig_regs already carries the
    //    kernel's restart state (rax = -ERESTARTSYS with rip just past the
    //    `syscall` instruction). On resume the kernel's own signal-return path
    //    rewinds rip and reloads the syscall number, transparently restarting
    //    the interrupted syscall — so a plain restore is correct here.
    ptrace::setregs(target, orig_regs)
        .context("Failed to restore original registers")?;

    // 10. Detach from the baseline (it remains SIGSTOP-frozen from eBPF). The
    //     baseline is the pristine rollback copy and stays frozen until the
    //     epoch is committed (baseline killed) or rolled back (baseline resumed).
    ptrace::detach(target, Some(Signal::SIGSTOP))
        .with_context(|| format!("Failed to detach from pid {}", pid))?;

    eprintln!("[cow] Injected clone: baseline pid {} → candidate {}", pid, child_pid);

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
