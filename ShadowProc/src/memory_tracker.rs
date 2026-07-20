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
//!
//! PLATFORM: x86-64 only. The injected clone register layout, the `0f 05`
//! syscall-opcode check used to rewind a boundary, and the __NR_clone number
//! are all x86-64 specific (a compile_error! in main.rs enforces this).

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

/// Linux clone() flag: make the new task a sibling of the caller (its parent is
/// the caller's parent) instead of a child of the caller.
const CLONE_PARENT: u64 = 0x0000_8000;

/// Termination signal (low byte of clone flags) delivered to the candidate's
/// parent when the candidate dies. Setting it to SIGCHLD — rather than 0 — is
/// what lets the launcher reap a killed candidate with an ordinary waitpid():
/// with exit_signal == 0 the candidate is a "clone child", reapable only via a
/// __WALL/__WCLONE wait, a flavour most launchers (and Python's os.waitpid)
/// cannot express — so killed candidates leaked as permanent zombies.
const SIGCHLD: u64 = 17;

/// State for a single tracked epoch.
///
/// `baseline_pid` is the ORIGINAL process, kept frozen as the pristine rollback
/// target. `candidate_pid` is the COW fork that runs the epoch speculatively.
/// `orig_regs` are the snapshot registers captured at the boundary BEFORE the
/// clone was injected; they are needed to cleanly rewind the baseline back onto
/// its interrupted boundary syscall when the epoch is rejected (see
/// restore_baseline_for_restart).
struct EpochState {
    baseline_pid: u32,
    candidate_pid: u32,
    orig_regs: libc::user_regs_struct,
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
    /// Baseline pids with an in-flight epoch setup: reserved (phase 1) but not
    /// yet finalized because the slow ptrace injection (phase 2) is running with
    /// the ProcessManager lock RELEASED. Guards against a second concurrent
    /// begin (or duplicate clone injection) for the same pid during that window.
    reserving: HashSet<u32>,
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
            reserving: HashSet::new(),
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

    /// Phase 1 of a lock-free epoch setup: reserve `pid` so no other caller can
    /// start a second epoch (or a duplicate clone injection) for it while the
    /// slow ptrace injection runs with the ProcessManager lock released. Call
    /// while holding the lock. Fails if an epoch is already active or a
    /// reservation is already in flight for this pid.
    pub fn reserve(&mut self, pid: u32) -> Result<()> {
        if let Some(e) = self.epochs.get(&pid) {
            anyhow::bail!(
                "Process {} already has an active epoch (candidate {})",
                pid, e.candidate_pid
            );
        }
        if !self.reserving.insert(pid) {
            anyhow::bail!("Process {} already has an in-flight epoch setup", pid);
        }
        Ok(())
    }

    /// Phase 2 (run WITHOUT the ProcessManager lock): the slow ptrace clone
    /// injection. Touches no tracker state, so it is safe to run unlocked while
    /// other socket clients and the event loop keep making progress.
    pub fn inject(pid: u32) -> Result<(u32, libc::user_regs_struct)> {
        inject_fork_via_ptrace(pid)
            .with_context(|| format!("Failed to inject clone into pid {}", pid))
    }

    /// Phase 3a: finalize a reservation with the injected candidate. Under lock.
    pub fn finish_tracking(
        &mut self,
        pid: u32,
        candidate: u32,
        orig_regs: libc::user_regs_struct,
    ) {
        self.reserving.remove(&pid);
        self.epochs.insert(
            pid,
            EpochState {
                baseline_pid: pid,
                candidate_pid: candidate,
                orig_regs,
            },
        );
    }

    /// Phase 3b: cancel a reservation whose injection failed. Under lock.
    pub fn abort_reserve(&mut self, pid: u32) {
        self.reserving.remove(&pid);
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
        let orig_regs = state.orig_regs;
        // Kill the candidate explicitly; suppress Drop to avoid a redundant
        // second kill/reap of the same pid.
        std::mem::forget(state);

        let _ = nix::sys::signal::kill(Pid::from_raw(candidate as i32), Signal::SIGKILL);
        let _ = waitpid(Pid::from_raw(candidate as i32), Some(WaitPidFlag::WNOHANG));

        // Rewind the baseline back onto its interrupted boundary syscall. This is
        // done HERE (at reject), not at begin, on purpose: at begin the baseline
        // is stopped at the injected clone's syscall-exit, where a SETREGS of rax
        // is immediately clobbered by the kernel writing clone's return value
        // (the child pid) into rax. By reject time the baseline has long since
        // group-stopped at a clean userspace boundary (clone fully returned), so
        // re-attaching and rewinding its registers there sticks. Without this the
        // resumed baseline runs read()'s return handler with rax = child pid and
        // faults (or re-runs `syscall` with a garbage number -> ENOSYS).
        if let Err(e) = restore_baseline_for_restart(baseline, &orig_regs) {
            eprintln!(
                "[cow] Warning: failed to rewind baseline pid {} for restart: {}",
                baseline, e
            );
        }

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

    /// Garbage-collect epochs whose processes have exited.
    ///
    /// Removes only epochs where BOTH baseline and candidate are gone (pure
    /// garbage). A half-dead epoch (e.g. the candidate crashed mid-epoch while
    /// the pristine baseline is still frozen) is left intact and only logged:
    /// resolving it means resuming or discarding the survivor, which is a
    /// semantic decision for the caller (reject/commit), not the reaper.
    /// Returns the baseline keys of the epochs that were dropped.
    pub fn reap_dead(&mut self) -> Vec<u32> {
        let mut removed = Vec::new();
        let keys: Vec<u32> = self.epochs.keys().copied().collect();
        for k in keys {
            let (base, cand) = match self.epochs.get(&k) {
                Some(e) => (e.baseline_pid, e.candidate_pid),
                None => continue,
            };
            let base_alive = task_alive(base);
            let cand_alive = task_alive(cand);
            if !base_alive && !cand_alive {
                // Both gone: pure garbage. Drop it (EpochState::Drop harmlessly
                // re-kills the already-dead candidate).
                self.epochs.remove(&k);
                removed.push(k);
                eprintln!(
                    "[cow] reap: epoch baseline {} / candidate {} both gone; dropped",
                    base, cand
                );
            } else if !cand_alive {
                eprintln!(
                    "[cow] warn: candidate pid {} died mid-epoch; baseline {} still frozen (resolve via reject/commit)",
                    cand, base
                );
            } else if !base_alive {
                eprintln!(
                    "[cow] warn: baseline pid {} of live candidate {} gone unexpectedly",
                    base, cand
                );
            }
        }
        removed
    }
}

// ═══════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════

/// Wait for a state change on `pid` but NEVER block forever.
///
/// The injector (inject_fork_via_ptrace, phase 2 of
/// ProcessManager::begin_speculative_unlocked) runs on a socket-connection or
/// CLI thread. A plain `waitpid(pid, None)` that blocks on a target which never
/// delivers the expected ptrace-stop would wedge that thread forever (and, on
/// the legacy locked paths, could hang the whole daemon). So we poll with
/// WNOHANG and give up after `timeout_ms`, turning a hang into a recoverable
/// error.
fn waitpid_timeout(
    pid: Pid,
    extra: Option<WaitPidFlag>,
    timeout_ms: u64,
) -> Result<WaitStatus> {
    let mut flags = WaitPidFlag::WNOHANG;
    if let Some(f) = extra {
        flags |= f;
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        match waitpid(pid, Some(flags)) {
            Ok(WaitStatus::StillAlive) => {
                if Instant::now() >= deadline {
                    anyhow::bail!("waitpid on {} timed out after {} ms", pid, timeout_ms);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(status) => return Ok(status),
            Err(Errno::EINTR) => continue,
            Err(e) => anyhow::bail!("waitpid on {} failed: {}", pid, e),
        }
    }
}

/// Inject a clone() system call into the target process via ptrace to create a
/// coherent COW copy (the candidate).
///
/// The target process must be in a stopped state (SIGSTOP).
/// Returns the PID of the newly created candidate (also stopped) together with
/// the snapshot registers captured at the boundary (needed later to rewind the
/// baseline for a clean syscall restart on reject).
///
/// Uses PTRACE_O_TRACEFORK/CLONE/VFORK + PTRACE_CONT for reliable syscall
/// injection (PTRACE_SINGLESTEP is unreliable across `syscall` instructions on
/// some kernels).
fn inject_fork_via_ptrace(pid: u32) -> Result<(u32, libc::user_regs_struct)> {
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

    match waitpid_timeout(target, None, 2000) {
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

    // 4. Set up registers for clone(CLONE_PARENT|SIGCHLD, 0, 0, 0, 0) → a
    //    fork-like COW SIBLING that raises SIGCHLD to its parent on exit.
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
    //    exit_signal is set to SIGCHLD (the low byte of flags) so that when the
    //    candidate dies its parent (the launcher) receives SIGCHLD and can reap
    //    it with an ordinary waitpid(). Leaving it 0 made the candidate a
    //    "clone child" reapable only via __WALL/__WCLONE — a wait flavour most
    //    launchers (and Python's os.waitpid) can't express, so killed
    //    candidates leaked as permanent zombies under the launcher.
    let mut new_regs = orig_regs;
    new_regs.rip = syscall_addr;
    new_regs.rax = libc::SYS_clone as u64;   // __NR_clone = 56
    new_regs.rdi = CLONE_PARENT | SIGCHLD;   // flags = CLONE_PARENT + exit_signal SIGCHLD (COW; reapable)
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
        match waitpid_timeout(target, None, 5000) {
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
    match waitpid_timeout(Pid::from_raw(child_pid as i32), Some(WaitPidFlag::__WALL), 2000) {
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

    // 9. Restore the baseline's registers to the snapshot state and leave it
    //    group-stopped at a CLEAN userspace boundary.
    //
    //    Note we do NOT try to rewind the interrupted syscall here. At this
    //    PTRACE_EVENT_FORK stop the baseline is mid clone-exit, and any rax we
    //    SETREGS is immediately clobbered by the kernel writing clone's return
    //    value (the child pid) into rax when the task resumes. So rax is not
    //    trustworthy from here; the actual rewind onto the boundary syscall is
    //    performed later, at reject time, by restore_baseline_for_restart(),
    //    when the baseline has group-stopped at a clean boundary where SETREGS
    //    sticks. Here we only restore rip/args to the snapshot so the baseline
    //    parks at a well-defined userspace return boundary (rip just past the
    //    original `syscall`).
    ptrace::setregs(target, orig_regs)
        .context("Failed to restore baseline snapshot registers")?;

    // 10. Detach from the baseline (it remains SIGSTOP-frozen). The baseline is
    //     the pristine rollback copy and stays frozen until the epoch is
    //     committed (baseline killed) or rolled back (baseline rewound + resumed).
    ptrace::detach(target, Some(Signal::SIGSTOP))
        .with_context(|| format!("Failed to detach from pid {}", pid))?;

    eprintln!("[cow] Injected clone: baseline pid {} → candidate {}", pid, child_pid);

    Ok((child_pid, orig_regs))
}

/// x86-64 "restart pending" values the kernel leaves in `rax` when a syscall
/// was interrupted by a signal and should be re-executed afterwards. Visible via
/// GETREGS at the signal-delivery / group-stop, BEFORE the kernel performs the
/// restart rewind. (ERESTARTSYS / ERESTARTNOINTR / ERESTARTNOHAND /
/// ERESTART_RESTARTBLOCK, seen as their negated errno in rax.)
fn is_restart_pending(rax: u64) -> bool {
    matches!(rax as i64, -512 | -513 | -514 | -516)
}

/// Restore a rejected baseline to its pristine snapshot and leave it
/// group-stopped, ready for the caller to SIGCONT.
///
/// Two things have to be undone. First, the clone injection clobbered some of
/// the baseline's registers (the injected `syscall` overwrote rax with the child
/// pid, plus rcx/r11); restoring the FULL snapshot (orig_regs) fixes that
/// unconditionally. Second, IF the baseline was frozen mid-syscall with a
/// restart pending (e.g. blocked in read(), or an LSM/fmod_ret interception that
/// returned -ERESTARTSYS), its rip sits just past the `syscall` instruction and
/// the syscall must be rewound so it re-executes on resume; we detect that from
/// the snapshot — rip-2 is `0f 05` AND rax is a restart-pending value — and
/// point rip back at the `syscall` while reloading the syscall number from
/// orig_rax.
///
/// A baseline frozen anywhere else — after a COMPLETED syscall, or at an
/// arbitrary userspace instruction — is resumed EXACTLY at the snapshot with no
/// rewind. That avoids two bugs a naive rip-2 check has: re-executing a finished
/// syscall (double side effect), and pointing rip into the middle of a
/// non-syscall instruction.
///
/// Doing this at reject time (not inject time) is deliberate: the task is
/// stopped at a plain userspace boundary, so SETREGS is not clobbered by a
/// pending syscall-exit return value.
fn restore_baseline_for_restart(pid: u32, orig_regs: &libc::user_regs_struct) -> Result<()> {
    let target = Pid::from_raw(pid as i32);

    // Attach without perturbing the existing group-stop, then obtain a
    // ptrace-stop we can SETREGS on.
    ptrace::seize(target, ptrace::Options::empty())
        .with_context(|| format!("reject: ptrace seize {} failed", pid))?;
    ptrace::interrupt(target)
        .with_context(|| format!("reject: ptrace interrupt {} failed", pid))?;
    match waitpid_timeout(target, None, 2000) {
        Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::Stopped(_, _)) => {}
        Ok(status) => {
            ptrace::detach(target, Some(Signal::SIGSTOP)).ok();
            anyhow::bail!("reject: unexpected wait status after seize/interrupt: {:?}", status);
        }
        Err(e) => {
            ptrace::detach(target, Some(Signal::SIGSTOP)).ok();
            anyhow::bail!("reject: waitpid after seize/interrupt failed: {}", e);
        }
    }

    // Always start from the FULL snapshot: this alone un-does the register
    // clobber the clone injection left behind (the injected `syscall` overwrote
    // rax with the child pid, and rcx/r11 with the sysret rip/flags). Restoring
    // every register to orig_regs makes the baseline coherent again regardless
    // of the boundary it was frozen at.
    let mut resume_regs = *orig_regs;

    // Decide whether the baseline ALSO needs its boundary syscall rewound so it
    // re-executes on resume. That is true ONLY when it was frozen mid-syscall
    // with a restart pending, detected from the snapshot via two independent
    // signals:
    //   (a) rip-2 is a 2-byte `syscall` instruction (0f 05), and
    //   (b) rax holds a kernel "restart pending" value (-ERESTARTSYS etc.),
    //       i.e. the syscall was interrupted, not completed.
    // Requiring BOTH avoids re-executing a completed syscall (rip-2 == 0f 05 but
    // rax is a normal return) and mis-pointing rip when the task was frozen at
    // an arbitrary (non-syscall) instruction. In those cases the baseline is
    // resumed EXACTLY at the snapshot instead.
    let syscall_ip = orig_regs.rip.wrapping_sub(2);
    let mut rip_is_syscall = false;
    if orig_regs.rip >= 2 {
        if let Ok(mut mem) = OpenOptions::new()
            .read(true)
            .open(format!("/proc/{}/mem", pid))
        {
            let mut buf = [0u8; 2];
            if mem.seek(SeekFrom::Start(syscall_ip)).is_ok() && mem.read_exact(&mut buf).is_ok() {
                rip_is_syscall = buf == [0x0f, 0x05];
            }
        }
    }

    if rip_is_syscall && is_restart_pending(orig_regs.rax) {
        resume_regs.rip = syscall_ip;          // back onto the `syscall` insn
        resume_regs.rax = orig_regs.orig_rax;  // reload the syscall number
        eprintln!(
            "[cow] reject rewind pid={} rip 0x{:x} -> 0x{:x} rax -> {} (orig_rax)",
            pid, orig_regs.rip, resume_regs.rip, orig_regs.orig_rax
        );
    } else {
        eprintln!(
            "[cow] reject: baseline pid={} not at an interrupted-syscall boundary \
             (rip=0x{:x} rax={}); resuming at snapshot without rewind",
            pid, orig_regs.rip, orig_regs.rax as i64
        );
    }

    ptrace::setregs(target, resume_regs)
        .context("reject: failed to restore baseline registers")?;

    // Detach, leaving the baseline group-stopped (SIGSTOP). The caller SIGCONTs
    // it, at which point it either re-executes the boundary syscall (rewound
    // case) or simply continues from the snapshot.
    ptrace::detach(target, Some(Signal::SIGSTOP))
        .with_context(|| format!("reject: failed to detach from pid {}", pid))?;

    Ok(())
}

/// Returns false if `pid` has no /proc entry or its task is a zombie/dead.
/// Used by reap_dead() to garbage-collect epochs whose processes have exited.
fn task_alive(pid: u32) -> bool {
    let stat = match fs::read_to_string(format!("/proc/{}/stat", pid)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // /proc/<pid>/stat: "pid (comm) state ...". comm may contain spaces and
    // parens, so find the LAST ')' and read the first non-space char after it.
    match stat.rfind(')') {
        Some(idx) => {
            let state = stat[idx + 1..].trim_start().chars().next();
            !matches!(state, Some('Z') | Some('X') | Some('x'))
        }
        None => true,
    }
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
        if mem_file.seek(SeekFrom::Start(regs.rip - 2)).is_ok()
            && mem_file.read_exact(&mut buf).is_ok()
            && buf == [0x0f, 0x05]
        {
            return Ok(regs.rip - 2);
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
                if mem_file.seek(SeekFrom::Start(start)).is_ok()
                    && mem_file.read_exact(&mut vdso_buf).is_ok()
                {
                    for i in 0..vdso_buf.len().saturating_sub(1) {
                        if vdso_buf[i] == 0x0f && vdso_buf[i + 1] == 0x05 {
                            return Ok(start + i as u64);
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
