//! COW (Copy-on-Write) Memory Tracker for ShadowProc
//!
//! Implements memory rollback by leveraging the Linux kernel's native COW mechanism:
//! 1. Inject fork() via ptrace into the target process → creates a "shadow" child
//! 2. The shadow child shares physical pages with the parent (COW semantics)
//! 3. When the parent writes to a page, the kernel automatically preserves the
//!    original page in the shadow child
//! 4. On rollback: scan soft-dirty pages, restore from shadow child's /proc/pid/mem
//! 5. On commit: kill the shadow child

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::RawFd;

const PAGE_SIZE: u64 = 4096;
/// Bit 55 in pagemap entry indicates soft-dirty
const SOFT_DIRTY_BIT: u64 = 1 << 55;
/// Bit 63 indicates page is present
const PAGE_PRESENT_BIT: u64 = 1 << 63;

/// Statistics returned after a rollback operation
#[derive(Debug, Clone)]
pub struct RollbackStats {
    pub pages_scanned: u64,
    pub pages_dirty: u64,
    pub pages_restored: u64,
    pub bytes_restored: u64,
}

/// A writable private memory region parsed from /proc/pid/maps
#[derive(Debug, Clone)]
struct MemRegion {
    start: u64,
    end: u64,
}

/// State for a single tracked process
struct ShadowState {
    target_pid: u32,
    shadow_pid: u32,
    memfd: RawFd,
    writable_regions: Vec<MemRegion>,
}

impl Drop for ShadowState {
    fn drop(&mut self) {
        // Kill shadow child if still alive
        let _ = nix::sys::signal::kill(Pid::from_raw(self.shadow_pid as i32), Signal::SIGKILL);
        // Wait to reap zombie
        let _ = waitpid(Pid::from_raw(self.shadow_pid as i32), Some(WaitPidFlag::WNOHANG));
        // Close memfd
        unsafe {
            libc::close(self.memfd);
        }
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
    /// 2. Inject a fork() syscall to create a shadow child
    /// 3. Freeze the shadow child permanently
    /// 4. Detach from the parent
    /// 5. Clear soft-dirty bits on the parent
    pub fn begin_tracking(&mut self, pid: u32) -> Result<()> {
        if self.shadows.contains_key(&pid) {
            anyhow::bail!("Process {} is already being tracked for COW", pid);
        }

        // Parse writable private regions before ptrace (proc is accessible)
        let regions = parse_maps(pid)?;
        if regions.is_empty() {
            anyhow::bail!("No writable private regions found for pid {}", pid);
        }

        // Create memfd for page transfer buffer
        let memfd = create_memfd()?;

        // Inject fork via ptrace to create shadow child
        let shadow_pid = inject_fork_via_ptrace(pid)
            .with_context(|| format!("Failed to inject fork into pid {}", pid))?;

        // Clear soft-dirty bits so we can track future writes
        clear_soft_dirty(pid)
            .with_context(|| format!("Failed to clear soft-dirty for pid {}", pid))?;

        eprintln!(
            "[cow] Started tracking pid {} -> shadow pid {}, {} writable regions",
            pid,
            shadow_pid,
            regions.len()
        );

        self.shadows.insert(
            pid,
            ShadowState {
                target_pid: pid,
                shadow_pid,
                memfd,
                writable_regions: regions,
            },
        );

        Ok(())
    }

    /// Rollback a process's memory to the state captured at begin_tracking().
    /// The process MUST be frozen (SIGSTOP) when this is called.
    ///
    /// Returns statistics about the rollback operation.
    pub fn rollback(&mut self, pid: u32) -> Result<RollbackStats> {
        let state = self
            .shadows
            .get(&pid)
            .ok_or_else(|| anyhow::anyhow!("Process {} is not being COW-tracked", pid))?;

        // Scan for dirty pages
        let dirty_pages = scan_dirty_pages(pid, &state.writable_regions)?;
        let pages_scanned: u64 = state
            .writable_regions
            .iter()
            .map(|r| (r.end - r.start) / PAGE_SIZE)
            .sum();

        let pages_dirty = dirty_pages.len() as u64;

        // Restore dirty pages from shadow child
        let pages_restored =
            restore_pages(pid, state.shadow_pid, &dirty_pages, state.memfd)?;

        let stats = RollbackStats {
            pages_scanned,
            pages_dirty,
            pages_restored: pages_restored as u64,
            bytes_restored: pages_restored as u64 * PAGE_SIZE,
        };

        eprintln!(
            "[cow] Rollback pid {}: scanned={}, dirty={}, restored={} ({} bytes)",
            pid, stats.pages_scanned, stats.pages_dirty, stats.pages_restored, stats.bytes_restored
        );

        // Clean up shadow process
        self.shadows.remove(&pid);

        Ok(stats)
    }

    /// Commit: discard the shadow process (accept all memory changes).
    pub fn commit(&mut self, pid: u32) -> Result<()> {
        if self.shadows.remove(&pid).is_none() {
            anyhow::bail!("Process {} is not being COW-tracked", pid);
        }
        eprintln!("[cow] Committed pid {} - shadow discarded", pid);
        Ok(())
    }

    /// Check if a process is currently being COW-tracked
    pub fn is_tracking(&self, pid: u32) -> bool {
        self.shadows.contains_key(&pid)
    }

    /// Get all tracked PIDs
    pub fn tracked_pids(&self) -> Vec<u32> {
        self.shadows.keys().copied().collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════

/// Parse /proc/pid/maps to find writable private (anonymous + file-backed) regions.
/// These are regions where COW tracking is meaningful.
fn parse_maps(pid: u32) -> Result<Vec<MemRegion>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path)
        .with_context(|| format!("Failed to read {}", maps_path))?;

    let mut regions = Vec::new();

    for line in content.lines() {
        // Format: address perms offset dev inode pathname
        // e.g.: 7f8a1000-7f8a2000 rw-p 00000000 00:00 0  [heap]
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let perms = parts[1];
        // We want: writable (w) + private (p)
        // perms format: rwxp or rwxs (s = shared)
        if perms.len() < 4 {
            continue;
        }
        let is_writable = perms.as_bytes()[1] == b'w';
        let is_private = perms.as_bytes()[3] == b'p';

        if !is_writable || !is_private {
            continue;
        }

        // Skip [vvar] and [vdso] - kernel-managed, can't write to them
        if let Some(name) = parts.get(5) {
            if *name == "[vvar]" || *name == "[vdso]" || *name == "[vsyscall]" {
                continue;
            }
        }

        // Parse address range
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            continue;
        }
        let start = u64::from_str_radix(addr_parts[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addr_parts[1], 16).unwrap_or(0);

        if start < end {
            regions.push(MemRegion { start, end });
        }
    }

    Ok(regions)
}

/// Create a memfd for use as a page transfer buffer
fn create_memfd() -> Result<RawFd> {
    let name = std::ffi::CString::new("shadow_cow_buffer").unwrap();
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        anyhow::bail!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        );
    }
    // Pre-allocate one page
    unsafe {
        libc::ftruncate(fd, PAGE_SIZE as i64);
    }
    Ok(fd)
}

/// Clear soft-dirty bits for a process by writing "4" to /proc/pid/clear_refs
fn clear_soft_dirty(pid: u32) -> Result<()> {
    let path = format!("/proc/{}/clear_refs", pid);
    fs::write(&path, "4")
        .with_context(|| format!("Failed to write to {}", path))?;
    Ok(())
}

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

/// Scan /proc/pid/pagemap for soft-dirty pages in the given regions.
/// Returns a list of virtual page addresses that have been written to.
fn scan_dirty_pages(pid: u32, regions: &[MemRegion]) -> Result<Vec<u64>> {
    let pagemap_path = format!("/proc/{}/pagemap", pid);
    let mut pagemap = OpenOptions::new()
        .read(true)
        .open(&pagemap_path)
        .with_context(|| format!("Failed to open {}", pagemap_path))?;

    let mut dirty_pages = Vec::new();

    for region in regions {
        let start_page = region.start / PAGE_SIZE;
        let end_page = region.end / PAGE_SIZE;

        for page_idx in start_page..end_page {
            let offset = page_idx * 8; // Each pagemap entry is 8 bytes
            if pagemap.seek(SeekFrom::Start(offset)).is_err() {
                continue;
            }

            let mut entry_bytes = [0u8; 8];
            if pagemap.read_exact(&mut entry_bytes).is_err() {
                continue;
            }

            let entry = u64::from_ne_bytes(entry_bytes);

            // Check if page is present and soft-dirty
            if (entry & PAGE_PRESENT_BIT) != 0 && (entry & SOFT_DIRTY_BIT) != 0 {
                dirty_pages.push(page_idx * PAGE_SIZE);
            }
        }
    }

    Ok(dirty_pages)
}

/// Restore dirty pages from the shadow child process to the target process.
/// Uses memfd as an intermediate buffer.
/// Returns the number of pages successfully restored.
fn restore_pages(target_pid: u32, shadow_pid: u32, pages: &[u64], _memfd: RawFd) -> Result<u32> {
    let shadow_mem_path = format!("/proc/{}/mem", shadow_pid);
    let target_mem_path = format!("/proc/{}/mem", target_pid);

    let mut shadow_mem = OpenOptions::new()
        .read(true)
        .open(&shadow_mem_path)
        .with_context(|| format!("Failed to open {}", shadow_mem_path))?;

    let mut target_mem = OpenOptions::new()
        .write(true)
        .open(&target_mem_path)
        .with_context(|| format!("Failed to open {}", target_mem_path))?;

    let mut page_buf = [0u8; PAGE_SIZE as usize];
    let mut restored = 0u32;

    for &page_addr in pages {
        // Read original page from shadow child
        if shadow_mem.seek(SeekFrom::Start(page_addr)).is_err() {
            eprintln!(
                "[cow] Warning: could not seek to 0x{:x} in shadow pid {}",
                page_addr, shadow_pid
            );
            continue;
        }
        if shadow_mem.read_exact(&mut page_buf).is_err() {
            eprintln!(
                "[cow] Warning: could not read page at 0x{:x} from shadow pid {}",
                page_addr, shadow_pid
            );
            continue;
        }

        // Write page to target process
        if target_mem.seek(SeekFrom::Start(page_addr)).is_err() {
            eprintln!(
                "[cow] Warning: could not seek to 0x{:x} in target pid {}",
                page_addr, target_pid
            );
            continue;
        }
        if target_mem.write_all(&page_buf).is_err() {
            eprintln!(
                "[cow] Warning: could not write page at 0x{:x} to target pid {}",
                page_addr, target_pid
            );
            continue;
        }

        restored += 1;
    }

    Ok(restored)
}
