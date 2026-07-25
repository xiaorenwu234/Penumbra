#![allow(dead_code)]

// ShadowProc is x86-64 only. It hard-codes the x86-64 syscall ABI throughout:
// the register layout for the ptrace-injected clone(2), the 2-byte `0f 05`
// syscall opcode used to rewind a boundary, __NR_bpf = 321, and fmod_ret hooks
// attached to __x64_sys_* symbols. On another architecture it would compile but
// fail at runtime in hard-to-diagnose ways, so fail loudly at build time.
#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "ShadowProc supports x86-64 only (hard-coded x86-64 syscall ABI: injected \
     clone register layout, `0f 05` syscall opcode, __NR_bpf=321, and \
     __x64_sys_* fmod_ret hooks)."
);

mod bpf_loader;
mod cli;
mod event_handler;
mod memory_tracker;
mod policy_generated;
mod process_manager;
mod socket_server;

use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::bounded;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bpf_loader::BpfManager;
use cli::Cli;
use event_handler::{Decision, EventType, InterceptEvent};
use process_manager::ProcessManager;
use socket_server::SocketServer;

#[derive(Parser, Debug)]
#[command(
    name = "shadow-proc",
    about = "eBPF-based process communication interceptor and freezer",
    version
)]
struct Args {
    /// Path to the cgroup to monitor (e.g., /sys/fs/cgroup/user.slice/shadow).
    /// Optional when using socket API to add cgroups dynamically.
    #[arg(short, long)]
    cgroup_path: Option<PathBuf>,

    /// Directory to store CRIU checkpoints
    #[arg(short = 'd', long, default_value = "/tmp/shadow-proc-checkpoints")]
    checkpoint_dir: PathBuf,

    /// Unix socket path for control API
    #[arg(short = 's', long)]
    sock: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Harden the control plane (issue #2): forbid this daemon (and anything it
    // ever execs) from gaining privileges via a setuid/setgid bit. no_new_privs
    // is inherited across fork/exec and can never be unset. ShadowProc never
    // execs a setuid helper, so this is always safe here.
    set_no_new_privs();

    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║         ShadowProc - Process Communication Guard        ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    if let Some(ref cgroup) = args.cgroup_path {
        eprintln!("║  Monitoring cgroup: {:37}║", cgroup.display());
    } else {
        eprintln!("║  Monitoring cgroup: (none - use socket API to add)      ║");
    }
    eprintln!(
        "║  Checkpoint dir:    {:37}║",
        args.checkpoint_dir.display()
    );
    if let Some(ref sock) = args.sock {
        eprintln!("║  Socket path:       {:37}║", sock.display());
    }
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    // Verify cgroup path exists if provided
    if let Some(ref cgroup_path) = args.cgroup_path {
        if !cgroup_path.exists() {
            anyhow::bail!(
                "Cgroup path does not exist: {:?}. \
                 Create it with: sudo mkdir -p {:?}",
                cgroup_path,
                cgroup_path
            );
        }
    }

    // Create event channel
    let (event_tx, event_rx) = bounded::<InterceptEvent>(1024);

    // Start BPF manager
    eprintln!("[*] Loading eBPF programs (LSM + fmod_ret)...");
    let bpf_manager = BpfManager::start(args.cgroup_path.as_deref(), event_tx)
        .context("Failed to start BPF manager. Are you running as root? Is BPF LSM enabled?")?;
    let bpf_manager = Arc::new(bpf_manager);
    eprintln!("[+] eBPF programs loaded and attached successfully.");
    eprintln!("[*] Monitoring for external communication attempts...");
    eprintln!("[*] Type 'help' for available commands.");
    eprintln!();

    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    ctrlc_handler(running_clone);

    // Process manager (shared via Arc<Mutex>)
    let process_manager = Arc::new(Mutex::new(ProcessManager::new(
        args.checkpoint_dir,
        bpf_manager.clone(),
    )));

    // Start socket server if requested
    let _socket_server = if let Some(ref sock_path) = args.sock {
        Some(SocketServer::start(
            sock_path,
            process_manager.clone(),
            bpf_manager.clone(),
            running.clone(),
        )?)
    } else {
        None
    };

    // Main event loop: poll both stdin and events
    let mut stdout = io::stdout();

    print!("shadow-proc> ");
    stdout.flush()?;

    // Spawn a thread to read stdin lines
    let (cmd_tx, cmd_rx) = bounded::<String>(64);
    let running_for_stdin = running.clone();
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            if !running_for_stdin.load(Ordering::Relaxed) {
                break;
            }
            if let Ok(line) = line {
                if cmd_tx.send(line).is_err() {
                    break;
                }
            }
        }
    });

    // CLI instance (wraps access to process_manager for interactive use)
    let mut cli = Cli::new_with_shared(process_manager.clone());

    // Periodic-cleanup tick counter (see reap_dead call at the end of the loop).
    let mut tick: u32 = 0;

    // Main loop
    while running.load(Ordering::Relaxed) {
        // Drain a bounded batch of ring-buffer events each tick. Handling only
        // one event per 10ms caps throughput around 100/s and makes BPF drops
        // likely under bursts; batching keeps the control socket responsive
        // while letting userspace catch up with syscall-rate events.
        let mut handled_events = 0u32;
        while handled_events < 256 {
            let event = match event_rx.try_recv() {
                Ok(event) => event,
                Err(_) => break,
            };
            handled_events += 1;
            let mut pm = process_manager.lock().unwrap();

            match event.event_type_enum() {
                EventType::Fork => {
                    // Fork event: auto-track child if parent is tracked
                    if let Some(parent_tgid) = event.parent_tgid() {
                        let child_tgid = event.tgid;
                        eprintln!(
                            "\n\x1b[1;36m[FORK]\x1b[0m parent={} child={} comm={}",
                            parent_tgid,
                            child_tgid,
                            event.comm_str()
                        );
                        let _ = pm.handle_fork_event(parent_tgid, child_tgid);
                    }
                }
                _ => {
                    match event.decision_enum() {
                        Decision::Fence => {
                            // FENCE means BPF returned -ERESTARTSYS and queued
                            // SIGSTOP. Only this path may register frozen state
                            // and stop the rest of the cgroup as an atomic unit.
                            eprintln!("\n\x1b[1;31m[INTERCEPTED]\x1b[0m {}", event);
                            let trigger_tgid = event.tgid;
                            pm.record_frozen(event);

                            let cgroup_path =
                                pm.get_frozen(trigger_tgid).map(|f| f.cgroup_path.clone());
                            if let Some(cgroup_path) = cgroup_path {
                                match pm.freeze_by_cgroup(&cgroup_path) {
                                    Ok(pids) if !pids.is_empty() => {
                                        eprintln!(
                                            "\x1b[1;33m[CGROUP-FREEZE]\x1b[0m froze {} sibling process(es) in {}: {:?}",
                                            pids.len(), cgroup_path, pids
                                        );
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        eprintln!(
                                            "\x1b[1;33m[CGROUP-FREEZE]\x1b[0m failed to freeze cgroup {}: {}",
                                            cgroup_path, e
                                        );
                                    }
                                }
                            }
                        }
                        Decision::Deny => {
                            // DENY means MODE_ENFORCED returned EPERM. The
                            // triggering process was not stopped and must not be
                            // recorded as frozen; keep a violation record for
                            // the orchestrator/audit plane only.
                            eprintln!("\n\x1b[1;35m[DENIED]\x1b[0m {}", event);
                            pm.record_violation(event);
                        }
                        Decision::Allow | Decision::Unknown(_) => {
                            // ALLOW/info lifecycle events are not fences. Unknown
                            // decisions are logged and left out of frozen state to
                            // avoid falsely resuming or killing a running process.
                            eprintln!("\n\x1b[1;34m[EVENT]\x1b[0m {}", event);
                        }
                    }
                }
            }
        }

        if handled_events > 0 {
            eprint!("shadow-proc> ");
            io::stderr().flush().ok();
        }

        // Check for user commands (non-blocking)
        if let Ok(cmd) = cmd_rx.try_recv() {
            let should_quit = cli.process_command(&cmd)?;
            if should_quit {
                break;
            }
            print!("shadow-proc> ");
            stdout.flush()?;
        }

        // Small sleep to avoid busy-waiting without artificially capping event
        // throughput to ~100/s.
        thread::sleep(Duration::from_millis(1));

        // Roughly once a second, garbage-collect bookkeeping for processes that
        // exited on their own (crash / external kill). try_lock so this never
        // contends with event or command handling.
        tick = tick.wrapping_add(1);
        if tick.is_multiple_of(1000) {
            if let Ok(mut pm) = process_manager.try_lock() {
                pm.reap_dead();
            }
        }
    }

    eprintln!("\n[*] Shutting down ShadowProc...");
    // Abandon in-flight speculation (resume pristine baselines, discard
    // candidates) and KILL any remaining non-versioned frozen process so its
    // unauthorized pending effect cannot escape once the BPF hooks detach.
    {
        let mut pm = process_manager.lock().unwrap();
        let n = pm.release_all();
        if n > 0 {
            eprintln!(
                "[*] Handled {} frozen process(es) on shutdown \
                       (baselines resumed, unauthorized frozen killed).",
                n
            );
        }
    }
    // bpf_manager is dropped via Arc when all references go out of scope
    eprintln!("[+] Done.");

    Ok(())
}

fn ctrlc_handler(running: Arc<AtomicBool>) {
    let _ = ctrlc::set_handler(move || {
        running.store(false, Ordering::Relaxed);
    });
}

/// Set PR_SET_NO_NEW_PRIVS so no execve from this process tree can gain
/// privileges via a setuid/setgid bit. Best-effort: a failure is logged but
/// not fatal (the daemon's other fences remain in force).
fn set_no_new_privs() {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes only scalar args (no pointers).
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        eprintln!(
            "[!] Warning: PR_SET_NO_NEW_PRIVS failed ({}); continuing without it.",
            std::io::Error::last_os_error()
        );
    }
}
