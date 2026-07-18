#![allow(dead_code)]

mod bpf_loader;
mod cli;
mod event_handler;
mod memory_tracker;
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
use event_handler::{EventType, InterceptEvent};
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

    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║         ShadowProc - Process Communication Guard        ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    if let Some(ref cgroup) = args.cgroup_path {
        eprintln!("║  Monitoring cgroup: {:37}║", cgroup.display());
    } else {
        eprintln!("║  Monitoring cgroup: (none - use socket API to add)      ║");
    }
    eprintln!("║  Checkpoint dir:    {:37}║", args.checkpoint_dir.display());
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
    let bpf_manager = BpfManager::start(
        args.cgroup_path.as_deref(),
        event_tx,
    ).context("Failed to start BPF manager. Are you running as root? Is BPF LSM enabled?")?;
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
    let process_manager = Arc::new(Mutex::new(
        ProcessManager::new(args.checkpoint_dir, bpf_manager.clone())
    ));

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

    // Main loop
    while running.load(Ordering::Relaxed) {
        // Check for new events (non-blocking)
        if let Ok(event) = event_rx.try_recv() {
            let mut pm = process_manager.lock().unwrap();

            match event.event_type_enum() {
                EventType::Fork => {
                    // Fork event: auto-track child if parent is tracked
                    if let Some(parent_tgid) = event.parent_tgid() {
                        let child_tgid = event.tgid;
                        eprintln!(
                            "\n\x1b[1;36m[FORK]\x1b[0m parent={} child={} comm={}",
                            parent_tgid, child_tgid, event.comm_str()
                        );
                        let _ = pm.handle_fork_event(parent_tgid, child_tgid);
                    }
                }
                _ => {
                    // Normal interception event
                    eprintln!("\n\x1b[1;31m[INTERCEPTED]\x1b[0m {}", event);
                    let trigger_tgid = event.tgid;
                    pm.record_frozen(event);

                    // Auto-freeze the rest of the cgroup so the whole group is
                    // stopped as an atomic unit before audit/commit/rollback.
                    // The triggering process is already SIGSTOP'd by eBPF and
                    // recorded above; freeze_by_cgroup skips it and SIGSTOPs the
                    // remaining siblings, recording them for later resume/kill.
                    let cgroup_path = pm
                        .get_frozen(trigger_tgid)
                        .map(|f| f.cgroup_path.clone());
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
            }

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

        // Small sleep to avoid busy-waiting
        thread::sleep(Duration::from_millis(10));
    }

    eprintln!("\n[*] Shutting down ShadowProc...");
    // bpf_manager is dropped via Arc when all references go out of scope
    eprintln!("[+] Done.");

    Ok(())
}

fn ctrlc_handler(running: Arc<AtomicBool>) {
    let _ = ctrlc::set_handler(move || {
        running.store(false, Ordering::Relaxed);
    });
}
