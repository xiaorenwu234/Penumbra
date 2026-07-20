use anyhow::Result;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::process_manager::ProcessManager;

/// Interactive CLI for managing intercepted processes
pub struct Cli {
    process_manager: Arc<Mutex<ProcessManager>>,
}

impl Cli {
    /// Create a Cli that shares a ProcessManager with the socket server.
    pub fn new_with_shared(process_manager: Arc<Mutex<ProcessManager>>) -> Self {
        Cli { process_manager }
    }

    /// Process a command from the user
    pub fn process_command(&mut self, input: &str) -> Result<bool> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(false);
        }

        match parts[0] {
            "list" | "ls" => {
                let pm = self.process_manager.lock().unwrap();
                let frozen = pm.list_frozen();
                if frozen.is_empty() {
                    println!("No frozen processes.");
                } else {
                    println!("{:<8} {:<8} {:<16} {:<12} {:<10} CGROUP", "PID", "TGID", "COMM", "TYPE", "SYSCALL");
                    println!("{}", "-".repeat(80));
                    for p in frozen {
                        println!(
                            "{:<8} {:<8} {:<16} {:<12} {:<10} {}",
                            p.pid,
                            p.tgid,
                            p.comm,
                            p.event.event_type_enum(),
                            p.event.syscall_name(),
                            p.cgroup_path,
                        );
                    }
                }
            }

            "continue" | "cont" | "c" => {
                if parts.len() < 2 {
                    println!("Usage: continue <pid>");
                    return Ok(false);
                }
                let pid: u32 = parts[1].parse().unwrap_or(0);
                let mut pm = self.process_manager.lock().unwrap();
                // Unfreeze at cgroup granularity: resolve the cgroup this pid
                // belongs to, then resume the whole group (matching the
                // whole-cgroup freeze behavior on interception).
                let cgroup = pm.get_frozen(pid).map(|f| f.cgroup_path.clone());
                match cgroup {
                    Some(cg) => match pm.continue_by_cgroup(&cg) {
                        Ok(pids) => println!(
                            "\x1b[32m[OK]\x1b[0m Resumed cgroup {} ({} process(es): {:?})",
                            cg, pids.len(), pids
                        ),
                        Err(e) => println!("\x1b[31m[ERROR]\x1b[0m {}", e),
                    },
                    None => println!(
                        "\x1b[31m[ERROR]\x1b[0m Process {} is not in frozen list",
                        pid
                    ),
                }
            }

            "discard" | "kill" | "d" => {
                if parts.len() < 2 {
                    println!("Usage: discard <pid>");
                    return Ok(false);
                }
                let pid: u32 = parts[1].parse().unwrap_or(0);
                let mut pm = self.process_manager.lock().unwrap();
                match pm.discard_process(pid) {
                    Ok(()) => println!("\x1b[32m[OK]\x1b[0m Process {} killed", pid),
                    Err(e) => println!("\x1b[31m[ERROR]\x1b[0m {}", e),
                }
            }

            "checkpoint" | "cp" => {
                if parts.len() < 2 {
                    println!("Usage: checkpoint <pid>");
                    return Ok(false);
                }
                let pid: u32 = parts[1].parse().unwrap_or(0);
                let mut pm = self.process_manager.lock().unwrap();
                match pm.checkpoint(pid) {
                    Ok(path) => println!("\x1b[32m[OK]\x1b[0m Checkpoint saved to {:?}", path),
                    Err(e) => println!("\x1b[31m[ERROR]\x1b[0m {}", e),
                }
            }

            "restore" => {
                if parts.len() < 2 {
                    println!("Usage: restore <checkpoint-path>");
                    return Ok(false);
                }
                let path = PathBuf::from(parts[1]);
                let pm = self.process_manager.lock().unwrap();
                match pm.restore(&path) {
                    Ok(_) => println!("\x1b[32m[OK]\x1b[0m Process restored from {:?}", path),
                    Err(e) => println!("\x1b[31m[ERROR]\x1b[0m {}", e),
                }
            }

            "speculative" | "spec" => {
                if parts.len() < 2 {
                    println!("Usage: speculative <pid>");
                    return Ok(false);
                }
                let pid: u32 = parts[1].parse().unwrap_or(0);
                // Mirror the socket path's three-phase setup so the multi-second
                // ptrace clone injection runs WITHOUT the ProcessManager lock
                // held: reserve (locked) -> inject (unlocked) -> finish/abort
                // (locked). Otherwise the whole event loop and every socket
                // client would block for the entire duration of the injection.
                let reserved = {
                    let mut pm = self.process_manager.lock().unwrap();
                    pm.reserve_speculative(pid)
                };
                let baseline = match reserved {
                    Ok(b) => b,
                    Err(e) => {
                        println!("\x1b[31m[ERROR]\x1b[0m {}", e);
                        return Ok(false);
                    }
                };
                let injected = ProcessManager::inject_speculative(baseline);
                let mut pm = self.process_manager.lock().unwrap();
                match injected {
                    Ok((candidate, regs)) => {
                        pm.finish_speculative(baseline, candidate, regs);
                        println!(
                            "\x1b[32m[OK]\x1b[0m Epoch started: froze pid {} as pristine baseline, forked speculative candidate pid {} (the live process for this epoch)",
                            baseline, candidate
                        );
                    }
                    Err(e) => {
                        pm.abort_speculative(baseline);
                        println!("\x1b[31m[ERROR]\x1b[0m {}", e);
                    }
                }
            }

            "reject" | "rj" => {
                if parts.len() < 2 {
                    println!("Usage: reject <pid>");
                    return Ok(false);
                }
                let pid: u32 = parts[1].parse().unwrap_or(0);
                let mut pm = self.process_manager.lock().unwrap();
                match pm.reject_to_checkpoint(pid) {
                    Ok(baseline) => println!(
                        "\x1b[32m[OK]\x1b[0m Rolled back epoch for pid {}; discarded candidate, resumed pristine baseline pid {} as canonical",
                        pid, baseline
                    ),
                    Err(e) => println!("\x1b[31m[ERROR]\x1b[0m {}", e),
                }
            }

            "commit" => {
                if parts.len() < 2 {
                    println!("Usage: commit <pid>");
                    return Ok(false);
                }
                let pid: u32 = parts[1].parse().unwrap_or(0);
                let mut pm = self.process_manager.lock().unwrap();
                match pm.commit_process(pid) {
                    Ok(()) => println!("\x1b[32m[OK]\x1b[0m Committed pid {} - COW shadow discarded", pid),
                    Err(e) => println!("\x1b[31m[ERROR]\x1b[0m {}", e),
                }
            }

            "help" | "h" | "?" => {
                println!("Commands:");
                println!("  list (ls)              - List all frozen processes");
                println!("  continue (c) <pid>     - Resume the whole cgroup the pid belongs to");
                println!("  discard (d) <pid>      - Kill a frozen process");
                println!("  checkpoint (cp) <pid>  - CRIU checkpoint a frozen process");
                println!("  restore <path>         - Restore from a CRIU checkpoint");
                println!("  speculative (spec) <pid> - Begin a versioning epoch (fork speculative candidate)");
                println!("  reject (rj) <pid>      - Roll back: discard candidate, resume pristine baseline");
                println!("  commit <pid>           - Commit: discard baseline, keep candidate as canonical");
                println!("  quit (q)               - Exit ShadowProc");
                println!("  help (h)               - Show this help");
            }

            "quit" | "q" | "exit" => {
                return Ok(true);
            }

            _ => {
                println!("Unknown command: '{}'. Type 'help' for available commands.", parts[0]);
            }
        }

        Ok(false)
    }
}
