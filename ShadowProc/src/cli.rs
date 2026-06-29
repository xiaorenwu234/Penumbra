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
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
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
                    println!("{:<8} {:<8} {:<16} {:<12} {:<10} {}", "PID", "TGID", "COMM", "TYPE", "SYSCALL", "CGROUP");
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
                match pm.continue_process(pid) {
                    Ok(()) => println!("\x1b[32m[OK]\x1b[0m Process {} resumed (SIGCONT sent)", pid),
                    Err(e) => println!("\x1b[31m[ERROR]\x1b[0m {}", e),
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

            "help" | "h" | "?" => {
                println!("Commands:");
                println!("  list (ls)              - List all frozen processes");
                println!("  continue (c) <pid>     - Resume a frozen process");
                println!("  discard (d) <pid>      - Kill a frozen process");
                println!("  checkpoint (cp) <pid>  - CRIU checkpoint a frozen process");
                println!("  restore <path>         - Restore from a CRIU checkpoint");
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
