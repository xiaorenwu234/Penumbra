use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::bpf_loader::BpfManager;
use crate::process_manager::ProcessManager;

#[derive(Deserialize, Debug)]
struct Request {
    action: String,
    #[serde(default)]
    cgroup_path: Option<String>,
    #[serde(default)]
    cgroup_id: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
}

#[derive(Serialize)]
struct Response {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frozen: Option<Vec<FrozenInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pids: Option<Vec<u32>>,
}

#[derive(Serialize, Clone)]
struct FrozenInfo {
    pid: u32,
    tgid: u32,
    comm: String,
    cgroup: String,
    event_type: String,
    syscall: String,
}

pub struct SocketServer {
    sock_path: PathBuf,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

/// Validate a cgroup path supplied over the control socket (issue #2 cgroupfs
/// write restriction). Fail-closed: the path must be absolute, live under the
/// cgroup2 root `/sys/fs/cgroup`, and contain no `..`/`.` traversal component,
/// so a malicious control message can never point the daemon at an arbitrary
/// cgroup outside the managed subtree.
fn cgroup_path_ok(path: &str) -> bool {
    use std::path::Component;
    let p = Path::new(path);
    if !p.is_absolute() {
        return false;
    }
    for c in p.components() {
        if matches!(c, Component::ParentDir | Component::CurDir) {
            return false;
        }
    }
    p.starts_with("/sys/fs/cgroup")
}

impl SocketServer {
    pub fn start(
        sock_path: &Path,
        process_manager: Arc<Mutex<ProcessManager>>,
        bpf_manager: Arc<BpfManager>,
        running: Arc<AtomicBool>,
    ) -> Result<Self> {
        // Remove stale socket
        let _ = std::fs::remove_file(sock_path);

        // Restrict the containing directory to the daemon's uid (0700) so no
        // other user can reach the socket path at all.
        #[cfg(unix)]
        if let Some(dir) = sock_path.parent() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }

        let listener = UnixListener::bind(sock_path)
            .with_context(|| format!("Failed to bind socket: {:?}", sock_path))?;

        // Use non-blocking mode so the accept loop can check the
        // running flag periodically and shut down gracefully.
        listener.set_nonblocking(true)?;

        // Lock the socket down to owner rw only (0600). This is the ONLY control
        // interface; a co-located sandboxed agent must not be able to reach it.
        // Peer identity is additionally checked (SO_PEERCRED) on every accept.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))
                .ok();
        }

        let sock_path_buf = sock_path.to_path_buf();
        let running_clone = running.clone();

        eprintln!("[socket] Listening on {:?} (non-blocking)", sock_path);

        let handle = thread::spawn(move || {
            Self::accept_loop(listener, process_manager, bpf_manager, running_clone);
        });

        Ok(SocketServer {
            sock_path: sock_path_buf,
            running,
            handle: Some(handle),
        })
    }

    fn accept_loop(
        listener: UnixListener,
        process_manager: Arc<Mutex<ProcessManager>>,
        bpf_manager: Arc<BpfManager>,
        running: Arc<AtomicBool>,
    ) {
        while running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    // Peer authentication: only admit a client running as the
                    // daemon's own uid (the orchestrator). Reject anyone else
                    // (e.g. a sandboxed agent) before handing off the stream.
                    if !Self::authorized_peer(&stream) {
                        eprintln!("[socket] Rejected unauthorized peer");
                        continue;
                    }
                    eprintln!("[socket] New connection accepted");
                    let pm = process_manager.clone();
                    let bpf = bpf_manager.clone();
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_conn(stream, pm, bpf) {
                            eprintln!("[socket] Connection handler error: {}", e);
                        }
                    });
                }
                // Timeout is expected — just loop back and check running flag
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                           || e.kind() == std::io::ErrorKind::TimedOut => {
                    continue;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => {
                    eprintln!("[socket] Accept error: {}", e);
                    // Don't break! Log and retry — transient errors should not
                    // permanently kill the accept loop.
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        eprintln!("[socket] Accept loop exiting");
    }

    /// Verify the connecting peer via SO_PEERCRED and only admit a process
    /// running as the daemon's own effective uid (the orchestrator). Any other
    /// uid (e.g. a sandboxed agent) is rejected. Fails closed on any error.
    fn authorized_peer(stream: &UnixStream) -> bool {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            eprintln!("[socket] SO_PEERCRED failed; rejecting peer");
            return false;
        }
        let self_uid = unsafe { libc::geteuid() };
        if cred.uid != self_uid {
            eprintln!(
                "[socket] Reject peer uid={} pid={} != daemon uid={}",
                cred.uid, cred.pid, self_uid
            );
            return false;
        }
        true
    }

    fn handle_conn(
        stream: UnixStream,
        process_manager: Arc<Mutex<ProcessManager>>,
        bpf_manager: Arc<BpfManager>,
    ) -> Result<()> {
        let reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Client closed the connection — normal exit
                    break;
                }
                Err(e) => return Err(e.into()),
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            eprintln!("[socket] Received: {}", trimmed);

            let req: Request = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    let resp = Response {
                        status: "error".into(),
                        message: Some(format!("invalid JSON: {}", e)),
                        frozen: None,
                        pids: None,
                    };
                    let resp_str = serde_json::to_string(&resp)?;
                    writeln!(writer, "{}", resp_str)?;
                    writer.flush()?;
                    continue;
                }
            };

            eprintln!("[socket] Handling action: {}", req.action);
            let resp = Self::handle_request(&req, &process_manager, &bpf_manager);
            let resp_str = serde_json::to_string(&resp)?;
            eprintln!("[socket] Sending response: {}", resp_str);
            writeln!(writer, "{}", resp_str)?;
            writer.flush()?;
            eprintln!("[socket] Response flushed");
        }

        eprintln!("[socket] Connection closed by client");
        Ok(())
    }

    fn handle_request(
        req: &Request,
        process_manager: &Arc<Mutex<ProcessManager>>,
        bpf_manager: &Arc<BpfManager>,
    ) -> Response {
        match req.action.as_str() {
            "add_cgroup" => {
                let Some(path) = &req.cgroup_path else {
                    return Response {
                        status: "error".into(),
                        message: Some("cgroup_path required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                if !cgroup_path_ok(path) {
                    return Response {
                        status: "error".into(),
                        message: Some(format!(
                            "refused cgroup_path outside managed root: {}", path)),
                        frozen: None,
                        pids: None,
                    };
                }
                match bpf_manager.add_cgroup(Path::new(path)) {
                    Ok(_) => Response {
                        status: "ok".into(),
                        message: None,
                        frozen: None,
                        pids: None,
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "remove_cgroup" => {
                let Some(path) = &req.cgroup_path else {
                    return Response {
                        status: "error".into(),
                        message: Some("cgroup_path required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                if !cgroup_path_ok(path) {
                    return Response {
                        status: "error".into(),
                        message: Some(format!(
                            "refused cgroup_path outside managed root: {}", path)),
                        frozen: None,
                        pids: None,
                    };
                }
                match bpf_manager.remove_cgroup(Path::new(path)) {
                    Ok(_) => Response {
                        status: "ok".into(),
                        message: None,
                        frozen: None,
                        pids: None,
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "list_all_frozen" => {
                let pm = process_manager.lock().unwrap();
                let frozen: Vec<FrozenInfo> = pm.list_frozen().iter().map(|p| FrozenInfo {
                    pid: p.pid,
                    tgid: p.tgid,
                    comm: p.comm.clone(),
                    cgroup: p.cgroup_path.clone(),
                    event_type: format!("{}", p.event.event_type_enum()),
                    syscall: p.event.syscall_name().to_string(),
                }).collect();
                Response {
                    status: "ok".into(),
                    message: None,
                    frozen: Some(frozen),
                    pids: None,
                }
            }

            "list_frozen" => {
                let Some(cgroup_id) = &req.cgroup_id else {
                    return Response {
                        status: "error".into(),
                        message: Some("cgroup_id required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let pm = process_manager.lock().unwrap();
                let frozen: Vec<FrozenInfo> = pm.list_frozen_by_cgroup(cgroup_id).iter().map(|p| FrozenInfo {
                    pid: p.pid,
                    tgid: p.tgid,
                    comm: p.comm.clone(),
                    cgroup: p.cgroup_path.clone(),
                    event_type: format!("{}", p.event.event_type_enum()),
                    syscall: p.event.syscall_name().to_string(),
                }).collect();
                Response {
                    status: "ok".into(),
                    message: None,
                    frozen: Some(frozen),
                    pids: None,
                }
            }

            "list_completed" => {
                let pm = process_manager.lock().unwrap();
                let filter_cgroup = req.cgroup_id.as_deref();
                let completed: Vec<FrozenInfo> = pm.list_frozen().iter()
                    .filter(|p| p.event.event_type == 8) // EVENT_EXIT_HOLD
                    .filter(|p| filter_cgroup.is_none_or(|cg| p.cgroup_path == cg))
                    .map(|p| FrozenInfo {
                        pid: p.pid,
                        tgid: p.tgid,
                        comm: p.comm.clone(),
                        cgroup: p.cgroup_path.clone(),
                        event_type: format!("{}", p.event.event_type_enum()),
                        syscall: p.event.syscall_name().to_string(),
                    }).collect();
                Response {
                    status: "ok".into(),
                    message: None,
                    frozen: Some(completed),
                    pids: None,
                }
            }

            "continue_by_cgroup" => {
                let Some(cgroup_id) = &req.cgroup_id else {
                    return Response {
                        status: "error".into(),
                        message: Some("cgroup_id required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.continue_by_cgroup(cgroup_id) {
                    Ok(pids) => Response {
                        status: "ok".into(),
                        message: None,
                        frozen: None,
                        pids: Some(pids),
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "kill_by_cgroup" => {
                let Some(cgroup_id) = &req.cgroup_id else {
                    return Response {
                        status: "error".into(),
                        message: Some("cgroup_id required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.kill_by_cgroup(cgroup_id) {
                    Ok(pids) => Response {
                        status: "ok".into(),
                        message: None,
                        frozen: None,
                        pids: Some(pids),
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "continue_pid" => {
                let Some(pid) = req.pid else {
                    return Response {
                        status: "error".into(),
                        message: Some("pid required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.continue_process(pid) {
                    Ok(()) => Response {
                        status: "ok".into(),
                        message: None,
                        frozen: None,
                        pids: None,
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "resume_pid" => {
                let Some(pid) = req.pid else {
                    return Response {
                        status: "error".into(),
                        message: Some("pid required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.resume_process(pid) {
                    Ok(()) => Response {
                        status: "ok".into(),
                        message: Some(format!("Resumed pid {} (will be intercepted again)", pid)),
                        frozen: None,
                        pids: None,
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            // Wake a speculative candidate WITHOUT granting any allow-map pass.
            // Unlike resume_pid (which sets allowed_pids=1, a permanent
            // per-epoch bypass), this is a plain SIGCONT: the candidate runs
            // ARMED, so its first external effect is intercepted and frozen.
            // This is the correct primitive for starting a candidate at the
            // input gate; full release only happens after finalization via
            // continue/commit (allowed_pids=2).
            "resume_candidate" => {
                let Some(pid) = req.pid else {
                    return Response {
                        status: "error".into(),
                        message: Some("pid required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.resume_candidate_raw(pid) {
                    Ok(()) => Response {
                        status: "ok".into(),
                        message: Some(format!("Resumed candidate {} armed (no allow pass)", pid)),
                        frozen: None,
                        pids: None,
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "kill_pid" => {
                let Some(pid) = req.pid else {
                    return Response {
                        status: "error".into(),
                        message: Some("pid required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.discard_process(pid) {
                    Ok(()) => Response {
                        status: "ok".into(),
                        message: None,
                        frozen: None,
                        pids: None,
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            // ═══════════════════════════════════════════════════════════
            // COW Memory Tracking commands
            // ═══════════════════════════════════════════════════════════

            "begin_speculative" => {
                // Epoch setup runs the slow ptrace clone injection WITHOUT the
                // ProcessManager lock held (phase 2), so concurrent clients and
                // the event loop are not blocked for its duration. Phase 1
                // (reserve) and phase 3 (finalize/abort) take the lock only
                // briefly.
                if let Some(cgroup_id) = &req.cgroup_id {
                    let reserved = {
                        let mut pm = process_manager.lock().unwrap();
                        pm.reserve_speculative_by_cgroup(cgroup_id)
                    };
                    // Inject each reserved baseline with the lock released.
                    let results: Vec<_> = reserved
                        .into_iter()
                        .map(|b| (b, ProcessManager::inject_speculative(b)))
                        .collect();
                    let mut candidates = Vec::new();
                    {
                        let mut pm = process_manager.lock().unwrap();
                        for (baseline, res) in results {
                            match res {
                                Ok((candidate, regs)) => {
                                    pm.finish_speculative(baseline, candidate, regs);
                                    candidates.push(candidate);
                                }
                                Err(e) => {
                                    pm.abort_speculative(baseline);
                                    eprintln!(
                                        "[socket] begin_speculative: inject failed for {}: {}",
                                        baseline, e
                                    );
                                }
                            }
                        }
                    }
                    Response {
                        status: "ok".into(),
                        message: Some(format!("COW tracking started for {} processes", candidates.len())),
                        frozen: None,
                        pids: Some(candidates),
                    }
                } else if let Some(pid) = req.pid {
                    // begin_speculative_unlocked runs reserve -> inject ->
                    // finish/abort internally, keeping the lock released during
                    // the slow ptrace clone injection.
                    match ProcessManager::begin_speculative_unlocked(process_manager, pid) {
                        Ok(candidate) => Response {
                            status: "ok".into(),
                            message: Some(format!(
                                "Epoch started for pid {}: froze it as pristine baseline, forked speculative candidate pid {} (the live process for this epoch)",
                                pid, candidate
                            )),
                            frozen: None,
                            pids: Some(vec![candidate]),
                        },
                        Err(e) => Response {
                            status: "error".into(),
                            message: Some(e.to_string()),
                            frozen: None,
                            pids: None,
                        },
                    }
                } else {
                    Response {
                        status: "error".into(),
                        message: Some("cgroup_id or pid required".into()),
                        frozen: None,
                        pids: None,
                    }
                }
            }

            // One-shot speculative fork: freeze the target, inject a COW clone,
            // and wake the candidate with a plain SIGCONT — all in a single
            // call. Deliberately does NOT touch the eBPF allow maps: the
            // candidate is a fresh tgid armed by default and frozen at a
            // non-intercepted boundary, so it needs no allow-pass; its later
            // intercepted syscalls are caught normally. The baseline stays
            // frozen as the pristine rollback copy. Collapses the old
            // freeze_by_cgroup -> begin_speculative -> resume_pid sequence.
            "spec_fork" => {
                let Some(pid) = req.pid else {
                    return Response {
                        status: "error".into(),
                        message: Some("pid required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                // Phase 1 (locked): SIGSTOP + register the target as frozen so
                // the injection has a stopped boundary and register_candidate
                // can build the candidate's frozen record.
                if let Err(e) = { process_manager.lock().unwrap().freeze_pid(pid) } {
                    return Response {
                        status: "error".into(),
                        message: Some(format!("spec_fork freeze failed: {}", e)),
                        frozen: None,
                        pids: None,
                    };
                }
                // Phase 2 (self-locking): the slow ptrace clone injection.
                match ProcessManager::begin_speculative_unlocked(process_manager, pid) {
                    Ok(candidate) => {
                        // Phase 3 (locked): wake the candidate with a raw
                        // SIGCONT, no eBPF allow maps touched.
                        let mut pm = process_manager.lock().unwrap();
                        match pm.resume_candidate_raw(candidate) {
                            Ok(()) => Response {
                                status: "ok".into(),
                                message: Some(format!(
                                    "spec_fork: froze baseline pid {}, forked candidate pid {} and resumed it (no eBPF allow)",
                                    pid, candidate
                                )),
                                frozen: None,
                                pids: Some(vec![candidate]),
                            },
                            Err(e) => Response {
                                status: "error".into(),
                                message: Some(format!(
                                    "spec_fork: candidate {} forked but resume failed: {}",
                                    candidate, e
                                )),
                                frozen: None,
                                pids: Some(vec![candidate]),
                            },
                        }
                    }
                    Err(e) => {
                        // Injection failed: unfreeze the baseline we stopped, so
                        // this one-shot command leaves no stuck frozen process.
                        let _ = process_manager.lock().unwrap().resume_candidate_raw(pid);
                        Response {
                            status: "error".into(),
                            message: Some(format!("spec_fork inject failed: {}", e)),
                            frozen: None,
                            pids: None,
                        }
                    }
                }
            }

            "commit_by_cgroup" => {
                let Some(cgroup_id) = &req.cgroup_id else {
                    return Response {
                        status: "error".into(),
                        message: Some("cgroup_id required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.commit_by_cgroup(cgroup_id) {
                    Ok(pids) => Response {
                        status: "ok".into(),
                        message: Some(format!("Committed {} processes", pids.len())),
                        frozen: None,
                        pids: Some(pids),
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "commit_pid" => {
                let Some(pid) = req.pid else {
                    return Response {
                        status: "error".into(),
                        message: Some("pid required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.commit_process(pid) {
                    Ok(()) => Response {
                        status: "ok".into(),
                        message: Some(format!("Committed pid {}", pid)),
                        frozen: None,
                        pids: None,
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "reject_pid" => {
                let Some(pid) = req.pid else {
                    return Response {
                        status: "error".into(),
                        message: Some("pid required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.reject_to_checkpoint(pid) {
                    Ok(baseline) => Response {
                        status: "ok".into(),
                        message: Some(format!(
                            "Rolled back epoch for pid {}: discarded speculative candidate, resumed pristine baseline pid {} as canonical",
                            pid, baseline
                        )),
                        frozen: None,
                        // pids[0] is the canonical pid the caller tracks from now
                        // on (the original baseline, resumed unchanged).
                        pids: Some(vec![baseline]),
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "reject_by_cgroup" => {
                let Some(cgroup_id) = &req.cgroup_id else {
                    return Response {
                        status: "error".into(),
                        message: Some("cgroup_id required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.reject_by_cgroup(cgroup_id) {
                    Ok(pids) => Response {
                        status: "ok".into(),
                        message: Some(format!(
                            "Rolled back {} speculative epoch(s): discarded candidates (and their descendants), resumed pristine baselines",
                            pids.len()
                        )),
                        frozen: None,
                        // pids are the resumed baseline pids, canonical from now on.
                        pids: Some(pids),
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            "freeze_by_cgroup" => {
                let Some(cgroup_id) = &req.cgroup_id else {
                    return Response {
                        status: "error".into(),
                        message: Some("cgroup_id required".into()),
                        frozen: None,
                        pids: None,
                    };
                };
                let mut pm = process_manager.lock().unwrap();
                match pm.freeze_by_cgroup(cgroup_id) {
                    Ok(pids) => Response {
                        status: "ok".into(),
                        message: Some(format!("Froze {} processes", pids.len())),
                        frozen: None,
                        pids: Some(pids),
                    },
                    Err(e) => Response {
                        status: "error".into(),
                        message: Some(e.to_string()),
                        frozen: None,
                        pids: None,
                    },
                }
            }

            _ => Response {
                status: "error".into(),
                message: Some(format!("unknown action: {}", req.action)),
                frozen: None,
                pids: None,
            },
        }
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        eprintln!("[socket] Stopping socket server ({:?})", self.sock_path);
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.sock_path);
    }
}
