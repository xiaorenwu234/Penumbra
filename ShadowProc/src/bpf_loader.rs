use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapFlags, RingBufferBuilder};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::sync::Mutex;

#[path = "bpf/shadow_proc.skel.rs"]
mod shadow_proc_skel;

use shadow_proc_skel::*;

use crate::event_handler::InterceptEvent;

/// Key for the operation policy BPF hash map.
/// Matches `struct class_policy_key` in shadow_proc.bpf.c.
#[repr(C)]
#[derive(Clone, Copy)]
struct ClassPolicyKey {
    cgroup_id: u64,
    effect_class: u8,
    operation: u8,
}

/// Value for the restart_token BPF hash map.
/// Matches `struct restart_token_val` in shadow_proc.bpf.c.
#[repr(C)]
struct RestartTokenVal {
    syscall_nr: u32,
    effect_class: u8,
    operation: u8,
    _pad0: [u8; 2],
}

/// Key for the network_policy BPF hash map.
/// Matches `struct net_policy_key` in shadow_proc.bpf.c.
/// addr/port are HOST order; 0 is the wildcard at that position.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetPolicyKey {
    pub cgroup_id: u64,
    pub family: u8,
    pub operation: u8,
    pub port: u16,
    pub addr: u32,
}

/// Key for the ipc_policy BPF hash map.
/// Matches `struct ipc_policy_key` in shadow_proc.bpf.c.
/// target 0 is the per-ipc_type wildcard.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpcPolicyKey {
    pub cgroup_id: u64,
    pub ipc_type: u8,
    pub operation: u8,
    pub _pad0: [u8; 6],
    pub target: u64,
}

/// Key for the signal_policy BPF hash map.
/// Matches `struct sig_policy_key` in shadow_proc.bpf.c.
/// target_cgroup 0 is the any-target wildcard.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigPolicyKey {
    pub cgroup_id: u64,
    pub operation: u8,
    pub _pad0: [u8; 7],
    pub target_cgroup: u64,
}

/// One fine-grained network endpoint entry (host-order addr/port;
/// 0 is the wildcard at that position).
#[derive(Debug, Clone, Copy)]
pub struct NetPolicyEntry {
    pub operation: u8,
    pub family: u8,
    pub addr: u32,
    pub port: u16,
    pub allow: u8,
}

/// One fine-grained IPC entry (ipc_type: IPC_TYPE_* from the BPF side;
/// target 0 = any target of that type).
#[derive(Debug, Clone, Copy)]
pub struct IpcPolicyEntry {
    pub operation: u8,
    pub ipc_type: u8,
    pub target: u64,
    pub allow: u8,
}

/// One fine-grained signal entry (target_cgroup 0 = any target).
#[derive(Debug, Clone, Copy)]
pub struct SigPolicyEntry {
    pub operation: u8,
    pub target_cgroup: u64,
    pub allow: u8,
}

/// Operation-aware process-layer policy for one cgroup (P0-5).
/// classes: (effect_class, operation, mode) — mode 1 = operation-wide allow,
/// mode 2 = fine-grained (the per-endpoint maps decide, default-deny).
#[derive(Debug, Clone, Default)]
pub struct ProcPolicy {
    pub classes: Vec<(u8, u8, u8)>,
    pub network: Vec<NetPolicyEntry>,
    pub ipc: Vec<IpcPolicyEntry>,
    pub signal: Vec<SigPolicyEntry>,
}

/// Fine-grained keys installed for a cgroup, tracked so clear_all_policies()
/// can delete them (BPF hash maps have no "delete by prefix" operation).
#[derive(Default)]
struct FinePolicyKeys {
    net: Vec<NetPolicyKey>,
    ipc: Vec<IpcPolicyKey>,
    sig: Vec<SigPolicyKey>,
}

fn all_policy_operations() -> Vec<(u8, Vec<u8>)> {
    use crate::policy_generated::*;
    vec![
        (CLASS_FILESYSTEM, vec![
            OP_READ, OP_WRITE, OP_CREATE, OP_DELETE, OP_RENAME, OP_LINK,
            OP_SYMLINK, OP_TRUNCATE, OP_CHMOD, OP_CHOWN, OP_MKDIR, OP_RMDIR,
        ]),
        (CLASS_NETWORK, vec![OP_CONNECT, OP_BIND, OP_SEND]),
        (CLASS_IPC, vec![
            OP_PIPE_WRITE, OP_UNIX_WRITE, OP_SYSV_SHM, OP_SYSV_MSG,
            OP_SYSV_SEM, OP_POSIX_MQ, OP_SHARED_MAPPING,
        ]),
        (CLASS_SIGNAL, vec![OP_KILL, OP_PTRACE]),
        (CLASS_PRIVILEGE, vec![
            OP_EXEC_PRIV, OP_SETUID, OP_SETGID, OP_SETGROUPS, OP_CAPSET,
        ]),
        (CLASS_OUTPUT, vec![OP_WRITE_OUT, OP_SENDFILE, OP_SPLICE, OP_IO_URING]),
        (CLASS_SYSTEM, vec![
            OP_MOUNT, OP_NAMESPACE, OP_KEYRING, OP_BPF, OP_PERF,
            OP_TTY_IOCTL, OP_PROCESS_VM,
        ]),
    ]
}

/// Raw bpf() syscall wrapper for MAP_DELETE_ELEM
unsafe fn libc_bpf_map_delete_elem(map_fd: i32, key: *const std::ffi::c_void) -> i64 {
    #[repr(C)]
    struct BpfAttrMapElem {
        map_fd: u32,
        _pad0: u32,
        key: u64,
        value_or_next: u64,
        flags: u64,
    }
    let attr = BpfAttrMapElem {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: key as u64,
        value_or_next: 0,
        flags: 0,
    };
    libc::syscall(
        321i64, // __NR_bpf on x86_64
        3i64,   // BPF_MAP_DELETE_ELEM
        &attr as *const _ as i64,
        std::mem::size_of::<BpfAttrMapElem>() as i64,
    )
}

/// Raw bpf() syscall wrapper for MAP_UPDATE_ELEM
unsafe fn libc_bpf_map_update_elem(
    map_fd: i32,
    key: *const std::ffi::c_void,
    value: *const std::ffi::c_void,
) -> i64 {
    #[repr(C)]
    struct BpfAttrMapElem {
        map_fd: u32,
        _pad0: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let attr = BpfAttrMapElem {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: key as u64,
        value: value as u64,
        flags: 0, // BPF_ANY
    };
    libc::syscall(
        321i64, // __NR_bpf
        2i64,   // BPF_MAP_UPDATE_ELEM
        &attr as *const _ as i64,
        std::mem::size_of::<BpfAttrMapElem>() as i64,
    )
}

/// Fail-closed variant of libc_bpf_map_update_elem: policy installation
/// must surface a failed map write instead of silently continuing (a lost
/// entry could turn a deny into an allow — or wedge a release mid-way).
unsafe fn bpf_map_update_checked(
    map_fd: i32,
    key: *const std::ffi::c_void,
    value: *const std::ffi::c_void,
) -> Result<()> {
    let ret = libc_bpf_map_update_elem(map_fd, key, value);
    if ret != 0 {
        anyhow::bail!(
            "BPF map update failed (fd {}): {}",
            map_fd,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Tracks cgroup_map slot allocation so cgroups can be added AND removed.
///
/// The old design used a monotonic index + append-only Vec of fds, so slots
/// were never reclaimed: a long-lived daemon serving many sessions would hit
/// the 64-slot cap and permanently fail add_cgroup. This recycles freed indices
/// and keeps the kernel-side cgroup_count at (highest occupied index + 1) so
/// check_cgroup() never scans dead slots.
struct CgroupSlots {
    /// idx -> open fd (kept alive so the kernel cgroup_map entry stays valid).
    used: HashMap<u32, File>,
    /// cgroup path -> idx, so a cgroup can be removed by path.
    by_path: HashMap<String, u32>,
    /// Freed indices, reused before growing high_water.
    free: Vec<u32>,
    /// Next never-used index.
    high_water: u32,
}

pub struct BpfManager {
    running: Arc<AtomicBool>,
    poll_thread: Option<thread::JoinHandle<()>>,
    /// Raw fd of stopped_pids map
    stopped_pids_fd: i32,
    /// Raw fd of epoch_mode map (Phase 2)
    epoch_mode_fd: i32,
    /// Raw fd of class_policy map (Phase 2)
    class_policy_fd: i32,
    /// Raw fd of network_policy map (fine-grained, P0-5)
    network_policy_fd: i32,
    /// Raw fd of ipc_policy map (fine-grained, P0-5)
    ipc_policy_fd: i32,
    /// Raw fd of signal_policy map (fine-grained, P0-5)
    signal_policy_fd: i32,
    /// Raw fd of restart_token map (Phase 2)
    restart_token_fd: i32,
    /// Raw fd of cgroup_map
    cgroup_map_fd: i32,
    /// Raw fd of cgroup_count map
    cgroup_count_fd: i32,
    /// Raw fd of cow_enabled map
    cow_enabled_fd: i32,
    /// cgroup_map slot bookkeeping (add/remove with index recycling).
    cgroup_slots: Mutex<CgroupSlots>,
    /// Fine-grained policy keys installed per cgroup (epoch-end cleanup).
    fine_keys: Mutex<HashMap<u64, FinePolicyKeys>>,
}

impl BpfManager {
    /// Load eBPF programs (LSM + fmod_ret) and start polling for events.
    /// If cgroup_path is provided, it's added as the first monitored cgroup.
    pub fn start(cgroup_path: Option<&Path>, event_tx: Sender<InterceptEvent>) -> Result<Self> {
        let skel_builder = ShadowProcSkelBuilder::default();
        let open_skel = skel_builder.open().context("Failed to open BPF skeleton")?;
        let mut skel = open_skel.load().context("Failed to load BPF programs")?;

        // Get map fds before moving skel into thread
        let stopped_pids_fd = skel.maps().stopped_pids().as_fd().as_raw_fd();
        let epoch_mode_fd = skel.maps().epoch_mode().as_fd().as_raw_fd();
        let class_policy_fd = skel.maps().class_policy().as_fd().as_raw_fd();
        let network_policy_fd = skel.maps().network_policy().as_fd().as_raw_fd();
        let ipc_policy_fd = skel.maps().ipc_policy().as_fd().as_raw_fd();
        let signal_policy_fd = skel.maps().signal_policy().as_fd().as_raw_fd();
        let restart_token_fd = skel.maps().restart_token().as_fd().as_raw_fd();
        let cgroup_map_fd = skel.maps().cgroup_map().as_fd().as_raw_fd();
        let cgroup_count_fd = skel.maps().cgroup_count().as_fd().as_raw_fd();
        let cow_enabled_fd = skel.maps().cow_enabled().as_fd().as_raw_fd();

        // Enable the interceptor
        let key: u32 = 0;
        let enabled: u32 = 1;
        skel.maps_mut()
            .config_map()
            .update(
                &key.to_ne_bytes(),
                &enabled.to_ne_bytes(),
                MapFlags::ANY,
            )
            .context("Failed to enable config")?;

        // Attach all programs (LSM + fmod_ret)
        skel.attach().context("Failed to attach BPF programs")?;

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        // Move everything into the polling thread
        let poll_thread = thread::spawn(move || {
            // Build ring buffer with event sender callback
            let tx = event_tx;
            let mut rb_builder = RingBufferBuilder::new();
            let maps = skel.maps();
            let events_map = maps.events();
            rb_builder
                .add(events_map, move |data| {
                    if data.len() >= std::mem::size_of::<InterceptEvent>() {
                        let event: InterceptEvent = unsafe {
                            std::ptr::read_unaligned(data.as_ptr() as *const InterceptEvent)
                        };
                        let _ = tx.send(event);
                    }
                    0
                })
                .expect("Failed to add ring buffer");

            let ring_buf = rb_builder.build().expect("Failed to build ring buffer");

            // Poll loop
            while running_clone.load(Ordering::Relaxed) {
                let _ = ring_buf.poll(Duration::from_millis(100));
            }

            // skel is dropped here, detaching programs
            drop(skel);
        });

        let manager = BpfManager {
            running,
            poll_thread: Some(poll_thread),
            stopped_pids_fd,
            epoch_mode_fd,
            class_policy_fd,
            network_policy_fd,
            ipc_policy_fd,
            signal_policy_fd,
            restart_token_fd,
            cgroup_map_fd,
            cgroup_count_fd,
            cow_enabled_fd,
            cgroup_slots: Mutex::new(CgroupSlots {
                used: HashMap::new(),
                by_path: HashMap::new(),
                free: Vec::new(),
                high_water: 0,
            }),
            fine_keys: Mutex::new(HashMap::new()),
        };

        // Add initial cgroup if provided
        if let Some(path) = cgroup_path {
            manager.add_cgroup(path)?;
        }

        Ok(manager)
    }

    /// Add a cgroup to the monitored set. Returns the index assigned.
    /// Idempotent: re-adding an already-registered path returns its existing
    /// index without consuming a new slot.
    pub fn add_cgroup(&self, cgroup_path: &Path) -> Result<u32> {
        let cgroup_fd = File::open(cgroup_path)
            .with_context(|| format!("Failed to open cgroup path: {:?}", cgroup_path))?;

        let path_key = cgroup_path.to_string_lossy().to_string();
        let mut slots = self.cgroup_slots.lock().unwrap();

        // Already registered -> return the existing index (idempotent).
        if let Some(&idx) = slots.by_path.get(&path_key) {
            return Ok(idx);
        }

        // Allocate a slot: reuse a freed index first, else grow the high-water
        // mark. Only the number of *live* cgroups is bounded by 64, not the
        // total ever added over the daemon's lifetime.
        let idx = if let Some(idx) = slots.free.pop() {
            idx
        } else {
            if slots.high_water >= 64 {
                anyhow::bail!("Maximum 64 concurrent cgroups supported");
            }
            let i = slots.high_water;
            slots.high_water += 1;
            i
        };

        // Update cgroup_map[idx] = cgroup_fd
        let key_bytes = idx.to_ne_bytes();
        let fd_bytes = cgroup_fd.as_raw_fd().to_ne_bytes();
        unsafe {
            libc_bpf_map_update_elem(
                self.cgroup_map_fd,
                key_bytes.as_ptr() as *const _,
                fd_bytes.as_ptr() as *const _,
            );
        }

        // Keep the fd alive (dropping it would invalidate the map entry).
        slots.used.insert(idx, cgroup_fd);
        slots.by_path.insert(path_key, idx);

        // Keep cgroup_count at (highest occupied index + 1).
        Self::sync_cgroup_count(self.cgroup_count_fd, &slots);

        eprintln!("[+] Added cgroup {:?} at index {}", cgroup_path, idx);
        Ok(idx)
    }

    /// Remove a previously-added cgroup from the monitored set, freeing its
    /// cgroup_map slot for reuse. This is what makes a long-lived daemon able to
    /// churn through an unbounded number of sessions without exhausting the
    /// 64-slot array. No-op error if the path was never registered.
    pub fn remove_cgroup(&self, cgroup_path: &Path) -> Result<()> {
        let path_key = cgroup_path.to_string_lossy().to_string();
        let mut slots = self.cgroup_slots.lock().unwrap();

        let idx = slots
            .by_path
            .remove(&path_key)
            .ok_or_else(|| anyhow::anyhow!("cgroup not registered: {:?}", cgroup_path))?;

        // Delete the kernel map entry, then drop the fd (closes it).
        let key_bytes = idx.to_ne_bytes();
        unsafe {
            libc_bpf_map_delete_elem(self.cgroup_map_fd, key_bytes.as_ptr() as *const _);
        }
        slots.used.remove(&idx); // drops File -> closes the held fd

        // Recycle the index and tighten cgroup_count so check_cgroup() stops
        // scanning past the highest live slot.
        slots.free.push(idx);
        Self::sync_cgroup_count(self.cgroup_count_fd, &slots);

        eprintln!("[+] Removed cgroup {:?} (freed index {})", cgroup_path, idx);
        Ok(())
    }

    /// Set cgroup_count[0] = (highest occupied index + 1), or 0 if none.
    /// Empty interior slots are safe: bpf_current_task_under_cgroup() on a
    /// deleted CGROUP_ARRAY entry returns an error (not 1), so check_cgroup()
    /// skips them.
    fn sync_cgroup_count(count_fd: i32, slots: &CgroupSlots) {
        let count: u32 = slots
            .used
            .keys()
            .copied()
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
        let count_key: u32 = 0;
        unsafe {
            libc_bpf_map_update_elem(
                count_fd,
                count_key.to_ne_bytes().as_ptr() as *const _,
                count.to_ne_bytes().as_ptr() as *const _,
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 2: Three-state model API
    // ═══════════════════════════════════════════════════════════════

    /// Remove the stopped_pids entry for a tgid (no allow pass granted).
    /// MUST be called before SIGCONT so the restarted syscall is not
    /// treated as an in-flight stop dedup.
    ///
    /// This replaces the old `clear_stopped` / `clear_stopped_full` which
    /// also set a PERMANENT allow in allowed_pids. In the three-state model,
    /// a resumed process is allowed via one-shot restart tokens
    /// (grant_restart_token) or ENFORCED-mode policy, NOT a permanent bypass.
    pub fn clear_stopped_mark(&self, tgid: u32) -> Result<()> {
        let key_bytes = tgid.to_ne_bytes();
        unsafe {
            libc_bpf_map_delete_elem(self.stopped_pids_fd, key_bytes.as_ptr() as *const _);
        }
        Ok(())
    }

    /// Grant a one-shot restart token for a tid + syscall_nr.
    ///
    /// When the thread with this tid next calls syscall_nr, check_policy()
    /// finds the token, CONSUMES it (deletes the entry), and returns
    /// DECISION_ALLOW. The token grants exactly ONE syscall pass — the
    /// next intercepted syscall is subject to the normal mode-based decision.
    ///
    /// This replaces the old permanent allowed_pids bypass with per-syscall
    /// granularity: only the specific authorized syscall passes.
    pub fn grant_restart_token(
        &self,
        tid: u32,
        syscall_nr: u32,
        effect_class: u8,
        operation: u8,
    ) -> Result<()> {
        let key_bytes = tid.to_ne_bytes();
        let val = RestartTokenVal {
            syscall_nr,
            effect_class,
            operation,
            _pad0: [0u8; 2],
        };
        unsafe {
            libc_bpf_map_update_elem(
                self.restart_token_fd,
                key_bytes.as_ptr() as *const _,
                &val as *const _ as *const _,
            );
        }
        Ok(())
    }

    /// Set the epoch mode for a cgroup.
    ///
    /// MODE_SPECULATIVE (default): fence all external effects.
    /// MODE_AUTHORIZED_PENDING: still fence (process not running).
    /// MODE_ENFORCED: consult policy maps; allow if policy permits, deny otherwise.
    pub fn set_epoch_mode(&self, cgroup_id: u64, mode: u8) -> Result<()> {
        let key_bytes = cgroup_id.to_ne_bytes();
        let val_bytes = mode.to_ne_bytes();
        unsafe {
            libc_bpf_map_update_elem(
                self.epoch_mode_fd,
                key_bytes.as_ptr() as *const _,
                val_bytes.as_ptr() as *const _,
            );
        }
        Ok(())
    }

    /// Install an operation-level policy entry: per (cgroup, effect_class, operation) -> allow/deny.
    /// Only consulted in MODE_ENFORCED. Default-deny: absent entry = deny.
    pub fn install_class_policy(
        &self,
        cgroup_id: u64,
        effect_class: u8,
        operation: u8,
        allow: u8,
    ) -> Result<()> {
        let key = ClassPolicyKey {
            cgroup_id,
            effect_class,
            operation,
        };
        unsafe {
            libc_bpf_map_update_elem(
                self.class_policy_fd,
                &key as *const _ as *const _,
                &allow as *const _ as *const _,
            );
        }
        Ok(())
    }

    /// Clear the epoch mode for a cgroup, resetting it to MODE_SPECULATIVE
    /// (the default when no entry exists). Called at epoch end.
    pub fn clear_epoch_mode(&self, cgroup_id: u64) -> Result<()> {
        let key_bytes = cgroup_id.to_ne_bytes();
        unsafe {
            libc_bpf_map_delete_elem(self.epoch_mode_fd, key_bytes.as_ptr() as *const _);
        }
        Ok(())
    }

    /// Clear a restart token for a tid (e.g., on reject/abort).
    pub fn clear_restart_token(&self, tid: u32) -> Result<()> {
        let key_bytes = tid.to_ne_bytes();
        unsafe {
            libc_bpf_map_delete_elem(self.restart_token_fd, key_bytes.as_ptr() as *const _);
        }
        Ok(())
    }

    /// Install allow-all operation policies for a cgroup and set ENFORCED mode.
    ///
    /// This is the equivalent of the old `clear_stopped_full` (permanent
    /// full release): it lets the process run to completion by allowing every
    /// operation in every effect class.
    pub fn enforce_allow_all(&self, cgroup_id: u64) -> Result<()> {
        for (cls, ops) in all_policy_operations() {
            for op in ops {
                self.install_class_policy(cgroup_id, cls, op, 1)?;
            }
        }
        self.set_epoch_mode(cgroup_id, crate::policy_generated::MODE_ENFORCED)?;
        Ok(())
    }

    /// Delete a single class_policy entry for a cgroup + effect_class + operation.
    pub fn clear_class_policy(&self, cgroup_id: u64, effect_class: u8, operation: u8) -> Result<()> {
        let key = ClassPolicyKey {
            cgroup_id,
            effect_class,
            operation,
        };
        unsafe {
            libc_bpf_map_delete_elem(self.class_policy_fd, &key as *const _ as *const _);
        }
        Ok(())
    }

    /// Install one fine-grained network policy entry (host-order addr/port;
    /// 0 is the wildcard at that position).
    pub fn install_net_policy(
        &self,
        cgroup_id: u64,
        operation: u8,
        family: u8,
        addr: u32,
        port: u16,
        allow: u8,
    ) -> Result<()> {
        let key = NetPolicyKey { cgroup_id, family, operation, port, addr };
        unsafe {
            bpf_map_update_checked(
                self.network_policy_fd,
                &key as *const _ as *const _,
                &allow as *const _ as *const _,
            )
        }
    }

    /// Install one fine-grained IPC policy entry (target 0 = any target).
    pub fn install_ipc_policy(
        &self,
        cgroup_id: u64,
        operation: u8,
        ipc_type: u8,
        target: u64,
        allow: u8,
    ) -> Result<()> {
        let key = IpcPolicyKey { cgroup_id, ipc_type, operation, _pad0: [0; 6], target };
        unsafe {
            bpf_map_update_checked(
                self.ipc_policy_fd,
                &key as *const _ as *const _,
                &allow as *const _ as *const _,
            )
        }
    }

    /// Install one fine-grained signal policy entry (target_cgroup 0 = any).
    pub fn install_signal_policy(
        &self,
        cgroup_id: u64,
        operation: u8,
        target_cgroup: u64,
        allow: u8,
    ) -> Result<()> {
        let key = SigPolicyKey { cgroup_id, operation, _pad0: [0; 7], target_cgroup };
        unsafe {
            bpf_map_update_checked(
                self.signal_policy_fd,
                &key as *const _ as *const _,
                &allow as *const _ as *const _,
            )
        }
    }

    /// Atomically install a full process-layer policy for a cgroup and switch
    /// it to MODE_ENFORCED (P0-5). Fine-grained endpoint entries are written
    /// first, class modes second, ENFORCED last; on ANY failure everything
    /// installed so far is rolled back and the epoch mode is reset, so a
    /// half-installed policy can never take effect.
    pub fn enforce_policy(&self, cgroup_id: u64, policy: &ProcPolicy) -> Result<()> {
        let mut keys = FinePolicyKeys::default();
        let mut classes_done: Vec<(u8, u8)> = Vec::new();
        let result = (|| -> Result<()> {
            for e in &policy.network {
                let key = NetPolicyKey {
                    cgroup_id, family: e.family, operation: e.operation,
                    port: e.port, addr: e.addr,
                };
                unsafe {
                    bpf_map_update_checked(
                        self.network_policy_fd,
                        &key as *const _ as *const _,
                        &e.allow as *const _ as *const _,
                    )?;
                }
                keys.net.push(key);
            }
            for e in &policy.ipc {
                let key = IpcPolicyKey {
                    cgroup_id, ipc_type: e.ipc_type, operation: e.operation,
                    _pad0: [0; 6], target: e.target,
                };
                unsafe {
                    bpf_map_update_checked(
                        self.ipc_policy_fd,
                        &key as *const _ as *const _,
                        &e.allow as *const _ as *const _,
                    )?;
                }
                keys.ipc.push(key);
            }
            for e in &policy.signal {
                let key = SigPolicyKey {
                    cgroup_id, operation: e.operation, _pad0: [0; 7],
                    target_cgroup: e.target_cgroup,
                };
                unsafe {
                    bpf_map_update_checked(
                        self.signal_policy_fd,
                        &key as *const _ as *const _,
                        &e.allow as *const _ as *const _,
                    )?;
                }
                keys.sig.push(key);
            }
            for &(cls, op, mode) in &policy.classes {
                let ckey = ClassPolicyKey { cgroup_id, effect_class: cls, operation: op };
                unsafe {
                    bpf_map_update_checked(
                        self.class_policy_fd,
                        &ckey as *const _ as *const _,
                        &mode as *const _ as *const _,
                    )?;
                }
                classes_done.push((cls, op));
            }
            self.set_epoch_mode(cgroup_id, crate::policy_generated::MODE_ENFORCED)?;
            Ok(())
        })();

        if let Err(e) = result {
            // Roll back to the pre-install state (fail-closed).
            for k in &keys.net {
                unsafe { libc_bpf_map_delete_elem(self.network_policy_fd, k as *const _ as *const _); }
            }
            for k in &keys.ipc {
                unsafe { libc_bpf_map_delete_elem(self.ipc_policy_fd, k as *const _ as *const _); }
            }
            for k in &keys.sig {
                unsafe { libc_bpf_map_delete_elem(self.signal_policy_fd, k as *const _ as *const _); }
            }
            for &(cls, op) in &classes_done {
                let _ = self.clear_class_policy(cgroup_id, cls, op);
            }
            let _ = self.clear_epoch_mode(cgroup_id);
            return Err(e);
        }

        // Track the installed keys so clear_all_policies() can delete them.
        let mut fine = self.fine_keys.lock().unwrap();
        let entry = fine.entry(cgroup_id).or_default();
        entry.net.extend(keys.net);
        entry.ipc.extend(keys.ipc);
        entry.sig.extend(keys.sig);
        Ok(())
    }

    /// Delete every tracked fine-grained policy key for a cgroup.
    pub fn clear_fine_policies(&self, cgroup_id: u64) -> Result<()> {
        let keys = {
            let mut fine = self.fine_keys.lock().unwrap();
            fine.remove(&cgroup_id).unwrap_or_default()
        };
        for k in &keys.net {
            unsafe { libc_bpf_map_delete_elem(self.network_policy_fd, k as *const _ as *const _); }
        }
        for k in &keys.ipc {
            unsafe { libc_bpf_map_delete_elem(self.ipc_policy_fd, k as *const _ as *const _); }
        }
        for k in &keys.sig {
            unsafe { libc_bpf_map_delete_elem(self.signal_policy_fd, k as *const _ as *const _); }
        }
        Ok(())
    }

    /// Clear all policies for a cgroup: reset epoch_mode to SPECULATIVE
    /// (default when no entry exists), delete all class_policy entries and
    /// every tracked fine-grained endpoint entry. Called at epoch boundaries
    /// to ensure a clean SPECULATIVE start.
    pub fn clear_all_policies(&self, cgroup_id: u64) -> Result<()> {
        self.clear_epoch_mode(cgroup_id)?;
        for (cls, ops) in all_policy_operations() {
            for op in ops {
                self.clear_class_policy(cgroup_id, cls, op)?;
            }
        }
        self.clear_fine_policies(cgroup_id)?;
        Ok(())
    }

    /// Resolve a cgroup path to its kernel cgroup_id (inode number).
    /// This is what bpf_get_current_cgroup_id() returns in BPF, and what
    /// the epoch_mode/class_policy maps are keyed by.
    pub fn cgroup_id_from_path(&self, cgroup_path: &str) -> Result<u64> {
        let path = if cgroup_path.starts_with('/') {
            format!("/sys/fs/cgroup{}", cgroup_path)
        } else {
            format!("/sys/fs/cgroup/{}", cgroup_path)
        };
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&path)
            .with_context(|| format!("Failed to stat cgroup path: {}", path))
            .map(|m| m.ino())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.poll_thread.take() {
            let _ = handle.join();
        }
    }

    /// Enable or disable COW auto-tracking for fork events in monitored cgroups.
    pub fn set_cow_enabled(&self, enabled: bool) -> Result<()> {
        let key: u32 = 0;
        let val: u32 = if enabled { 1 } else { 0 };
        unsafe {
            libc_bpf_map_update_elem(
                self.cow_enabled_fd,
                key.to_ne_bytes().as_ptr() as *const _,
                val.to_ne_bytes().as_ptr() as *const _,
            );
        }
        eprintln!("[+] COW fork auto-tracking: {}", if enabled { "enabled" } else { "disabled" });
        Ok(())
    }
}

impl Drop for BpfManager {
    fn drop(&mut self) {
        self.stop();
    }
}
