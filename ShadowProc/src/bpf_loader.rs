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
    /// Raw fd of allowed_pids map
    allowed_pids_fd: i32,
    /// Raw fd of cgroup_map
    cgroup_map_fd: i32,
    /// Raw fd of cgroup_count map
    cgroup_count_fd: i32,
    /// Raw fd of cow_enabled map
    cow_enabled_fd: i32,
    /// cgroup_map slot bookkeeping (add/remove with index recycling).
    cgroup_slots: Mutex<CgroupSlots>,
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
        let allowed_pids_fd = skel.maps().allowed_pids().as_fd().as_raw_fd();
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
            allowed_pids_fd,
            cgroup_map_fd,
            cgroup_count_fd,
            cow_enabled_fd,
            cgroup_slots: Mutex::new(CgroupSlots {
                used: HashMap::new(),
                by_path: HashMap::new(),
                free: Vec::new(),
                high_water: 0,
            }),
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

    /// Allow a process to pass all future interception, then remove from stopped list.
    /// MUST be called before SIGCONT.
    /// Flow: add to allowed_pids → delete from stopped_pids → SIGCONT
    ///       → kernel restarts syscall → hook sees allowed → passes through
    pub fn clear_stopped(&self, tgid: u32) -> Result<()> {
        let key_bytes = tgid.to_ne_bytes();
        let val: u32 = 1;
        let val_bytes = val.to_ne_bytes();

        // 1. Add to allowed_pids (so restarted syscall passes through)
        unsafe {
            libc_bpf_map_update_elem(
                self.allowed_pids_fd,
                key_bytes.as_ptr() as *const _,
                val_bytes.as_ptr() as *const _,
            );
        }

        // 2. Remove from stopped_pids
        unsafe {
            libc_bpf_map_delete_elem(self.stopped_pids_fd, key_bytes.as_ptr() as *const _);
        }

        Ok(())
    }

    /// Fully release a tgid: like `clear_stopped`, but marks allowed_pids with
    /// value 2 instead of 1. Value 2 means EVEN the exit-hold sentinel
    /// (192.0.2.255:65535) is let through, so the process can run to completion
    /// and actually exit. A normal `clear_stopped` (value 1) still stops the
    /// process at its exit-hold sentinel. Used by continue/commit paths.
    /// Flow: set allowed_pids=2 → delete from stopped_pids → caller SIGCONTs.
    pub fn clear_stopped_full(&self, tgid: u32) -> Result<()> {
        let key_bytes = tgid.to_ne_bytes();
        let val: u32 = 2;
        let val_bytes = val.to_ne_bytes();

        unsafe {
            libc_bpf_map_update_elem(
                self.allowed_pids_fd,
                key_bytes.as_ptr() as *const _,
                val_bytes.as_ptr() as *const _,
            );
        }
        unsafe {
            libc_bpf_map_delete_elem(self.stopped_pids_fd, key_bytes.as_ptr() as *const _);
        }

        Ok(())
    }

    /// Re-arm interception for a tgid at an epoch boundary by removing its
    /// PERMANENT allow_pids entry. After this, the tgid's next interceptable
    /// syscall is caught again.
    ///
    /// This is the counterpart of `clear_stopped`'s permanent allow: resume /
    /// commit grant a permanent pass so the process runs the whole epoch
    /// uninterrupted (per-epoch, not per-syscall, granularity); this call, made
    /// when a NEW epoch begins, revokes that pass so the process is guarded
    /// again. A freshly cloned candidate has a new tgid and is armed by default,
    /// so re-arming mainly matters for a pid reused as a new epoch's baseline.
    pub fn rearm_intercept(&self, tgid: u32) -> Result<()> {
        let key_bytes = tgid.to_ne_bytes();
        unsafe {
            libc_bpf_map_delete_elem(self.allowed_pids_fd, key_bytes.as_ptr() as *const _);
        }
        Ok(())
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
