use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapFlags, RingBufferBuilder};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
    /// Number of registered cgroups
    cgroup_next_idx: AtomicU32,
    /// Keep cgroup fds alive
    cgroup_fds: Mutex<Vec<File>>,
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
            cgroup_next_idx: AtomicU32::new(0),
            cgroup_fds: Mutex::new(Vec::new()),
        };

        // Add initial cgroup if provided
        if let Some(path) = cgroup_path {
            manager.add_cgroup(path)?;
        }

        Ok(manager)
    }

    /// Add a cgroup to the monitored set. Returns the index assigned.
    pub fn add_cgroup(&self, cgroup_path: &Path) -> Result<u32> {
        let cgroup_fd = File::open(cgroup_path)
            .with_context(|| format!("Failed to open cgroup path: {:?}", cgroup_path))?;

        let idx = self.cgroup_next_idx.fetch_add(1, Ordering::SeqCst);
        if idx >= 64 {
            self.cgroup_next_idx.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("Maximum 64 cgroups supported");
        }

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

        // Update cgroup_count[0] = idx + 1
        let count_key: u32 = 0;
        let count_val = idx + 1;
        unsafe {
            libc_bpf_map_update_elem(
                self.cgroup_count_fd,
                count_key.to_ne_bytes().as_ptr() as *const _,
                count_val.to_ne_bytes().as_ptr() as *const _,
            );
        }

        // Keep the fd alive
        self.cgroup_fds.lock().unwrap().push(cgroup_fd);

        eprintln!("[+] Added cgroup {:?} at index {}", cgroup_path, idx);
        Ok(idx)
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

    /// Resume a process (clear stopped state) WITHOUT permanently allowing it.
    /// The process can be intercepted again on future syscalls.
    /// Used for speculative execution where we need multiple freeze/resume cycles.
    ///
    /// Strategy: temporarily add to allowed_pids (so the restarted -ERESTARTSYS syscall
    /// passes through), then remove from allowed_pids after 100ms so future syscalls
    /// (like connect()) are intercepted again.
    pub fn clear_stopped_only(&self, tgid: u32) -> Result<()> {
        let key_bytes = tgid.to_ne_bytes();

        unsafe {
            // Step 1: Add to allowed_pids temporarily (lets restarted syscall pass)
            let val: u32 = 1;
            let val_bytes = val.to_ne_bytes();
            libc_bpf_map_update_elem(
                self.allowed_pids_fd,
                key_bytes.as_ptr() as *const _,
                val_bytes.as_ptr() as *const _,
            );

            // Step 2: Remove from stopped_pids
            libc_bpf_map_delete_elem(self.stopped_pids_fd, key_bytes.as_ptr() as *const _);
        }

        // Step 3: Schedule removal from allowed_pids after a brief delay
        // (enough time for the restarted syscall to pass through)
        let allowed_fd = self.allowed_pids_fd;
        let key_copy = tgid;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let key_bytes = key_copy.to_ne_bytes();
            unsafe {
                libc_bpf_map_delete_elem(allowed_fd, key_bytes.as_ptr() as *const _);
            }
            eprintln!("[bpf] Removed pid {} from allowed_pids (re-enabling interception)", key_copy);
        });

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
