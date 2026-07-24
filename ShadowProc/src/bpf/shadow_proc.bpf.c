// SPDX-License-Identifier: GPL-2.0
// ShadowProc - eBPF process communication interceptor
//
// Architecture:
// - LSM hooks: intercept network, IPC, signal, ptrace (returns -ERESTARTSYS to block)
// - fmod_ret on ksys_write: intercept stdout/stderr/pipe writes (returns -ERESTARTSYS)
// - On interception: block syscall + SIGSTOP + notify userspace via ring buffer
// - On resume: userspace clears stopped_pids map entry, sends SIGCONT,
//   kernel auto-restarts syscall, this time hook allows it through
//
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// -ERESTARTSYS: kernel will auto-restart syscall after signal handling
#define ERESTARTSYS 512

// Event types
#define EVENT_NETWORK     1
#define EVENT_IPC         2
#define EVENT_WRITE_OUT   3
#define EVENT_SIGNAL      4
#define EVENT_PTRACE      5
#define EVENT_FORK        7
#define EVENT_EXIT_HOLD   8
#define EVENT_PRIV_EXEC   9   // Attempt to execute setuid/setgid binary
#define EVENT_PRIV_SETUID 10  // Attempt to change UID

// File types
#define S_IFIFO  0010000
#define S_IFSOCK 0140000
#define S_IFMT   0170000

struct event {
    __u32 pid;
    __u32 tgid;
    __u32 syscall_nr;
    __u32 event_type;
    __u64 timestamp;
    char comm[16];
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Cgroup array map for filtering (supports multiple cgroups)
struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} cgroup_map SEC(".maps");

// Tracks how many cgroups are registered
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cgroup_count SEC(".maps");

// Config map: enabled flag
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

// Tracks which tgids are currently stopped
// Key: tgid, Value: 1 = stopped
// Userspace MUST delete the entry before sending SIGCONT
//
// SIZING (applies to stopped_pids / allowed_pids below): 4096
// entries, keyed by tgid. Entries are reclaimed by the sched_process_exit hook
// when a tracked process dies, so steady-state occupancy tracks the number of
// live monitored tgids, not cumulative history. This bounds normal use well;
// a pathological workload that keeps >4096 monitored tgids resident at once
// could still saturate a map (update then fails fail-closed: interception is
// simply not armed for the overflow tgid). Raise max_entries if you expect to
// monitor that many concurrent process groups.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} stopped_pids SEC(".maps");

// Tracks which tgids are allowed to pass normal interception.
// Key: tgid. Value encodes HOW fully the process is released:
//   1 = normal permanent allow: normal syscalls pass, but the exit-hold
//       sentinel (192.0.2.255:65535) is STILL intercepted. Granted by resume.
//   2 = full release: even the exit-hold sentinel passes, so the process can
//       run to completion and exit. Granted by continue/commit.
// Interception is re-armed at the next epoch boundary by deleting the entry.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} allowed_pids SEC(".maps");

// Tracks which cgroups have COW auto-tracking enabled
// Key: 0, Value: 1 = enabled (all monitored cgroups auto-track forks)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cow_enabled SEC(".maps");

// Owner cgroup of each writable file-backed MAP_SHARED mapping, keyed by the
// inode pointer (stable while any mapping holds the inode alive). Used for
// same-epoch verification of shared memory (issue #5): a mapping is internal
// only if the SAME cgroup already owns the inode.
// NOTE (deferred): entries are not reclaimed on last-unmap / inode-free, so a
// reused inode pointer could carry a stale owner; runtime cleanup is future
// work. The first mapping is always fail-closed, bounding the residual risk.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} shared_map_owner SEC(".maps");

static __always_inline int check_cgroup(void)
{
    __u32 count_key = 0;
    __u32 *count = bpf_map_lookup_elem(&cgroup_count, &count_key);
    __u32 n = count ? *count : 0;
    if (n == 0)
        return 0;

    // Check each registered cgroup (up to 64)
    #pragma unroll
    for (__u32 i = 0; i < 64; i++) {
        if (i >= n)
            break;
        if (bpf_current_task_under_cgroup(&cgroup_map, i) == 1)
            return 1;
    }
    return 0;
}

static __always_inline int is_enabled(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&config_map, &key);
    if (!val)
        return 0;
    return *val == 1;
}

// Returns 1 if we should intercept this process
// Returns 0 if we should let it pass
static __always_inline int should_intercept(void)
{
    if (!is_enabled())
        return 0;
    if (!check_cgroup())
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // If process is in allowed list, always let it pass. This is a PERMANENT
    // pass granted at resume/commit time: the process runs the whole epoch
    // (and beyond) uninterrupted. Interception is re-armed at the next epoch
    // boundary by deleting this entry (see rearm_intercept in bpf_loader.rs),
    // giving per-epoch (not per-syscall) enforcement granularity.
    __u32 *allowed = bpf_map_lookup_elem(&allowed_pids, &tgid);
    if (allowed)
        return 0;

    // NOTE: we deliberately do NOT pass merely because stopped_pids is set.
    // A set mark means a group-directed SIGSTOP is already in flight for this
    // tgid, but its sibling threads keep running until the stop actually lands.
    // If such a sibling reaches an external syscall in that window and we
    // returned 0 (pass) here, its irreversible effect would ESCAPE the freeze.
    // Instead we still report "intercept": the hook proceeds to do_intercept(),
    // which recognises the in-flight stop, SKIPS the duplicate event/SIGSTOP,
    // and lets the caller return -ERESTARTSYS so the sibling's syscall is
    // BLOCKED and auto-restarted after resume. (The resume path sets
    // allowed_pids above, so a resumed process is passed there, not caught
    // here.)
    return 1;
}

// Like should_intercept(), but for the exit-hold sentinel connect. The sentinel
// is a cooperative "hold me at exit" marker, so it must fire even for a process
// that already holds a NORMAL permanent allow (allowed_pids == 1) from an
// earlier resume. Only a FULL release (allowed_pids == 2, granted by
// continue/commit) lets the sentinel pass so the process can finally exit.
// Still respects the enabled flag, cgroup membership, and the stopped mark
// (so an already-held process is not re-stopped on the syscall auto-restart).
static __always_inline int should_intercept_sentinel(void)
{
    if (!is_enabled())
        return 0;
    if (!check_cgroup())
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // Fully released (post continue/commit) -> let the sentinel pass.
    __u32 *allowed = bpf_map_lookup_elem(&allowed_pids, &tgid);
    if (allowed && *allowed == 2)
        return 0;

    // Like should_intercept(): do NOT pass merely because a stop is already in
    // flight. Returning 1 routes the sentinel through do_intercept(), which
    // dedups the in-flight stop (no second event/SIGSTOP) while the hook still
    // returns -ERESTARTSYS — keeping the process HELD at its exit boundary
    // instead of letting the sentinel slip past during the stop-propagation
    // window. Only a FULL release (allowed_pids == 2, checked above) lets the
    // sentinel through so the process can finally exit.
    return 1;
}

// Emit event + SIGSTOP + mark as stopped. Returns bpf_send_signal()'s result
// (0 on success). Callers still return -ERESTARTSYS regardless, so a failed
// stop is fail-closed: the syscall is auto-restarted and the stop is retried.
static __always_inline int do_intercept(__u32 syscall_nr, __u32 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 one = 1;

    // If the tgid is ALREADY marked stopped, a group-directed SIGSTOP is
    // already in flight (or in effect) for it. This call is therefore either a
    // SIBLING thread that reached an external syscall during the
    // stop-propagation window, or the initiating thread's own syscall being
    // re-entered before the (asynchronous, irq_work-delivered) SIGSTOP landed.
    // We must NOT emit a duplicate event or queue a second SIGSTOP (that would
    // storm userspace and the signal path), but we MUST still block it: the
    // caller returns -ERESTARTSYS unconditionally, so the syscall does not
    // execute and is restarted once the process is resumed. This is what closes
    // the window where a sibling's external syscall used to slip through while
    // the stop was still propagating.
    __u32 *already = bpf_map_lookup_elem(&stopped_pids, &tgid);
    if (already)
        return 0;

    // First hook to catch this tgid: mark it stopped BEFORE notifying/stopping
    // so any concurrent sibling hook takes the dedup path above.
    bpf_map_update_elem(&stopped_pids, &tgid, &one, BPF_ANY);

    // Emit event to userspace
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = pid_tgid & 0xFFFFFFFF;
        e->tgid = tgid;
        e->syscall_nr = syscall_nr;
        e->event_type = event_type;
        e->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    // SIGSTOP the process. If the signal could not be queued we must NOT leave
    // the tgid marked stopped: otherwise should_intercept() would treat a
    // never-stopped process as already handled and silently let its future
    // external syscalls through. Drop the mark so interception re-arms; the
    // caller still returns -ERESTARTSYS, so the kernel auto-restarts the syscall
    // and we retry the stop on the next pass (fail-closed).
    long ret = bpf_send_signal(19);
    if (ret != 0)
        bpf_map_delete_elem(&stopped_pids, &tgid);
    return (int)ret;
}

// ═══════════════════════════════════════════════════════════════
// Network address-family filtering + AF_UNIX system-socket whitelist
//
// SCOPE: only OUTBOUND association is intercepted (connect/bind/sendmsg).
// Inbound listen()/accept() are intentionally NOT hooked: the threat model is
// data leaving the sandbox, and an accepted inbound peer cannot itself carry
// data out until the sandboxed process writes to it — which is already covered
// by the write/sendmsg hooks. Add socket_listen/socket_accept hooks here if the
// model expands to inbound exposure.
//
// Intercept (external / irreversible):
//   - AF_INET / AF_INET6  (real remote IP AND loopback 127.0.0.1 / ::1)
//   - AF_UNIX / AF_LOCAL that is NOT a runtime system socket
//   - any other non-local family (AF_PACKET, ...)
// Exempt (not external):
//   - AF_UNSPEC (connect(AF_UNSPEC) just dissolves association)
//   - AF_NETLINK (peer is the kernel)
//   - AF_UNIX hitting the runtime system-socket prefix whitelist
// ═══════════════════════════════════════════════════════════════

#define AF_UNSPEC   0
#define AF_UNIX     1
#define AF_INET     2
#define AF_INET6    10
#define AF_NETLINK  16

#define SUN_PATH_OFF 2  // offsetof(struct sockaddr_un, sun_path)

// Compare buf against a compile-time literal prefix (longest whitelist prefix
// is "/var/run/avahi-daemon/" = 22 chars, so 24 iterations suffice).
#define HAS_PREFIX(buf, lit) __has_prefix((buf), (lit), sizeof(lit) - 1)
static __always_inline int __has_prefix(const char *buf, const char *pfx, int n)
{
    #pragma unroll
    for (int i = 0; i < 24; i++) {
        if (i >= n)
            return 1;  // all prefix chars matched
        if (buf[i] != pfx[i])
            return 0;
    }
    return 1;
}

// Returns 1 if the AF_UNIX sun_path is a runtime system socket (exempt).
// `path` points to the sun_path bytes (128-byte buffer).
static __always_inline int unix_path_whitelisted(const char *path)
{
    // Abstract namespace socket: sun_path[0] == '\0', name follows.
    // D-Bus abstract sockets look like @/tmp/dbus-XXXX .
    if (path[0] == '\0')
        return HAS_PREFIX(path + 1, "/tmp/dbus-");

    // Pathname sockets
    if (HAS_PREFIX(path, "/var/run/nscd/"))          return 1;  // NSS cache
    if (HAS_PREFIX(path, "/run/nscd/"))              return 1;
    if (HAS_PREFIX(path, "/var/run/dbus/"))          return 1;  // D-Bus
    if (HAS_PREFIX(path, "/run/dbus/"))              return 1;
    if (HAS_PREFIX(path, "@/tmp/dbus-"))             return 1;
    if (HAS_PREFIX(path, "/run/systemd/"))           return 1;  // systemd
    if (HAS_PREFIX(path, "/var/run/systemd/"))       return 1;
    if (HAS_PREFIX(path, "/var/lib/sss/"))           return 1;  // SSSD/winbind/samba
    if (HAS_PREFIX(path, "/run/sssd/"))              return 1;
    if (HAS_PREFIX(path, "/var/run/sssd/"))          return 1;
    if (HAS_PREFIX(path, "/var/run/samba/"))         return 1;
    if (HAS_PREFIX(path, "/run/samba/"))             return 1;
    if (HAS_PREFIX(path, "/var/lib/samba/"))         return 1;
    if (HAS_PREFIX(path, "/dev/log"))                return 1;  // syslog
    if (HAS_PREFIX(path, "/var/run/avahi-daemon/"))  return 1;  // avahi/mDNS
    if (HAS_PREFIX(path, "/run/avahi-daemon/"))      return 1;
    return 0;
}

// Classify a connect()/bind() target. Returns 1 if it should be intercepted.
// `address` is a kernel copy (sockaddr_storage, 128 bytes), safe to over-read.
static __always_inline int net_addr_should_block(struct sockaddr *address, int addrlen)
{
    __u16 family = 0;
    if (addrlen >= 2)
        bpf_probe_read_kernel(&family, sizeof(family), address);

    if (family == AF_UNSPEC || family == AF_NETLINK)
        return 0;  // exempt

    if (family == AF_UNIX) {
        char path[128] = {};
        // sun_path lives at offset 2 within the 128-byte storage.
        bpf_probe_read_kernel(path, 108, (char *)address + SUN_PATH_OFF);
        if (unix_path_whitelisted(path))
            return 0;  // system socket -> exempt
        return 1;
    }

    // AF_INET / AF_INET6 (incl. loopback) / any other external family
    return 1;
}

// ═══════════════════════════════════════════════════════════════
// LSM Hooks - Block syscall BEFORE execution, return -ERESTARTSYS
// so kernel auto-restarts after SIGCONT
// ═══════════════════════════════════════════════════════════════

// --- Network: connect ---
// Also detects exit-hold sentinel (192.0.2.255:65535) and tags as EVENT_EXIT_HOLD
SEC("lsm/socket_connect")
int BPF_PROG(shadow_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    // Check for exit-hold sentinel address FIRST: 192.0.2.255:65535.
    // This is a cooperative marker from libexithold.so (LD_PRELOAD) signalling
    // process completion. It is checked BEFORE should_intercept() so that it
    // fires even for a process holding a normal permanent allow (allowed_pids
    // == 1); only a full release (allowed_pids == 2) lets it pass. See
    // should_intercept_sentinel().
    if (addrlen >= 16) { // sizeof(struct sockaddr_in)
        __u16 family = 0;
        __u16 port = 0;
        __u32 ip = 0;
        bpf_probe_read_kernel(&family, 2, (void *)address);
        bpf_probe_read_kernel(&port, 2, (void *)address + 2);
        bpf_probe_read_kernel(&ip, 4, (void *)address + 4);
        // AF_INET=2, port=65535 (0xFFFF in network order), ip=192.0.2.255 (0xFF0200C0 on LE)
        if (family == 2 && port == 0xFFFF && ip == 0xFF0200C0) {
            if (should_intercept_sentinel()) {
                do_intercept(231, EVENT_EXIT_HOLD);
                return -ERESTARTSYS;
            }
            return 0;
        }
    }

    // General (non-sentinel) case: normal per-epoch enforcement.
    if (!should_intercept())
        return 0;

    // Classify by address family + AF_UNIX whitelist.
    if (net_addr_should_block(address, addrlen)) {
        do_intercept(42, EVENT_NETWORK);
        return -ERESTARTSYS;
    }
    return 0;
}

// --- Network: sendmsg (covers sendto, sendmsg) ---
SEC("lsm/socket_sendmsg")
int BPF_PROG(shadow_socket_sendmsg, struct socket *sock,
             struct msghdr *msg, int size)
{
    if (!should_intercept())
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u16 family = sk ? BPF_CORE_READ(sk, __sk_common.skc_family) : 0;

    if (family == AF_UNSPEC || family == AF_NETLINK)
        return 0;  // exempt

    if (family == AF_UNIX) {
        char path[128] = {};
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        int namelen = BPF_CORE_READ(msg, msg_namelen);

        if (msg_name && namelen > SUN_PATH_OFF) {
            // Unconnected datagram sendto(): explicit destination in msg_name.
            bpf_probe_read_kernel(path, 108, (char *)msg_name + SUN_PATH_OFF);
            if (unix_path_whitelisted(path))
                return 0;
        } else {
            // Connected AF_UNIX stream: recover the peer's bound path so the
            // whitelist still applies (e.g. writes to the D-Bus socket).
            struct sock *peer = BPF_CORE_READ((struct unix_sock *)sk, peer);
            struct unix_address *uaddr = NULL;
            if (peer)
                uaddr = BPF_CORE_READ((struct unix_sock *)peer, addr);
            if (!uaddr)
                uaddr = BPF_CORE_READ((struct unix_sock *)sk, addr);
            if (uaddr) {
                int alen = BPF_CORE_READ(uaddr, len);
                __u32 n = (alen > SUN_PATH_OFF) ? (__u32)(alen - SUN_PATH_OFF) : 0;
                n &= 127;  // bound for the verifier (path[128])
                bpf_probe_read_kernel(path, n,
                    (char *)uaddr + offsetof(struct unix_address, name) + SUN_PATH_OFF);
            }
            if (unix_path_whitelisted(path))
                return 0;
        }

        do_intercept(46, EVENT_NETWORK);
        return -ERESTARTSYS;
    }

    // AF_INET / AF_INET6 / other external family
    do_intercept(46, EVENT_NETWORK);
    return -ERESTARTSYS;
}

// --- Network: bind ---
SEC("lsm/socket_bind")
int BPF_PROG(shadow_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!should_intercept())
        return 0;
    if (net_addr_should_block(address, addrlen)) {
        do_intercept(49, EVENT_NETWORK);
        return -ERESTARTSYS;
    }
    return 0;
}

// ── SysV shared memory (shm) ──────────────────────────────────
// shmget: alloc_security fires when creating a new segment,
//         associate fires when attaching to an existing key.
// Together they cover every shmget() call.
SEC("lsm/shm_alloc_security")
int BPF_PROG(shadow_shm_alloc, struct kern_ipc_perm *perm)
{
    if (!should_intercept())
        return 0;
    do_intercept(29, EVENT_IPC); // 29 = shmget
    return -ERESTARTSYS;
}

SEC("lsm/shm_associate")
int BPF_PROG(shadow_shm_associate, struct kern_ipc_perm *perm, int shmflg)
{
    if (!should_intercept())
        return 0;
    do_intercept(29, EVENT_IPC); // 29 = shmget
    return -ERESTARTSYS;
}

// --- IPC: shmat ---
SEC("lsm/shm_shmat")
int BPF_PROG(shadow_shm_shmat, struct kern_ipc_perm *shp,
             char *shmaddr, int shmflg)
{
    if (!should_intercept())
        return 0;
    do_intercept(30, EVENT_IPC); // 30 = shmat
    return -ERESTARTSYS;
}

// --- IPC: shmctl ---
SEC("lsm/shm_shmctl")
int BPF_PROG(shadow_shm_shmctl, struct kern_ipc_perm *perm, int cmd)
{
    if (!should_intercept())
        return 0;
    do_intercept(31, EVENT_IPC); // 31 = shmctl
    return -ERESTARTSYS;
}

// --- IPC: mmap file-backed shared memory (POSIX shm via shm_open + mmap) ---
// Only file-backed, WRITABLE MAP_SHARED is treated as a cross-process channel.
// Anonymous MAP_SHARED (MAP_SHARED|MAP_ANONYMOUS) is parent-child sharing,
// which the spec explicitly EXEMPTS (like pipe/socketpair), so we skip it.
// mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
#define MAP_SHARED 0x01
#define PROT_WRITE 0x2
SEC("lsm/mmap_file")
int BPF_PROG(shadow_mmap_file, struct file *file,
             unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    if (!should_intercept())
        return 0;

    // Only intercept MAP_SHARED mappings
    if (!(flags & MAP_SHARED))
        return 0;

    // Anonymous shared mapping (file == NULL) = parent-child IPC -> EXEMPT
    if (!file)
        return 0;

    // Read-only shared file mappings are NOT a write/exfil channel and must be
    // exempt: the dynamic loader maps ld.so.cache / locale-archive / gconv cache
    // as PROT_READ|MAP_SHARED during process startup (e.g. every bash launch).
    // A POSIX shm IPC data channel has to be writable to carry data out, so we
    // only intercept writable shared mappings. (reqprot is what the caller asked
    // for; prot is the effective protection — OR them so neither can slip past.)
    if (!((reqprot | prot) & PROT_WRITE))
        return 0;

    // Same-epoch verification (issue #5): a writable file-backed MAP_SHARED is
    // internal only if another process in the SAME cgroup (epoch) already owns
    // this inode. The FIRST monitored mapping is fail-closed (intercepted)
    // because a host peer may already share the file; once it is authorized and
    // released, later same-cgroup mappers are exempt while a DIFFERENT cgroup
    // is still intercepted as a cross-epoch channel.
    struct inode *ino_p = BPF_CORE_READ(file, f_inode);
    if (!ino_p) {
        do_intercept(9, EVENT_IPC);
        return -ERESTARTSYS;
    }
    __u64 ino_key = (__u64)(unsigned long)ino_p;
    __u64 cur_cg = bpf_get_current_cgroup_id();
    __u64 *owner = bpf_map_lookup_elem(&shared_map_owner, &ino_key);
    if (owner) {
        if (*owner == cur_cg)
            return 0;  // same epoch -> internal shared memory, exempt
        // different cgroup -> cross-epoch shared mapping, fall through to block
    } else {
        // First monitored mapping: claim ownership for this cgroup, then block.
        bpf_map_update_elem(&shared_map_owner, &ino_key, &cur_cg, BPF_ANY);
    }
    do_intercept(9, EVENT_IPC); // 9 = mmap syscall number
    return -ERESTARTSYS;
}

// ── SysV message queues (msg) ─────────────────────────────────
// msgget: alloc_security (create) + associate (open existing)
SEC("lsm/msg_queue_alloc_security")
int BPF_PROG(shadow_msg_alloc, struct kern_ipc_perm *perm)
{
    if (!should_intercept())
        return 0;
    do_intercept(68, EVENT_IPC); // 68 = msgget
    return -ERESTARTSYS;
}

SEC("lsm/msg_queue_associate")
int BPF_PROG(shadow_msg_associate, struct kern_ipc_perm *perm, int msqflg)
{
    if (!should_intercept())
        return 0;
    do_intercept(68, EVENT_IPC); // 68 = msgget
    return -ERESTARTSYS;
}

// --- IPC: msg send ---
SEC("lsm/msg_queue_msgsnd")
int BPF_PROG(shadow_msg_msgsnd, struct kern_ipc_perm *msq,
             struct msg_msg *msg, int msqflg)
{
    if (!should_intercept())
        return 0;
    do_intercept(69, EVENT_IPC); // 69 = msgsnd
    return -ERESTARTSYS;
}

// --- IPC: msg receive ---
SEC("lsm/msg_queue_msgrcv")
int BPF_PROG(shadow_msg_msgrcv, struct kern_ipc_perm *msq,
             struct msg_msg *msg, struct task_struct *target,
             long type, int mode)
{
    if (!should_intercept())
        return 0;
    do_intercept(70, EVENT_IPC); // 70 = msgrcv
    return -ERESTARTSYS;
}

// --- IPC: msgctl ---
SEC("lsm/msg_queue_msgctl")
int BPF_PROG(shadow_msg_msgctl, struct kern_ipc_perm *perm, int cmd)
{
    if (!should_intercept())
        return 0;
    do_intercept(71, EVENT_IPC); // 71 = msgctl
    return -ERESTARTSYS;
}

// ── SysV semaphores (sem) ─────────────────────────────────────
// semget: alloc_security (create) + associate (open existing)
SEC("lsm/sem_alloc_security")
int BPF_PROG(shadow_sem_alloc, struct kern_ipc_perm *perm)
{
    if (!should_intercept())
        return 0;
    do_intercept(64, EVENT_IPC); // 64 = semget
    return -ERESTARTSYS;
}

SEC("lsm/sem_associate")
int BPF_PROG(shadow_sem_associate, struct kern_ipc_perm *perm, int semflg)
{
    if (!should_intercept())
        return 0;
    do_intercept(64, EVENT_IPC); // 64 = semget
    return -ERESTARTSYS;
}

// --- IPC: semop / semtimedop ---
SEC("lsm/sem_semop")
int BPF_PROG(shadow_sem_semop, struct kern_ipc_perm *perm,
             struct sembuf *sops, unsigned int nsops, int alter)
{
    if (!should_intercept())
        return 0;
    do_intercept(65, EVENT_IPC); // 65 = semop
    return -ERESTARTSYS;
}

// --- IPC: semctl ---
SEC("lsm/sem_semctl")
int BPF_PROG(shadow_sem_semctl, struct kern_ipc_perm *perm, int cmd)
{
    if (!should_intercept())
        return 0;
    do_intercept(66, EVENT_IPC); // 66 = semctl
    return -ERESTARTSYS;
}

// --- Signal: kill/tkill/tgkill to other processes ---
// Exempt signals that stay within the sender's own session:
//   - same thread group (self / sibling threads)  [fast path]
//   - any process in the same session (same PIDTYPE_SID struct pid).
//     A session subsumes the process group and covers siblings / cousins
//     that share the same session leader.
// Everything else (processes in other sessions) is intercepted.
SEC("lsm/task_kill")
int BPF_PROG(shadow_task_kill, struct task_struct *p,
             struct kernel_siginfo *info, int sig,
             const struct cred *cred)
{
    if (!should_intercept())
        return 0;

    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    __u32 my_tgid = BPF_CORE_READ(cur, tgid);
    __u32 target_tgid = BPF_CORE_READ(p, tgid);

    // 1. Same thread group (self or sibling thread) -> exempt (fast path)
    if (target_tgid == my_tgid)
        return 0;

    // 2. Same monitored cgroup (== same speculative epoch) -> exempt.
    // Tightened from the old same-session test (issue #5): a session can span
    // processes OUTSIDE this epoch's cgroup, so signalling them is an external
    // effect that must be fenced. Comparing the cgroup v2 id confines
    // "internal" to the epoch's own cgroup. self via the fast helper; target
    // via its default cgroup's kernfs id.
    __u64 my_cg = bpf_get_current_cgroup_id();
    __u64 tgt_cg = BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id);
    if (my_cg && my_cg == tgt_cg)
        return 0;

    do_intercept(62, EVENT_SIGNAL);
    return -ERESTARTSYS;
}

// --- Ptrace ---
SEC("lsm/ptrace_access_check")
int BPF_PROG(shadow_ptrace, struct task_struct *child, unsigned int mode)
{
    if (!should_intercept())
        return 0;
    do_intercept(101, EVENT_PTRACE);
    return -ERESTARTSYS;
}

// ═══════════════════════════════════════════════════════════════
// fmod_ret on ksys_write - intercept write to stdout/stderr/pipe
// fmod_ret runs BEFORE the function body; returning non-zero
// overrides the function return value (function does NOT execute)
// ═══════════════════════════════════════════════════════════════

SEC("fmod_ret/__x64_sys_write")
int BPF_PROG(shadow_sys_write, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;

    // Get fd from first argument (rdi on x86_64)
    unsigned long fd = PT_REGS_PARM1_CORE_SYSCALL(regs);

    // NOTE: stdout/stderr (fd 1/2) are NO LONGER intercepted.
    // They are redirected to a buffer file at launch time by cgroup_exec.
    // Only intercept writes to pipes/FIFOs/sockets (IPC detection).
    if (fd <= 2)
        return 0;

    // Check if fd is a pipe/FIFO/socket
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    // Reject fds beyond the process's actual fd-table capacity: indexing
    // fd_array[fd] past max_fds would read past the array and could
    // misclassify the fd. max_fds is the true size of the current table.
    // An fd we cannot inspect is treated as a possible pipe/socket carrying
    // data out, so we FAIL CLOSED (intercept) rather than pass.
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if (fd >= max_fds) {
        do_intercept(1, EVENT_WRITE_OUT);
        return -ERESTARTSYS;
    }

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return 0;

    // Above this constant bound the verifier cannot prove fd_array[fd] is in
    // range, so the fd type is un-inspectable. FAIL CLOSED (intercept): a high
    // fd may well be a pipe/socket exfil channel.
    if (fd > 1023) {
        do_intercept(1, EVENT_WRITE_OUT);
        return -ERESTARTSYS;
    }

    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);
    if (!f)
        return 0;

    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode)
        return 0;

    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    if ((mode & S_IFMT) == S_IFIFO || (mode & S_IFMT) == S_IFSOCK) {
        do_intercept(1, EVENT_WRITE_OUT);
        return -ERESTARTSYS;
    }

    return 0;
}

// Also intercept writev for completeness
SEC("fmod_ret/__x64_sys_writev")
int BPF_PROG(shadow_sys_writev, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;

    unsigned long fd = PT_REGS_PARM1_CORE_SYSCALL(regs);

    // NOTE: stdout/stderr (fd 1/2) are NO LONGER intercepted.
    if (fd <= 2)
        return 0;

    // Check pipe/socket (same logic as write)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    // Reject fds beyond the process's actual fd-table capacity (see write hook).
    // Un-inspectable fd => FAIL CLOSED (intercept).
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if (fd >= max_fds) {
        do_intercept(20, EVENT_WRITE_OUT);
        return -ERESTARTSYS;
    }

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return 0;

    // Above this constant bound the verifier cannot prove fd_array[fd] is in
    // range. FAIL CLOSED (intercept) rather than pass an un-inspectable fd.
    if (fd > 1023) {
        do_intercept(20, EVENT_WRITE_OUT);
        return -ERESTARTSYS;
    }

    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);
    if (!f)
        return 0;

    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode)
        return 0;

    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    if ((mode & S_IFMT) == S_IFIFO || (mode & S_IFMT) == S_IFSOCK) {
        do_intercept(20, EVENT_WRITE_OUT);
        return -ERESTARTSYS;
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════
// fmod_ret exfil hooks for data-moving syscalls with NO byte inspection:
//   - sendfile/sendfile64 : copies bytes between two fds (in-kernel), so it
//     can push file contents straight out a socket/pipe without ever calling
//     write().
//   - splice / vmsplice / tee : move pages between pipes, fds, and user memory,
//     another zero-copy path data can leave by.
// These bypass the write()/sendmsg() hooks entirely, so they were previously
// UNCOVERED exfil channels. We DEFAULT-DENY: while a monitored process is
// armed (should_intercept()), any of these is intercepted and the process is
// frozen at its first use, exactly like an external write. Fine-grained
// same-epoch fd-pair inspection is deferred; failing closed is the safe base.
// ═══════════════════════════════════════════════════════════════

SEC("fmod_ret/__x64_sys_sendfile64")
int BPF_PROG(shadow_sys_sendfile, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(40, EVENT_WRITE_OUT); // 40 = sendfile
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_splice")
int BPF_PROG(shadow_sys_splice, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(275, EVENT_WRITE_OUT); // 275 = splice
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_vmsplice")
int BPF_PROG(shadow_sys_vmsplice, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(278, EVENT_WRITE_OUT); // 278 = vmsplice
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_tee")
int BPF_PROG(shadow_sys_tee, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(276, EVENT_WRITE_OUT); // 276 = tee
    return -ERESTARTSYS;
}

// io_uring: async submission of network/file I/O can move data out WITHOUT the
// per-syscall write/sendmsg hooks ever firing. Default-deny while armed: block
// setup/enter/register so a monitored process is frozen at its first io_uring
// use (issue #5). Fine-grained SQE inspection is deferred.
SEC("fmod_ret/__x64_sys_io_uring_setup")
int BPF_PROG(shadow_sys_io_uring_setup, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(425, EVENT_WRITE_OUT); // 425 = io_uring_setup
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_io_uring_enter")
int BPF_PROG(shadow_sys_io_uring_enter, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(426, EVENT_WRITE_OUT); // 426 = io_uring_enter
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_io_uring_register")
int BPF_PROG(shadow_sys_io_uring_register, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(427, EVENT_WRITE_OUT); // 427 = io_uring_register
    return -ERESTARTSYS;
}

// ═══════════════════════════════════════════════════════════════
// fmod_ret IPC hooks for syscalls with NO dedicated LSM hook:
//   - shmdt (detach SysV shm)
//   - POSIX message queues: mq_open / mq_timedsend / mq_timedreceive / mq_notify
//     (glibc mq_send -> mq_timedsend, mq_receive -> mq_timedreceive)
// Same mechanism as the write hook: block before execution, restart on SIGCONT.
// ═══════════════════════════════════════════════════════════════

SEC("fmod_ret/__x64_sys_shmdt")
int BPF_PROG(shadow_sys_shmdt, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(67, EVENT_IPC); // 67 = shmdt
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_mq_open")
int BPF_PROG(shadow_sys_mq_open, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(240, EVENT_IPC); // 240 = mq_open
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_mq_timedsend")
int BPF_PROG(shadow_sys_mq_timedsend, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(242, EVENT_IPC); // 242 = mq_timedsend (mq_send)
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_mq_timedreceive")
int BPF_PROG(shadow_sys_mq_timedreceive, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(243, EVENT_IPC); // 243 = mq_timedreceive (mq_receive)
    return -ERESTARTSYS;
}

SEC("fmod_ret/__x64_sys_mq_notify")
int BPF_PROG(shadow_sys_mq_notify, struct pt_regs *regs)
{
    if (!should_intercept())
        return 0;
    do_intercept(244, EVENT_IPC); // 244 = mq_notify
    return -ERESTARTSYS;
}

// ═══════════════════════════════════════════════════════════════
// Privilege escalation hooks - block credential-changing syscalls
//   setuid family -> task_fix_setuid   (setuid/setreuid/setresuid/setfsuid)
//   setgid family -> task_fix_setgid   (setgid/setregid/setresgid/setfsgid)
//   setgroups     -> task_fix_setgroups
//   capset        -> capset
//   setuid/setgid binary execve -> bprm_check_security (extra guard)
// ═══════════════════════════════════════════════════════════════

// S_ISUID/S_ISGID bits in inode mode
#define S_ISUID 0004000
#define S_ISGID 0002000

// --- Privilege: block setuid/setgid binary execution ---
SEC("lsm/bprm_check_security")
int BPF_PROG(shadow_bprm_check, struct linux_binprm *bprm)
{
    if (!should_intercept())
        return 0;

    // Check if the binary has setuid or setgid bit set
    struct inode *inode = BPF_CORE_READ(bprm, file, f_inode);
    if (!inode)
        return 0;

    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    if (!(mode & S_ISUID) && !(mode & S_ISGID))
        return 0;  // not setuid/setgid, allow

    do_intercept(59, EVENT_PRIV_EXEC);  // 59 = execve syscall nr
    return -ERESTARTSYS;
}

// --- Privilege: UID changes (setuid/setreuid/setresuid/setfsuid) ---
SEC("lsm/task_fix_setuid")
int BPF_PROG(shadow_task_fix_setuid, struct cred *new_cred,
             const struct cred *old, int flags)
{
    if (!should_intercept())
        return 0;
    do_intercept(105, EVENT_PRIV_SETUID);  // 105 = setuid
    return -ERESTARTSYS;
}

// --- Privilege: GID changes (setgid/setregid/setresgid/setfsgid) ---
SEC("lsm/task_fix_setgid")
int BPF_PROG(shadow_task_fix_setgid, struct cred *new_cred,
             const struct cred *old, int flags)
{
    if (!should_intercept())
        return 0;
    do_intercept(106, EVENT_PRIV_SETUID);  // 106 = setgid
    return -ERESTARTSYS;
}

// --- Privilege: setgroups ---
SEC("lsm/task_fix_setgroups")
int BPF_PROG(shadow_task_fix_setgroups, struct cred *new_cred,
             const struct cred *old)
{
    if (!should_intercept())
        return 0;
    do_intercept(116, EVENT_PRIV_SETUID);  // 116 = setgroups
    return -ERESTARTSYS;
}

// --- Privilege: capset (capability changes) ---
SEC("lsm/capset")
int BPF_PROG(shadow_capset, struct cred *new_cred, const struct cred *old,
             const kernel_cap_t *effective, const kernel_cap_t *inheritable,
             const kernel_cap_t *permitted)
{
    if (!should_intercept())
        return 0;
    do_intercept(126, EVENT_PRIV_SETUID);  // 126 = capset
    return -ERESTARTSYS;
}

char LICENSE[] SEC("license") = "GPL";

// ═══════════════════════════════════════════════════════════════
// Fork tracking - detect new child processes in monitored cgroups.
//
// In the Frozen-Baseline + Speculative-Clone model, a candidate's descendants
// are NOT individually versioned: they are born inside the epoch cgroup and are
// discarded/kept as a unit via cgroup-level cleanup on rollback/commit. This
// hook therefore only REPORTS forks (informational); userspace does not inject
// a per-child checkpoint. It fires only when cow auto-tracking is enabled.
// ═══════════════════════════════════════════════════════════════

SEC("tp_btf/sched_process_fork")
int BPF_PROG(shadow_sched_fork, struct task_struct *parent, struct task_struct *child)
{
    if (!is_enabled())
        return 0;

    // Check if COW auto-tracking is enabled
    __u32 cow_key = 0;
    __u32 *cow_val = bpf_map_lookup_elem(&cow_enabled, &cow_key);
    if (!cow_val || *cow_val == 0)
        return 0;

    // Only track forks from processes within monitored cgroups
    if (!check_cgroup())
        return 0;

    // Emit a fork event so userspace can NOTE the epoch descendant (for
    // logging / observability). Cleanup is cgroup-scoped, not per-child.
    __u32 child_pid = BPF_CORE_READ(child, pid);
    __u32 child_tgid = BPF_CORE_READ(child, tgid);
    __u32 parent_tgid = BPF_CORE_READ(parent, tgid);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = child_pid;
        e->tgid = child_tgid;
        e->syscall_nr = parent_tgid;  // Repurpose: store parent tgid
        e->event_type = EVENT_FORK;
        e->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════
// Process-exit cleanup - drop all per-tgid state when a process leaves.
//
// stopped_pids / allowed_pids are keyed by tgid. Without cleanup, a stale
// "allowed" flag would survive process death, and a later pid-reuse inside a
// monitored cgroup could inherit it and be silently exempt from interception.
// Fires on thread-group-leader exit only.
// ═══════════════════════════════════════════════════════════════
SEC("tp_btf/sched_process_exit")
int BPF_PROG(shadow_sched_exit, struct task_struct *task)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    __u32 pid  = BPF_CORE_READ(task, pid);
    // Only clean up when the whole thread group is gone (leader exit).
    if (pid != tgid)
        return 0;
    bpf_map_delete_elem(&allowed_pids, &tgid);
    bpf_map_delete_elem(&stopped_pids, &tgid);
    return 0;
}
