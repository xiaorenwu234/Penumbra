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
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} stopped_pids SEC(".maps");

// Tracks which tgids are allowed to pass (after user chose "continue")
// Key: tgid, Value: 1 = allowed
// Once in this map, the process will never be intercepted again
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} allowed_pids SEC(".maps");

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

    // If process is in allowed list, always let it pass
    __u32 *allowed = bpf_map_lookup_elem(&allowed_pids, &tgid);
    if (allowed)
        return 0;

    // If already stopped, don't intercept again
    __u32 *val = bpf_map_lookup_elem(&stopped_pids, &tgid);
    if (val)
        return 0;

    return 1;
}

// Emit event + SIGSTOP + mark as stopped
static __always_inline void do_intercept(__u32 syscall_nr, __u32 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 one = 1;

    // Mark as stopped FIRST to prevent re-entry on signal delivery
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

    // SIGSTOP the process
    bpf_send_signal(19);
}

// ═══════════════════════════════════════════════════════════════
// LSM Hooks - Block syscall BEFORE execution, return -ERESTARTSYS
// so kernel auto-restarts after SIGCONT
// ═══════════════════════════════════════════════════════════════

// --- Network: connect ---
SEC("lsm/socket_connect")
int BPF_PROG(shadow_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!should_intercept())
        return 0;
    do_intercept(42, EVENT_NETWORK);
    return -ERESTARTSYS;
}

// --- Network: sendmsg (covers sendto, sendmsg) ---
SEC("lsm/socket_sendmsg")
int BPF_PROG(shadow_socket_sendmsg, struct socket *sock,
             struct msghdr *msg, int size)
{
    if (!should_intercept())
        return 0;
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
    do_intercept(49, EVENT_NETWORK);
    return -ERESTARTSYS;
}

// --- Network: listen ---
SEC("lsm/socket_listen")
int BPF_PROG(shadow_socket_listen, struct socket *sock, int backlog)
{
    if (!should_intercept())
        return 0;
    do_intercept(50, EVENT_NETWORK);
    return -ERESTARTSYS;
}

// --- Network: accept ---
SEC("lsm/socket_accept")
int BPF_PROG(shadow_socket_accept, struct socket *sock,
             struct socket *newsock)
{
    if (!should_intercept())
        return 0;
    do_intercept(288, EVENT_NETWORK);
    return -ERESTARTSYS;
}

// --- IPC: shmat ---
SEC("lsm/shm_shmat")
int BPF_PROG(shadow_shm_shmat, struct kern_ipc_perm *shp,
             char *shmaddr, int shmflg)
{
    if (!should_intercept())
        return 0;
    do_intercept(30, EVENT_IPC);
    return -ERESTARTSYS;
}

// --- IPC: mmap shared memory ---
// Intercepts mmap with MAP_SHARED flag (POSIX shm, file-backed shared mappings)
// mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
#define MAP_SHARED 0x01
SEC("lsm/mmap_file")
int BPF_PROG(shadow_mmap_file, struct file *file,
             unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    if (!should_intercept())
        return 0;

    // Only intercept MAP_SHARED mappings (used for IPC)
    // MAP_PRIVATE mappings (copy-on-write) are not communication channels
    if (!(flags & MAP_SHARED))
        return 0;

    // If file is NULL, it's an anonymous shared mapping (MAP_SHARED|MAP_ANONYMOUS)
    // which is used for parent-child IPC - intercept it
    // If file is non-NULL, it could be a shared file mapping or POSIX shm
    // Both are IPC channels - intercept
    do_intercept(9, EVENT_IPC); // 9 = mmap syscall number
    return -ERESTARTSYS;
}

// --- IPC: msg send ---
SEC("lsm/msg_queue_msgsnd")
int BPF_PROG(shadow_msg_msgsnd, struct kern_ipc_perm *msq,
             struct msg_msg *msg, int msqflg)
{
    if (!should_intercept())
        return 0;
    do_intercept(69, EVENT_IPC);
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
    do_intercept(70, EVENT_IPC);
    return -ERESTARTSYS;
}

// --- Signal: kill/tkill/tgkill to other processes ---
SEC("lsm/task_kill")
int BPF_PROG(shadow_task_kill, struct task_struct *p,
             struct kernel_siginfo *info, int sig,
             const struct cred *cred)
{
    if (!should_intercept())
        return 0;

    // Allow signals to self
    __u32 my_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 target_tgid = BPF_CORE_READ(p, tgid);
    if (target_tgid == my_tgid)
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

    // Check stdout/stderr
    if (fd == 1 || fd == 2) {
        do_intercept(1, EVENT_WRITE_OUT);
        return -ERESTARTSYS;
    }

    // Check if fd is a pipe/FIFO/socket
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return 0;

    // Bound check fd to avoid verifier issues
    if (fd > 1023)
        return 0;

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

    if (fd == 1 || fd == 2) {
        do_intercept(20, EVENT_WRITE_OUT);
        return -ERESTARTSYS;
    }

    // Check pipe/socket (same logic as write)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return 0;

    if (fd > 1023)
        return 0;

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

char LICENSE[] SEC("license") = "GPL";
