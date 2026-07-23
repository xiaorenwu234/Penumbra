/* SPDX-License-Identifier: GPL-2.0 */
/*
 * observ.bpf.c – unified tracepoint-based file-system + process event recorder.
 *
 * Covers:
 *   File-system: open, create, delete, rename, chmod, chown, mkdir, rmdir,
 *                link, symlink, truncate
 *   Process:     exec, fork, exit, kill, prctl, ptrace, setuid, capset
 *
 * Filters by cgroup_id → single ring buffer → userspace JSONL logger.
 */
#include "vmlinux.h"
#include "observ_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cri.bpf.h"   /* canonical path + operation-class helpers */

char LICENSE[] SEC("license") = "GPL";

/* ---- maps ------------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgroup_monitor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUF_SIZE);
} events SEC(".maps");

/* ---- helpers ---------------------------------------------------------- */

static __always_inline struct observ_event *
reserve_event(void) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *mon = bpf_map_lookup_elem(&cgroup_monitor, &cgroup_id);
    if (!mon)
        return NULL;

    struct observ_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return NULL;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid          = pid_tgid >> 32;
    evt->tid          = (__u32)pid_tgid;
    evt->uid          = uid_gid & 0xFFFFFFFF;
    evt->gid          = uid_gid >> 32;
    evt->cgroup_id    = cgroup_id;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    return evt;
}

static __always_inline void
submit_event(struct observ_event *evt) {
    bpf_ringbuf_submit(evt, 0);
}

static __always_inline const char *
get_data_loc_str(void *ctx, __u32 data_loc_field) {
    __u16 offset = (__u16)(data_loc_field & 0xFFFF);
    return (const char *)ctx + offset;
}

/* ===================================================================== */
/*  FILE-SYSTEM events - LSM hooks (semantically equivalent to enforce.bpf.c)*/
/*                                                                       */
/*  These hook the SAME LSM points as the enforcer and derive the path    */
/*  with the SAME helper (cri_build_path), so the canonical path recorded  */
/*  here is byte-identical to the one the enforcer checks. Only operations */
/*  that pass prior LSM checks (ret == 0) are recorded, matching the       */
/*  population the enforcer sees. All programs return 0 (never deny).      */
/* ===================================================================== */

SEC("lsm/file_open")
int BPF_PROG(observ_file_open, struct file *file, int ret) {
    if (ret != 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    unsigned int flags = BPF_CORE_READ(file, f_flags);
    evt->arg1 = flags;
    evt->event_type = (flags & O_CREAT) ? FS_EVENT_CREATE : FS_EVENT_OPEN;
    cri_build_path(BPF_CORE_READ(file, f_path.dentry), evt->path);
    submit_event(evt);
    return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(observ_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret) {
    if (ret != 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_CREATE;
    evt->arg1 = mode;
    cri_build_path(dentry, evt->path);
    submit_event(evt);
    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(observ_inode_unlink, struct inode *dir, struct dentry *dentry,
             int ret) {
    if (ret != 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_DELETE;
    cri_build_path(dentry, evt->path);
    submit_event(evt);
    return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(observ_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry, int ret) {
    if (ret != 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_RENAME;
    cri_build_path(old_dentry, evt->path);       /* source (enforced) */
    cri_build_path(new_dentry, evt->new_path);   /* destination */
    submit_event(evt);
    return 0;
}

SEC("lsm/inode_mkdir")
int BPF_PROG(observ_inode_mkdir, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret) {
    if (ret != 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_MKDIR;
    evt->arg1 = mode;
    cri_build_path(dentry, evt->path);
    submit_event(evt);
    return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(observ_inode_rmdir, struct inode *dir, struct dentry *dentry,
             int ret) {
    if (ret != 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_RMDIR;
    cri_build_path(dentry, evt->path);
    submit_event(evt);
    return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(observ_inode_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret) {
    if (ret != 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_LINK;
    cri_build_path(new_dentry, evt->path);       /* created link (enforced) */
    cri_build_path(old_dentry, evt->new_path);   /* existing target */
    submit_event(evt);
    return 0;
}

SEC("lsm/inode_symlink")
int BPF_PROG(observ_inode_symlink, struct inode *dir, struct dentry *dentry,
             const char *old_name, int ret) {
    if (ret != 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_SYMLINK;
    cri_build_path(dentry, evt->path);           /* created symlink (enforced) */
    bpf_probe_read_kernel_str(&evt->new_path, sizeof(evt->new_path), old_name);
    submit_event(evt);
    return 0;
}

/* CHMOD / CHOWN / TRUNCATE via inode_setattr. The leading mnt_idmap arg
 * matches the target kernel (6.x). Classified identically to the enforcer. */
SEC("lsm/inode_setattr")
int BPF_PROG(observ_inode_setattr, struct mnt_idmap *idmap,
             struct dentry *dentry, struct iattr *attr, int ret) {
    if (ret != 0) return 0;
    unsigned int ia_valid = BPF_CORE_READ(attr, ia_valid);
    __u16 event_type = cri_setattr_event(ia_valid);
    if (event_type == 0) return 0;
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = event_type;
    evt->arg1 = ia_valid;
    cri_build_path(dentry, evt->path);
    submit_event(evt);
    return 0;
}

/* ===================================================================== */
/*  PROCESS tracepoints                                                  */
/* ===================================================================== */

SEC("tp/sched/sched_process_exec")
int tp_sched_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_EXEC;
    __u32 data_loc = BPF_CORE_READ(ctx, __data_loc_filename);
    const char *filename = get_data_loc_str(ctx, data_loc);
    bpf_probe_read_kernel_str(&evt->path, sizeof(evt->path), filename);
    submit_event(evt);
    return 0;
}

SEC("tp/sched/sched_process_fork")
int tp_sched_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_FORK;
    evt->arg1 = BPF_CORE_READ(ctx, child_pid);
    __u32 data_loc = BPF_CORE_READ(ctx, __data_loc_child_comm);
    const char *child_comm = get_data_loc_str(ctx, data_loc);
    bpf_probe_read_kernel_str(&evt->path, sizeof(evt->path), child_comm);
    submit_event(evt);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_exit *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_EXIT;
    evt->arg1 = BPF_CORE_READ(ctx, group_dead) ? 1 : 0;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_kill")
int tp_kill(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_KILL;
    __kernel_pid_t target_pid; int sig;
    bpf_probe_read(&target_pid, sizeof(target_pid), &ctx->args[0]);
    bpf_probe_read(&sig,        sizeof(sig),         &ctx->args[1]);
    evt->arg1 = (__u32)target_pid;
    evt->arg2 = (__u32)sig;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_tkill")
int tp_tkill(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_KILL;
    int tid, sig;
    bpf_probe_read(&tid, sizeof(tid), &ctx->args[0]);
    bpf_probe_read(&sig, sizeof(sig), &ctx->args[1]);
    evt->arg1 = (__u32)tid;
    evt->arg2 = (__u32)sig;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_tgkill")
int tp_tgkill(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_KILL;
    int tgid, tid, sig;
    bpf_probe_read(&tgid, sizeof(tgid), &ctx->args[0]);
    bpf_probe_read(&tid,  sizeof(tid),  &ctx->args[1]);
    bpf_probe_read(&sig,  sizeof(sig),  &ctx->args[2]);
    evt->arg1 = (__u32)tgid;
    evt->arg2 = (__u32)tid;
    evt->arg3 = (__u32)sig;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_prctl")
int tp_prctl(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_PRCTL;
    int option;
    bpf_probe_read(&option, sizeof(option), &ctx->args[0]);
    evt->arg1 = (__u32)option;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_ptrace")
int tp_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_PTRACE;
    int request; __kernel_pid_t target_pid;
    bpf_probe_read(&request,    sizeof(request),    &ctx->args[0]);
    bpf_probe_read(&target_pid, sizeof(target_pid), &ctx->args[1]);
    evt->arg1 = (__u32)request;
    evt->arg2 = (__u32)target_pid;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_setuid")
int tp_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_SETUID;
    uid_t uid;
    bpf_probe_read(&uid, sizeof(uid), &ctx->args[0]);
    evt->arg1 = (__u32)uid;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_setreuid")
int tp_setreuid(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_SETUID;
    uid_t ruid, euid;
    bpf_probe_read(&ruid, sizeof(ruid), &ctx->args[0]);
    bpf_probe_read(&euid, sizeof(euid), &ctx->args[1]);
    evt->arg1 = (__u32)ruid;
    evt->arg2 = (__u32)euid;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_setresuid")
int tp_setresuid(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_SETUID;
    uid_t ruid, euid, suid;
    bpf_probe_read(&ruid, sizeof(ruid), &ctx->args[0]);
    bpf_probe_read(&euid, sizeof(euid), &ctx->args[1]);
    bpf_probe_read(&suid, sizeof(suid), &ctx->args[2]);
    evt->arg1 = (__u32)ruid;
    evt->arg2 = (__u32)euid;
    evt->arg3 = (__u32)suid;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_capset")
int tp_capset(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = PROC_EVENT_CAPSET;
    submit_event(evt);
    return 0;
}
