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
/*  FILE-SYSTEM tracepoints                                              */
/* ===================================================================== */

SEC("tp/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;

    __u32 flags;
    char *filename_ptr;
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &ctx->args[1]);
    bpf_probe_read(&flags,        sizeof(flags),        &ctx->args[2]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), filename_ptr);

    evt->arg1 = flags;
    evt->event_type = (flags & 0x40) ? FS_EVENT_CREATE : FS_EVENT_OPEN;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_DELETE;
    char *pathname_ptr;
    bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &ctx->args[1]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), pathname_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int tp_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_DELETE;
    char *pathname_ptr;
    bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &ctx->args[0]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), pathname_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_renameat")
int tp_renameat(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_RENAME;
    char *oldname_ptr, *newname_ptr;
    bpf_probe_read(&oldname_ptr, sizeof(oldname_ptr), &ctx->args[1]);
    bpf_probe_read(&newname_ptr, sizeof(newname_ptr), &ctx->args[3]);
    bpf_probe_read_user_str(&evt->path,     sizeof(evt->path),     oldname_ptr);
    bpf_probe_read_user_str(&evt->new_path, sizeof(evt->new_path), newname_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int tp_renameat2(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_RENAME;
    char *oldname_ptr, *newname_ptr;
    bpf_probe_read(&oldname_ptr, sizeof(oldname_ptr), &ctx->args[1]);
    bpf_probe_read(&newname_ptr, sizeof(newname_ptr), &ctx->args[3]);
    bpf_probe_read_user_str(&evt->path,     sizeof(evt->path),     oldname_ptr);
    bpf_probe_read_user_str(&evt->new_path, sizeof(evt->new_path), newname_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int tp_rename(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_RENAME;
    char *oldname_ptr, *newname_ptr;
    bpf_probe_read(&oldname_ptr, sizeof(oldname_ptr), &ctx->args[0]);
    bpf_probe_read(&newname_ptr, sizeof(newname_ptr), &ctx->args[1]);
    bpf_probe_read_user_str(&evt->path,     sizeof(evt->path),     oldname_ptr);
    bpf_probe_read_user_str(&evt->new_path, sizeof(evt->new_path), newname_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchmodat")
int tp_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_CHMOD;
    char *filename_ptr; __u32 mode;
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &ctx->args[1]);
    bpf_probe_read(&mode,         sizeof(mode),         &ctx->args[2]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), filename_ptr);
    evt->arg1 = mode;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_chmod")
int tp_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_CHMOD;
    char *filename_ptr; __u32 mode;
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &ctx->args[0]);
    bpf_probe_read(&mode,         sizeof(mode),         &ctx->args[1]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), filename_ptr);
    evt->arg1 = mode;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchownat")
int tp_fchownat(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_CHOWN;
    char *filename_ptr;
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &ctx->args[1]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), filename_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_chown")
int tp_chown(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_CHOWN;
    char *filename_ptr;
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &ctx->args[0]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), filename_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_mkdirat")
int tp_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_MKDIR;
    char *pathname_ptr; __u32 mode;
    bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &ctx->args[1]);
    bpf_probe_read(&mode,         sizeof(mode),         &ctx->args[2]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), pathname_ptr);
    evt->arg1 = mode;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_mkdir")
int tp_mkdir(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_MKDIR;
    char *pathname_ptr; __u32 mode;
    bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &ctx->args[0]);
    bpf_probe_read(&mode,         sizeof(mode),         &ctx->args[1]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), pathname_ptr);
    evt->arg1 = mode;
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_rmdir")
int tp_rmdir(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_RMDIR;
    char *pathname_ptr;
    bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &ctx->args[0]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), pathname_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_linkat")
int tp_linkat(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_LINK;
    char *oldname_ptr, *newname_ptr;
    bpf_probe_read(&oldname_ptr, sizeof(oldname_ptr), &ctx->args[1]);
    bpf_probe_read(&newname_ptr, sizeof(newname_ptr), &ctx->args[3]);
    bpf_probe_read_user_str(&evt->path,     sizeof(evt->path),     oldname_ptr);
    bpf_probe_read_user_str(&evt->new_path, sizeof(evt->new_path), newname_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_link")
int tp_link(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_LINK;
    char *oldname_ptr, *newname_ptr;
    bpf_probe_read(&oldname_ptr, sizeof(oldname_ptr), &ctx->args[0]);
    bpf_probe_read(&newname_ptr, sizeof(newname_ptr), &ctx->args[1]);
    bpf_probe_read_user_str(&evt->path,     sizeof(evt->path),     oldname_ptr);
    bpf_probe_read_user_str(&evt->new_path, sizeof(evt->new_path), newname_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_symlinkat")
int tp_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_SYMLINK;
    char *target_ptr, *linkpath_ptr;
    bpf_probe_read(&target_ptr,   sizeof(target_ptr),   &ctx->args[0]);
    bpf_probe_read(&linkpath_ptr, sizeof(linkpath_ptr), &ctx->args[2]);
    bpf_probe_read_user_str(&evt->path,     sizeof(evt->path),     linkpath_ptr);
    bpf_probe_read_user_str(&evt->new_path, sizeof(evt->new_path), target_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_symlink")
int tp_symlink(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_SYMLINK;
    char *target_ptr, *linkpath_ptr;
    bpf_probe_read(&target_ptr,   sizeof(target_ptr),   &ctx->args[0]);
    bpf_probe_read(&linkpath_ptr, sizeof(linkpath_ptr), &ctx->args[1]);
    bpf_probe_read_user_str(&evt->path,     sizeof(evt->path),     linkpath_ptr);
    bpf_probe_read_user_str(&evt->new_path, sizeof(evt->new_path), target_ptr);
    submit_event(evt);
    return 0;
}

SEC("tp/syscalls/sys_enter_truncate")
int tp_truncate(struct trace_event_raw_sys_enter *ctx) {
    struct observ_event *evt = reserve_event();
    if (!evt) return 0;
    evt->event_type = FS_EVENT_TRUNCATE;
    char *path_ptr;
    bpf_probe_read(&path_ptr, sizeof(path_ptr), &ctx->args[0]);
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), path_ptr);
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
