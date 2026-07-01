/* SPDX-License-Identifier: GPL-2.0 */
/*
 * observ_common.h – shared definitions between BPF and userspace.
 */
#ifndef OBSERV_COMMON_H
#define OBSERV_COMMON_H

/* ---- kernel-style types ---------------------------------------------- */
/*
 * BPF side: vmlinux.h provides __u8 / __u32 / __u64 etc.
 * Userspace: <linux/types.h> provides the same types.
 * Include it here so the struct definitions work in both contexts.
 */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* ---- event types ------------------------------------------------------ */

/* file-system events */
#define FS_EVENT_OPEN     1
#define FS_EVENT_CREATE   2
#define FS_EVENT_DELETE   3
#define FS_EVENT_RENAME   4
#define FS_EVENT_CHMOD    5
#define FS_EVENT_CHOWN    6
#define FS_EVENT_MKDIR    7
#define FS_EVENT_RMDIR    8
#define FS_EVENT_LINK     9
#define FS_EVENT_SYMLINK  10
#define FS_EVENT_TRUNCATE 11

/* process events */
#define PROC_EVENT_EXEC   100
#define PROC_EVENT_FORK   101
#define PROC_EVENT_EXIT   102
#define PROC_EVENT_KILL   103
#define PROC_EVENT_PRCTL  104
#define PROC_EVENT_PTRACE 105
#define PROC_EVENT_SETUID 106
#define PROC_EVENT_CAPSET 107

/* ---- audit actions ---------------------------------------------------- */

#define AUDIT_DENY  0
#define AUDIT_ALLOW 1

/* ---- constants -------------------------------------------------------- */

#define MAX_PATH        256
#define MAX_COMM        16
#define MAX_ARGS        640
#define RING_BUF_SIZE   (512 * 1024)   /* 512 KB ring buffer */

/* ---- unified event sent from BPF to userspace via ring buffer -------- */

/*
 * observ_event – covers both file-system and process events.
 *
 * Field semantics by event category:
 *   FS events:
 *     arg1     = flags (open) / mode (chmod, mkdir)
 *     path     = primary file path
 *     new_path = destination path (rename, link, symlink)
 *   PROC events:
 *     arg1     = child_pid / option / request / new uid / target pid
 *     arg2     = signal / target pid / euid
 *     arg3     = suid / tgid (tkill)
 *     path     = filename (exec) / child comm (fork)
 *     new_path = unused (reserved for future cmdline)
 */
struct observ_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u16 event_type;       /* FS_EVENT_* or PROC_EVENT_* */
    __u16 _pad0;
    __u32 arg1;             /* flags/mode (FS) | pid/option (PROC) */
    __u32 arg2;             /* signal (PROC) */
    __u32 arg3;             /* extra */
    __u32 _pad1;
    char  comm[MAX_COMM];
    char  path[MAX_PATH];         /* primary path or filename */
    char  new_path[MAX_PATH];     /* destination path or unused */
};

/* ---- audit rule (userspace only) ------------------------------------- */

struct audit_rule {
    int  event_type;              /* FS_EVENT_* / PROC_EVENT_*, or -1 for any */
    int  action;                  /* AUDIT_ALLOW or AUDIT_DENY */
    char path_pattern[MAX_PATH];  /* prefix to match against event path */
};

#endif /* OBSERV_COMMON_H */
