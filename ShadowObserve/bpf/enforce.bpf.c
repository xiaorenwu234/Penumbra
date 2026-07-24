/* SPDX-License-Identifier: GPL-2.0 */
/*
 * enforce.bpf.c - LSM-based whitelist enforcer for ShadowObserve.
 *
 * Once a cgroup's operations have been audited and approved, this program
 * restricts the cgroup to only perform allowed operations (by event_type +
 * canonical path). Any operation not in the whitelist returns -EPERM.
 *
 * CANONICAL RESOURCE IDENTIFIER: this enforcer and the observer (observ.bpf.c)
 * hook the SAME LSM points and derive the path with the SAME helper
 * (cri_build_path in cri.bpf.h), then match with the SAME rule
 * (cri_check_whitelist, a component-boundary prefix match mirroring the audit
 * engine). So an operation that passed the historical audit is allowed here,
 * and one the audit would flag is denied here - no observe/enforce divergence.
 *
 * Maps:
 *   enforce_enabled  - hash map: cgroup_id -> 1 (enforcement active)
 *   whitelist_rules  - hash map: whitelist_key -> 1 (allowed operations)
 *
 * The whitelist_key encodes cgroup_id + event_type + path_prefix. A special
 * "wildcard" entry with event_type=0xFFFF means "allow all events for the given
 * path prefix in that cgroup"; an empty path_prefix means "any path".
 */
#include "vmlinux.h"
#include "observ_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cri.bpf.h"   /* MAX_PREFIX_LEN, struct whitelist_key, cri_* helpers */

char LICENSE[] SEC("license") = "GPL";

/* ---- sizing ----------------------------------------------------------- */

#define MAX_WHITELIST_ENTRIES 4096
#define MAX_ENFORCE_CGROUPS   256

/* ---- maps ------------------------------------------------------------- */

/* Tracks which cgroups have enforcement enabled */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENFORCE_CGROUPS);
    __type(key, __u64);           /* cgroup_id */
    __type(value, __u8);          /* 1 = enforcement active */
} enforce_enabled SEC(".maps");

/* Whitelist rules: if a key exists, that operation is allowed */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST_ENTRIES);
    __type(key, struct whitelist_key);
    __type(value, __u8);
} whitelist_rules SEC(".maps");

/* ---- helpers ---------------------------------------------------------- */

/* Return 1 if enforcement is active for the current cgroup, else 0. */
static __always_inline int enforcing(__u64 *cgroup_id_out)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id_out)
        *cgroup_id_out = cgroup_id;
    return bpf_map_lookup_elem(&enforce_enabled, &cgroup_id) != NULL;
}

/* Build the canonical path of `dentry`, then apply the shared prefix match. */
static __always_inline int enforce_dentry(__u64 cgroup_id, __u16 event_type,
                                          struct dentry *dentry)
{
    char path[CRI_MAX_PATH] = {};
    int len = cri_build_path(dentry, path);
    return cri_check_whitelist(&whitelist_rules, cgroup_id, event_type, path, len);
}

/* ---- LSM hooks -------------------------------------------------------- */

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    /* Same OPEN-vs-CREATE classification as the observer's file_open. */
    unsigned int flags = BPF_CORE_READ(file, f_flags);
    __u16 event_type = (flags & O_CREAT) ? FS_EVENT_CREATE : FS_EVENT_OPEN;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (enforce_dentry(cgroup_id, event_type, dentry) < 0)
        return -1;              /* EPERM */
    return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(enforce_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    if (enforce_dentry(cgroup_id, FS_EVENT_CREATE, dentry) < 0)
        return -1;
    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(enforce_inode_unlink, struct inode *dir, struct dentry *dentry,
             int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    if (enforce_dentry(cgroup_id, FS_EVENT_DELETE, dentry) < 0)
        return -1;
    return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(enforce_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    /* DUAL-RESOURCE operation: a rename touches BOTH the source and the
     * destination, so BOTH must be whitelisted for FS_EVENT_RENAME. Checking
     * only the source would let an allowed file be renamed INTO a forbidden
     * directory (and checking only the destination would let a forbidden file
     * be renamed OUT). Deny if EITHER endpoint is not permitted. The observer
     * records old_dentry as `path` and new_dentry as `new_path`; the audit
     * engine mirrors this two-endpoint check, so observe==enforce holds. */
    if (enforce_dentry(cgroup_id, FS_EVENT_RENAME, old_dentry) < 0)
        return -1;
    if (enforce_dentry(cgroup_id, FS_EVENT_RENAME, new_dentry) < 0)
        return -1;
    return 0;
}

SEC("lsm/inode_mkdir")
int BPF_PROG(enforce_inode_mkdir, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    if (enforce_dentry(cgroup_id, FS_EVENT_MKDIR, dentry) < 0)
        return -1;
    return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(enforce_inode_rmdir, struct inode *dir, struct dentry *dentry,
             int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    if (enforce_dentry(cgroup_id, FS_EVENT_RMDIR, dentry) < 0)
        return -1;
    return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(enforce_inode_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    /* DUAL-RESOURCE operation: a hard link creates a new name (new_dentry) for
     * an existing inode (old_dentry). BOTH the created link and the existing
     * target must be whitelisted for FS_EVENT_LINK, else a forbidden file
     * could be linked into an allowed directory (or an allowed file linked
     * into a forbidden one). Deny if EITHER endpoint is not permitted. The
     * observer records new_dentry as `path` and old_dentry as `new_path`; the
     * audit engine mirrors this two-endpoint check. */
    if (enforce_dentry(cgroup_id, FS_EVENT_LINK, new_dentry) < 0)
        return -1;
    if (enforce_dentry(cgroup_id, FS_EVENT_LINK, old_dentry) < 0)
        return -1;
    return 0;
}

SEC("lsm/inode_symlink")
int BPF_PROG(enforce_inode_symlink, struct inode *dir, struct dentry *dentry,
             const char *old_name, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    /* Enforce on the created symlink (matches the observer's SYMLINK path). */
    if (enforce_dentry(cgroup_id, FS_EVENT_SYMLINK, dentry) < 0)
        return -1;
    return 0;
}

/* security_inode_setattr gained a leading `struct mnt_idmap *idmap` arg in the
 * 6.x series; this matches the target kernel (>= 6.x with mnt_idmap). Covers
 * CHMOD / CHOWN / TRUNCATE, classified identically to the observer. */
SEC("lsm/inode_setattr")
int BPF_PROG(enforce_inode_setattr, struct mnt_idmap *idmap,
             struct dentry *dentry, struct iattr *attr, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id;
    if (!enforcing(&cgroup_id))
        return 0;

    unsigned int ia_valid = BPF_CORE_READ(attr, ia_valid);
    __u16 event_type = cri_setattr_event(ia_valid);
    if (event_type == 0)
        return 0;               /* not a tracked attribute change */

    if (enforce_dentry(cgroup_id, event_type, dentry) < 0)
        return -1;
    return 0;
}
