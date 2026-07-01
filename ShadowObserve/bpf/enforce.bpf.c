/* SPDX-License-Identifier: GPL-2.0 */
/*
 * enforce.bpf.c – LSM-based whitelist enforcer for ShadowObserve.
 *
 * Once a cgroup's operations have been audited and approved, this program
 * restricts the cgroup to only perform allowed operations (by event_type
 * + path prefix). Any operation not in the whitelist returns -EPERM.
 *
 * Maps:
 *   enforce_enabled  – hash map: cgroup_id → 1 (enforcement active)
 *   whitelist_rules  – hash map: whitelist_key → 1 (allowed operations)
 *
 * The whitelist_key encodes: cgroup_id + event_type + path_prefix_hash.
 * A special "wildcard" entry with event_type=0xFFFF means "allow all events
 * for the given path prefix in that cgroup".
 */
#include "vmlinux.h"
#include "observ_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* ---- whitelist key structure ------------------------------------------ */

#define MAX_PREFIX_LEN 128
#define MAX_WHITELIST_ENTRIES 4096
#define MAX_ENFORCE_CGROUPS 256

/*
 * Whitelist rule key:
 *   cgroup_id  – which cgroup this rule applies to
 *   event_type – FS_EVENT_* or 0xFFFF for "any event"
 *   path_prefix – prefix to match (truncated to MAX_PREFIX_LEN)
 */
struct whitelist_key {
    __u64 cgroup_id;
    __u16 event_type;   /* FS_EVENT_*, or 0xFFFF for wildcard */
    __u16 _pad;
    char  path_prefix[MAX_PREFIX_LEN];
};

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

/*
 * Check if the given operation (cgroup + event_type + path) is whitelisted.
 * Returns 0 if allowed, -1 if denied.
 *
 * Matching logic:
 *   1. Check exact match: cgroup_id + event_type + path_prefix
 *   2. Check wildcard event: cgroup_id + 0xFFFF + path_prefix
 *   3. Check empty-path rules: cgroup_id + event_type + ""
 *   4. Check global wildcard: cgroup_id + 0xFFFF + ""
 *
 * Path matching is done by constructing keys with progressively shorter
 * path prefixes (directory boundaries). Due to BPF verifier limits, we
 * use a simplified approach: check the full path and the empty path.
 */
static __always_inline int check_whitelist(__u64 cgroup_id, __u16 event_type,
                                           const char *path, int path_len)
{
    struct whitelist_key key = {};
    __u8 *val;

    key.cgroup_id = cgroup_id;

    /* Check 1: exact event_type + full path prefix */
    key.event_type = event_type;
    if (path_len > 0) {
        int copy_len = path_len < MAX_PREFIX_LEN ? path_len : MAX_PREFIX_LEN - 1;
        bpf_probe_read_kernel_str(key.path_prefix, copy_len + 1, path);
    }
    val = bpf_map_lookup_elem(&whitelist_rules, &key);
    if (val)
        return 0;  /* allowed */

    /* Check 2: wildcard event (0xFFFF) + full path prefix */
    key.event_type = 0xFFFF;
    val = bpf_map_lookup_elem(&whitelist_rules, &key);
    if (val)
        return 0;  /* allowed */

    /* Check 3: exact event_type + empty path (allow all paths for this event) */
    key.event_type = event_type;
    __builtin_memset(key.path_prefix, 0, MAX_PREFIX_LEN);
    val = bpf_map_lookup_elem(&whitelist_rules, &key);
    if (val)
        return 0;  /* allowed */

    /* Check 4: global wildcard (allow everything for this cgroup) */
    key.event_type = 0xFFFF;
    val = bpf_map_lookup_elem(&whitelist_rules, &key);
    if (val)
        return 0;  /* allowed */

    return -1;  /* denied */
}

/* ---- LSM hooks -------------------------------------------------------- */

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *enforced = bpf_map_lookup_elem(&enforce_enabled, &cgroup_id);
    if (!enforced)
        return 0;  /* not enforced, allow */

    /* Get file path from dentry */
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    char path[MAX_PREFIX_LEN] = {};
    bpf_d_path(&file->f_path, path, sizeof(path));

    int len = 0;
    for (int i = 0; i < MAX_PREFIX_LEN - 1; i++) {
        if (path[i] == '\0') break;
        len++;
    }

    if (check_whitelist(cgroup_id, FS_EVENT_OPEN, path, len) < 0)
        return -1;  /* EPERM */

    return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(enforce_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *enforced = bpf_map_lookup_elem(&enforce_enabled, &cgroup_id);
    if (!enforced)
        return 0;

    char name[MAX_PREFIX_LEN] = {};
    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(dentry, d_name.name));

    int len = 0;
    for (int i = 0; i < MAX_PREFIX_LEN - 1; i++) {
        if (name[i] == '\0') break;
        len++;
    }

    if (check_whitelist(cgroup_id, FS_EVENT_CREATE, name, len) < 0)
        return -1;

    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(enforce_inode_unlink, struct inode *dir, struct dentry *dentry,
             int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *enforced = bpf_map_lookup_elem(&enforce_enabled, &cgroup_id);
    if (!enforced)
        return 0;

    char name[MAX_PREFIX_LEN] = {};
    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(dentry, d_name.name));

    int len = 0;
    for (int i = 0; i < MAX_PREFIX_LEN - 1; i++) {
        if (name[i] == '\0') break;
        len++;
    }

    if (check_whitelist(cgroup_id, FS_EVENT_DELETE, name, len) < 0)
        return -1;

    return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(enforce_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry)
{

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *enforced = bpf_map_lookup_elem(&enforce_enabled, &cgroup_id);
    if (!enforced)
        return 0;

    char name[MAX_PREFIX_LEN] = {};
    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(old_dentry, d_name.name));

    int len = 0;
    for (int i = 0; i < MAX_PREFIX_LEN - 1; i++) {
        if (name[i] == '\0') break;
        len++;
    }

    if (check_whitelist(cgroup_id, FS_EVENT_RENAME, name, len) < 0)
        return -1;

    return 0;
}

SEC("lsm/inode_mkdir")
int BPF_PROG(enforce_inode_mkdir, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *enforced = bpf_map_lookup_elem(&enforce_enabled, &cgroup_id);
    if (!enforced)
        return 0;

    char name[MAX_PREFIX_LEN] = {};
    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(dentry, d_name.name));

    int len = 0;
    for (int i = 0; i < MAX_PREFIX_LEN - 1; i++) {
        if (name[i] == '\0') break;
        len++;
    }

    if (check_whitelist(cgroup_id, FS_EVENT_MKDIR, name, len) < 0)
        return -1;

    return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(enforce_inode_rmdir, struct inode *dir, struct dentry *dentry,
             int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *enforced = bpf_map_lookup_elem(&enforce_enabled, &cgroup_id);
    if (!enforced)
        return 0;

    char name[MAX_PREFIX_LEN] = {};
    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(dentry, d_name.name));

    int len = 0;
    for (int i = 0; i < MAX_PREFIX_LEN - 1; i++) {
        if (name[i] == '\0') break;
        len++;
    }

    if (check_whitelist(cgroup_id, FS_EVENT_RMDIR, name, len) < 0)
        return -1;

    return 0;
}
