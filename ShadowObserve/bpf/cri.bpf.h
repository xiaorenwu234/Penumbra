/* SPDX-License-Identifier: GPL-2.0 */
/*
 * cri.bpf.h - Canonical Resource Identifier helpers shared by observ.bpf.c
 *             (observation) and enforce.bpf.c (enforcement).
 *
 * The whole point of this header is SEMANTIC EQUIVALENCE: observation and
 * enforcement must derive the SAME identifier for the SAME operation so that a
 * policy that passes the historical audit cannot be denied (or wrongly allowed)
 * by the runtime enforcer. We guarantee that by construction:
 *
 *   1. Both sides hook the SAME LSM points (file_open, inode_*), and
 *   2. Both sides derive the path with the SAME helper, cri_build_path(), and
 *   3. Both sides match with the SAME rule, cri_check_whitelist() on the enforce
 *      side mirrors AuditEngine::path_matches() on the audit side
 *      (component-boundary prefix).
 *
 * The Canonical Resource Identifier (CRI) is (operation_class, canonical_path):
 *   - operation_class = FS_EVENT_* (from observ_common.h), unchanged.
 *   - canonical_path  = absolute path built by walking dentry->d_parent to the
 *     filesystem root. We deliberately do NOT use bpf_d_path(): it is only
 *     callable from an allowlisted set of hooks (security_file_open,
 *     security_path_truncate, vfs_*, ...) and NOT from the inode_* hooks used
 *     for create/unlink/rename/etc. A manual d_parent walk works on any dentry,
 *     so ONE helper serves every FS hook. It is defined relative to the
 *     filesystem root and is used identically on both sides, so observe==enforce
 *     holds regardless of mount-boundary nuances or truncation.
 *
 * This header is BPF-only. It assumes vmlinux.h, bpf_helpers.h and
 * bpf_core_read.h have already been included by the translation unit.
 */
#ifndef CRI_BPF_H
#define CRI_BPF_H

#include "observ_common.h"   /* FS_EVENT_* operation classes */

/* Canonical path length cap. MUST equal the enforcer whitelist prefix width so
 * observation and enforcement truncate identically. */
#define MAX_PREFIX_LEN 128
#define CRI_MAX_PATH   MAX_PREFIX_LEN

/* Max directory depth walked toward the root. Bounds the dentry-collection
 * loop and the on-stack pointer array (CRI_MAX_DEPTH * 8 bytes). */
#define CRI_MAX_DEPTH  16

/* Max bytes copied per path component. A component longer than this is
 * truncated - identically on both sides, so still consistent. */
#define CRI_NAME_MAX   48

/* open(2) O_CREAT: file_open classifies as CREATE vs OPEN using this, on BOTH
 * the observe and enforce sides, so the two agree. */
#define O_CREAT 0x40

/* iattr->ia_valid bits (not exported into vmlinux BTF, so defined here). Used
 * by inode_setattr to derive CHMOD / CHOWN / TRUNCATE identically on each side. */
#define ATTR_MODE (1 << 0)
#define ATTR_UID  (1 << 1)
#define ATTR_GID  (1 << 2)
#define ATTR_SIZE (1 << 3)

/* ---- whitelist key (shared with enforcer userspace bpf_whitelist_key) ---- */
struct whitelist_key {
    __u64 cgroup_id;
    __u16 event_type;           /* FS_EVENT_*, or 0xFFFF for "any event" */
    __u16 _pad;
    char  path_prefix[MAX_PREFIX_LEN];
};

/*
 * cri_build_path - build the canonical absolute path of `dentry` into `buf`.
 *
 * `buf` MUST be at least CRI_MAX_PATH bytes. Returns the string length (>=1).
 * The result is a normalized absolute path: leading '/', single-'/' separators,
 * no trailing '/' (root is "/"). Long paths / components are truncated at the
 * fixed caps above - deterministically, so both sides agree.
 */
static __always_inline int cri_build_path(struct dentry *dentry, char *buf)
{
    struct dentry *dents[CRI_MAX_DEPTH] = {};
    int n = 0;

    /* Collect dentries from the leaf up toward the filesystem root. */
    #pragma unroll
    for (int i = 0; i < CRI_MAX_DEPTH; i++) {
        if (!dentry)
            break;
        dents[n] = dentry;
        n++;
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (parent == dentry || !parent)
            break;              /* reached the fs root (d_parent == self) */
        dentry = parent;
    }

    int pos = 0;
    /* Assemble forward from just-below-root (index n-2) down to the leaf
     * (index 0). The root slot (n-1) contributes only the leading '/'. */
    #pragma unroll
    for (int i = CRI_MAX_DEPTH - 1; i >= 0; i--) {
        if (i >= n - 1)
            continue;           /* skip out-of-range slots and the root slot */
        /* Stop if there is no room for a '/' plus a full component read; both
         * sides stop at the same point, so truncation stays consistent. */
        if (pos > CRI_MAX_PATH - CRI_NAME_MAX - 1)
            break;
        struct dentry *d = dents[i];
        const unsigned char *name = BPF_CORE_READ(d, d_name.name);
        buf[pos] = '/';
        pos++;
        long l = bpf_probe_read_kernel_str(&buf[pos], CRI_NAME_MAX, name);
        if (l > 1)
            pos += (int)l - 1;  /* exclude the NUL terminator */
    }

    if (pos <= 0) {
        buf[0] = '/';           /* root, or nothing walked */
        buf[1] = '\0';
        return 1;
    }
    if (pos > CRI_MAX_PATH - 1)
        pos = CRI_MAX_PATH - 1;
    buf[pos] = '\0';
    return pos;
}

/*
 * cri_setattr_event - map an iattr->ia_valid bitmask to a single FS_EVENT_*.
 * Used by inode_setattr on BOTH sides so a chmod+chown in one setattr is
 * classified identically (priority: TRUNCATE > CHMOD > CHOWN). Returns 0 if the
 * setattr touches none of the tracked attributes.
 */
static __always_inline __u16 cri_setattr_event(unsigned int ia_valid)
{
    if (ia_valid & ATTR_SIZE)
        return FS_EVENT_TRUNCATE;
    if (ia_valid & ATTR_MODE)
        return FS_EVENT_CHMOD;
    if (ia_valid & (ATTR_UID | ATTR_GID))
        return FS_EVENT_CHOWN;
    return 0;
}

/* Fill key->path_prefix with path[0..plen) followed by zeros, so the key byte-
 * matches a userspace-installed prefix (which is memcpy'd into a zeroed key). */
static __always_inline void cri_set_prefix(struct whitelist_key *key,
                                           const char *path, int plen)
{
    for (int j = 0; j < CRI_MAX_PATH; j++) {
        char c = (j < plen) ? path[j] : '\0';
        key->path_prefix[j] = c;
    }
}

/*
 * cri_check_whitelist - component-boundary prefix match, mirroring the audit
 * engine's AuditEngine::path_matches().
 *
 * A rule prefix P matches `path` iff P is empty, or path == P, or path starts
 * with P followed by '/'. Equivalently, P is one of path's ancestor prefixes at
 * a '/' boundary (or path itself). We enumerate those candidate prefixes and
 * probe the map for both the exact event_type and the 0xFFFF wildcard. The
 * empty-prefix probe covers "allow this event on any path" / "allow everything".
 *
 * Returns 0 if allowed, -1 if denied.
 */
static __always_inline int cri_check_whitelist(void *map, __u64 cgroup_id,
                                               __u16 event_type,
                                               const char *path, int path_len)
{
    struct whitelist_key key = {};
    key.cgroup_id = cgroup_id;

    /* Candidate: empty prefix (event-specific, then global wildcard). */
    key.event_type = event_type;
    if (bpf_map_lookup_elem(map, &key))
        return 0;
    key.event_type = 0xFFFF;
    if (bpf_map_lookup_elem(map, &key))
        return 0;

    if (path_len <= 0)
        return -1;
    if (path_len > CRI_MAX_PATH - 1)
        path_len = CRI_MAX_PATH - 1;

    /* Candidates: every ancestor dir boundary, plus the full path itself. */
    for (int L = 1; L <= CRI_MAX_PATH - 1; L++) {
        if (L > path_len)
            break;
        int is_end = (L == path_len);
        int is_boundary = 0;
        if (!is_end) {
            char c = path[L];
            is_boundary = (c == '/');
        }
        if (!is_boundary && !is_end)
            continue;

        cri_set_prefix(&key, path, L);
        key.event_type = event_type;
        if (bpf_map_lookup_elem(map, &key))
            return 0;
        key.event_type = 0xFFFF;
        if (bpf_map_lookup_elem(map, &key))
            return 0;
    }
    return -1;
}

#endif /* CRI_BPF_H */
