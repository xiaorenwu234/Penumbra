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

/* open(2) flags used by file_open classification. Writable opens are WRITE;
 * inode_create separately records CREATE for newly-created files. */
#define O_CREAT   0x40
#define O_ACCMODE 0x3
#define O_WRONLY  0x1
#define O_RDWR    0x2
#define O_TRUNC   0x200
#define O_APPEND  0x400
#define MAY_WRITE 0x2

static __always_inline __u16 cri_open_event(unsigned int flags)
{
    unsigned int acc = flags & O_ACCMODE;
    if (acc == O_WRONLY || acc == O_RDWR || (flags & (O_TRUNC | O_APPEND)))
        return FS_EVENT_WRITE;
    return FS_EVENT_OPEN;
}

/* iattr->ia_valid bits (not exported into vmlinux BTF, so defined here). Used
 * by inode_setattr to derive CHMOD / CHOWN / TRUNCATE identically on each side. */
#define ATTR_MODE (1 << 0)
#define ATTR_UID  (1 << 1)
#define ATTR_GID  (1 << 2)
#define ATTR_SIZE (1 << 3)

/* ---- whitelist key (shared with enforcer userspace bpf_whitelist_key) ---- */
/* event_type is the encoded (effect_class | operation<<8) value, or 0xFFFF
 * for "any event".  See effect_schema.h for the encoding and legacy aliases. */
struct whitelist_key {
    __u64 cgroup_id;
    __u16 event_type;           /* encoded class+op, or 0xFFFF for wildcard */
    __u16 _pad;
    char  path_prefix[MAX_PREFIX_LEN];
};

/*
 * cri_build_path_bounds - build the canonical absolute path of `dentry` into
 * `buf`, and optionally record its component-boundary prefix lengths.
 *
 * `buf` MUST be at least CRI_MAX_PATH bytes.
 *
 * `cand`, if non-NULL, MUST be at least CRI_MAX_DEPTH bytes and receives the
 * candidate prefix lengths for whitelist matching: after each component is
 * appended, the running length is exactly one of the path's ancestor prefixes
 * (the last one being the full path). Unused slots are left 0, which is never
 * a valid length, so 0 reliably means "empty slot". Collecting them HERE is
 * free -- this loop already knows every boundary, and it is unrolled, so the
 * stores use compile-time indices. The alternative (rescanning all
 * CRI_MAX_PATH byte offsets for '/' in the matcher) is what made the enforcer
 * unverifiable; see cri_check_whitelist().
 *
 * Returns the string length (>=1) on success. The result is a normalized
 * absolute path: leading '/', single-'/' separators, no trailing '/' (root
 * is "/").
 *
 * FAIL-CLOSED: returns a NEGATIVE value when the path cannot be represented
 * EXACTLY, instead of emitting a truncated path that "looks valid" — such a
 * path could match a shorter whitelist prefix and diverge observation from
 * enforcement:
 *   -1  path deeper than CRI_MAX_DEPTH (walk never reached the fs root, so
 *       the top ancestors are unknown)
 *   -2  a path component could not be read
 *   -3  a path component exceeds CRI_NAME_MAX (would be truncated)
 *   -4  the CRI_MAX_PATH buffer filled before the leaf (suffix would be lost)
 * Callers MUST deny (enforce side) or flag the event (observe side) on any
 * negative return. cri_check_whitelist() already denies path_len <= 0, so
 * the enforce side fails closed automatically.
 */
static __always_inline int cri_build_path_bounds(struct dentry *dentry, char *buf,
                                                 __u8 *cand)
{
    struct dentry *dents[CRI_MAX_DEPTH] = {};
    int n = 0;
    int hit_root = 0;

    if (cand)
        __builtin_memset(cand, 0, CRI_MAX_DEPTH);

    /* Collect dentries from the leaf up toward the filesystem root. */
    #pragma unroll
    for (int i = 0; i < CRI_MAX_DEPTH; i++) {
        if (!dentry)
            break;
        dents[n] = dentry;
        n++;
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (parent == dentry || !parent) {
            hit_root = 1;       /* reached the fs root (d_parent == self) */
            break;
        }
        dentry = parent;
    }

    /* The walk MUST converge on the filesystem root. If it stopped because
     * the depth cap was hit, the path's top ancestors are unknown and any
     * path built here would be a shorter, DIFFERENT path — deny. */
    if (!hit_root)
        return -1;

    int pos = 0;
    /* Assemble forward from just-below-root (index n-2) down to the leaf
     * (index 0). The root slot (n-1) contributes only the leading '/'. */
    #pragma unroll
    for (int i = CRI_MAX_DEPTH - 1; i >= 0; i--) {
        if (i >= n - 1)
            continue;           /* skip out-of-range slots and the root slot */
        /* No room for a '/' plus a full component read: the remaining
         * components would be silently dropped, truncating the path — deny. */
        if (pos > CRI_MAX_PATH - CRI_NAME_MAX - 1)
            return -4;
        struct dentry *d = dents[i];
        const unsigned char *name = BPF_CORE_READ(d, d_name.name);
        buf[pos] = '/';
        pos++;
        long l = bpf_probe_read_kernel_str(&buf[pos], CRI_NAME_MAX, name);
        if (l <= 0)
            return -2;          /* component unreadable */
        if (l >= CRI_NAME_MAX)
            return -3;          /* component truncated */
        pos += (int)l - 1;      /* exclude the NUL terminator */
        if (cand)
            cand[i] = (__u8)pos;  /* constant index: this loop is unrolled */
    }

    if (pos <= 0) {
        buf[0] = '/';           /* root, or nothing walked */
        buf[1] = '\0';
        if (cand)
            cand[0] = 1;        /* the only candidate prefix is "/" itself */
        return 1;
    }
    if (pos > CRI_MAX_PATH - 1)
        pos = CRI_MAX_PATH - 1;
    buf[pos] = '\0';
    return pos;
}

/* Path only, for callers that do not match against the whitelist (observer). */
static __always_inline int cri_build_path(struct dentry *dentry, char *buf)
{
    return cri_build_path_bounds(dentry, buf, NULL);
}

/*
 * cri_setattr_event - map an iattr->ia_valid bitmask to a single FS_EVENT_*.
 * Used by inode_setattr on BOTH sides so a chmod+chown in one setattr is
 * classified identically (priority: WRITE/TRUNCATE > CHMOD > CHOWN). Returns 0 if the
 * setattr touches none of the tracked attributes.
 */
static __always_inline __u16 cri_setattr_event(unsigned int ia_valid)
{
    if (ia_valid & ATTR_SIZE)
        return FS_EVENT_WRITE;
    if (ia_valid & ATTR_MODE)
        return FS_EVENT_CHMOD;
    if (ia_valid & (ATTR_UID | ATTR_GID))
        return FS_EVENT_CHOWN;
    return 0;
}

/* Fill key->path_prefix with path[0..plen) followed by zeros, so the key byte-
 * matches a userspace-installed prefix (which is memcpy'd into a zeroed key).
 *
 * `plen` MUST be in [0, CRI_MAX_PATH-1]; callers guarantee this by rejecting
 * longer paths outright (fail-closed).
 *
 * VERIFIER COST: this runs once per candidate prefix, so it must be cheap to
 * VERIFY, not just to execute. A per-byte copy loop is the trap: CRI_MAX_PATH
 * iterations of a handful of instructions each, re-verified for every candidate
 * length, costs O(CRI_MAX_PATH^2) processed instructions and (with the branch
 * states it forks) pushes prog load past the verifier's 1M ceiling -> -E2BIG.
 * A constant-size memset plus one variable-length helper read compiles to a
 * dozen wide stores and a single call, with no loop for the verifier to walk. */
static __always_inline void cri_set_prefix(struct whitelist_key *key,
                                           const char *path, int plen)
{
    __builtin_memset(key->path_prefix, 0, CRI_MAX_PATH);
    if (plen > 0)
        bpf_probe_read_kernel(key->path_prefix,
                              plen & (CRI_MAX_PATH - 1), path);
}

/*
 * cri_check_whitelist - component-boundary prefix match, mirroring the audit
 * engine's AuditEngine::path_matches().
 *
 * A rule prefix P matches `path` iff P is empty, or path == P, or path starts
 * with P followed by '/'. Equivalently, P is one of path's ancestor prefixes at
 * a '/' boundary (or path itself). `cand` carries exactly that set of lengths,
 * recorded by cri_build_path_bounds(); we probe each for both the exact
 * event_type and the 0xFFFF wildcard. The empty-prefix probe (done first, and
 * not part of `cand`) covers "allow this event on any path" / "allow everything".
 *
 * VERIFIER COMPLEXITY: the trip count here is the binding constraint on whether
 * the enforcer loads at all. Deriving the candidates by scanning every byte
 * offset for '/' means CRI_MAX_PATH iterations, and because the body forks
 * several branch states per iteration (two map lookups plus the boundary test)
 * the verifier's work grows superlinearly with the trip count -- 128 offsets
 * exhausted the 1M processed-instruction budget and prog load failed with
 * -E2BIG. Iterating the CRI_MAX_DEPTH precomputed boundaries instead probes the
 * IDENTICAL set of keys with an 8x smaller trip count.
 *
 * Returns 0 if allowed, -1 if denied.
 */
static __always_inline int cri_check_whitelist(void *map, __u64 cgroup_id,
                                               __u16 event_type,
                                               const char *path, int path_len,
                                               const __u8 *cand)
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
        return -1;   /* path cannot be fully represented -> deny (fail-closed),
                       * NOT match a short truncated prefix that could widen */

    /* Candidates: every ancestor dir boundary, plus the full path itself. */
    for (int i = 0; i < CRI_MAX_DEPTH; i++) {
        int L = cand[i];
        if (L <= 0 || L > path_len)
            continue;           /* empty slot, or beyond this path */

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
