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
#include <bpf/bpf_endian.h>

// -ERESTARTSYS: kernel will auto-restart syscall after signal handling
#define ERESTARTSYS 512

// Operations per class (from unified schema, policy_generated.rs).
// These must match EFFECT_OP_* in policy_generated.rs exactly.
#define EFFECT_OP_CONNECT         1
#define EFFECT_OP_BIND            2
#define EFFECT_OP_SEND            3
#define EFFECT_OP_PIPE_WRITE      1
#define EFFECT_OP_UNIX_WRITE      2
#define EFFECT_OP_SYSV_SHM        3
#define EFFECT_OP_SYSV_MSG        4
#define EFFECT_OP_SYSV_SEM        5
#define EFFECT_OP_POSIX_MQ        6
#define EFFECT_OP_SHARED_MAPPING  7
#define EFFECT_OP_KILL            1
#define EFFECT_OP_PTRACE          2
#define EFFECT_OP_EXEC_PRIV       1
#define EFFECT_OP_SETUID          2
#define EFFECT_OP_SETGID          3
#define EFFECT_OP_SETGROUPS       4
#define EFFECT_OP_CAPSET          5
#define EFFECT_OP_WRITE_OUT       1
#define EFFECT_OP_SENDFILE        2
#define EFFECT_OP_SPLICE          3
#define EFFECT_OP_IO_URING        4
#define EFFECT_OP_MOUNT           1
#define EFFECT_OP_NAMESPACE       2
#define EFFECT_OP_KEYRING         3
#define EFFECT_OP_BPF             4
#define EFFECT_OP_PERF            5
#define EFFECT_OP_TTY_IOCTL       6
#define EFFECT_OP_PROCESS_VM      7

// Encode (effect_class, operation) into a single uint16 event_type.
// Layout: low byte = effect_class, high byte = operation. This matches
// encode_event_type() in policy_generated.rs and the anonymous-union overlay
// in struct effect_event, so every consumer decodes via (ty & 0xFF) / (ty>>8).
#define ENCODE_EVENT(cls, op) ((__u32)(cls) | ((__u32)(op) << 8))

// Event types — unified schema encoding (P0-6). Each hook emits the specific
// (class, op) pair so userspace can route on effect_class without a hand-
// maintained 1..N table. EXIT_HOLD reuses NETWORK/CONNECT because the
// sentinel is a cooperative connect(); syscall_nr=231 (exit_group)
// distinguishes it at the consumers (see InterceptEvent::is_exit_hold).
#define EVENT_NETWORK_CONNECT  ENCODE_EVENT(EFFECT_CLASS_NETWORK, EFFECT_OP_CONNECT)     // 258
#define EVENT_NETWORK_BIND     ENCODE_EVENT(EFFECT_CLASS_NETWORK, EFFECT_OP_BIND)        // 514
#define EVENT_NETWORK_SEND     ENCODE_EVENT(EFFECT_CLASS_NETWORK, EFFECT_OP_SEND)        // 770
#define EVENT_IPC_SHM          ENCODE_EVENT(EFFECT_CLASS_IPC, EFFECT_OP_SYSV_SHM)        // 771
#define EVENT_IPC_MSG          ENCODE_EVENT(EFFECT_CLASS_IPC, EFFECT_OP_SYSV_MSG)        // 1027
#define EVENT_IPC_SEM          ENCODE_EVENT(EFFECT_CLASS_IPC, EFFECT_OP_SYSV_SEM)        // 1283
#define EVENT_IPC_MQ           ENCODE_EVENT(EFFECT_CLASS_IPC, EFFECT_OP_POSIX_MQ)        // 1539
#define EVENT_IPC_MMAP         ENCODE_EVENT(EFFECT_CLASS_IPC, EFFECT_OP_SHARED_MAPPING)  // 1795
#define EVENT_SIGNAL_KILL      ENCODE_EVENT(EFFECT_CLASS_SIGNAL, EFFECT_OP_KILL)         // 260
#define EVENT_SIGNAL_PTRACE    ENCODE_EVENT(EFFECT_CLASS_SIGNAL, EFFECT_OP_PTRACE)       // 516
#define EVENT_PRIV_EXEC        ENCODE_EVENT(EFFECT_CLASS_PRIVILEGE, EFFECT_OP_EXEC_PRIV) // 261
#define EVENT_PRIV_SETUID      ENCODE_EVENT(EFFECT_CLASS_PRIVILEGE, EFFECT_OP_SETUID)   // 517
#define EVENT_PRIV_SETGID      ENCODE_EVENT(EFFECT_CLASS_PRIVILEGE, EFFECT_OP_SETGID)   // 773
#define EVENT_PRIV_SETGROUPS   ENCODE_EVENT(EFFECT_CLASS_PRIVILEGE, EFFECT_OP_SETGROUPS)// 1029
#define EVENT_PRIV_CAPSET      ENCODE_EVENT(EFFECT_CLASS_PRIVILEGE, EFFECT_OP_CAPSET)   // 1285
#define EVENT_OUTPUT_WRITE     ENCODE_EVENT(EFFECT_CLASS_OUTPUT, EFFECT_OP_WRITE_OUT)    // 262
#define EVENT_OUTPUT_SENDFILE  ENCODE_EVENT(EFFECT_CLASS_OUTPUT, EFFECT_OP_SENDFILE)     // 518
#define EVENT_OUTPUT_SPLICE    ENCODE_EVENT(EFFECT_CLASS_OUTPUT, EFFECT_OP_SPLICE)       // 774
#define EVENT_OUTPUT_IO_URING  ENCODE_EVENT(EFFECT_CLASS_OUTPUT, EFFECT_OP_IO_URING)     // 1030
#define EVENT_SYSTEM_MOUNT     ENCODE_EVENT(EFFECT_CLASS_SYSTEM, EFFECT_OP_MOUNT)        // 263
#define EVENT_SYSTEM_NAMESPACE ENCODE_EVENT(EFFECT_CLASS_SYSTEM, EFFECT_OP_NAMESPACE)    // 519
#define EVENT_SYSTEM_KEYRING   ENCODE_EVENT(EFFECT_CLASS_SYSTEM, EFFECT_OP_KEYRING)      // 775
#define EVENT_SYSTEM_BPF       ENCODE_EVENT(EFFECT_CLASS_SYSTEM, EFFECT_OP_BPF)          // 1031
#define EVENT_SYSTEM_PERF      ENCODE_EVENT(EFFECT_CLASS_SYSTEM, EFFECT_OP_PERF)         // 1287
#define EVENT_SYSTEM_TTY_IOCTL ENCODE_EVENT(EFFECT_CLASS_SYSTEM, EFFECT_OP_TTY_IOCTL)    // 1543
#define EVENT_SYSTEM_PROCESS_VM ENCODE_EVENT(EFFECT_CLASS_SYSTEM, EFFECT_OP_PROCESS_VM)  // 1799
#define EVENT_EXIT_HOLD        ENCODE_EVENT(EFFECT_CLASS_NETWORK, EFFECT_OP_CONNECT)     // 258 (syscall_nr=231)
// FORK is a process lifecycle event, not an auditable effect; it uses the
// legacy_unmapped value (101) so it is never confused with an effect class.
#define EVENT_FORK             101

// ═══════════════════════════════════════════════════════════════
// Phase 2: Three-state model constants
// ═══════════════════════════════════════════════════════════════

// Epoch modes per cgroup
#define MODE_SPECULATIVE        0  // fence all external effects (reversible)
#define MODE_AUTHORIZED_PENDING 1  // policy pending; still fence (process not running)
#define MODE_ENFORCED           2  // policy installed; deny unallowed, allow allowed

// Decisions returned by check_policy()
#define DECISION_ALLOW  0  // let syscall proceed
#define DECISION_FENCE  1  // block + SIGSTOP + notify (reversible)
#define DECISION_DENY   2  // hard -EPERM (policy is final)

// Effect classes (from unified schema, policy_generated.rs)
#define EFFECT_CLASS_NETWORK    2
#define EFFECT_CLASS_IPC        3
#define EFFECT_CLASS_SIGNAL     4
#define EFFECT_CLASS_PRIVILEGE  5
#define EFFECT_CLASS_OUTPUT     6
#define EFFECT_CLASS_SYSTEM     7

// EPERM for hard deny
#define EPERM 1

// File types
#define S_IFIFO  0010000
#define S_IFCHR  0020000
#define S_IFSOCK 0140000
#define S_IFMT   0170000

struct event {
    __u32 pid;
    __u32 tgid;
    __u32 syscall_nr;
    __u32 event_type;
    __u64 timestamp;
    __u64 cgroup_id;
    __u8 decision;
    __u8 _pad0[7];
    char comm[16];
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Counts policy/intercept events that could not be emitted. Userspace treats a
// non-zero delta as an audit-completeness failure rather than silently losing a
// DENY or FENCE decision.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_events SEC(".maps");

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
// SIZING (applies to stopped_pids): 4096
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

// ═══════════════════════════════════════════════════════════════
// Phase 2: Three-state model maps
// ═══════════════════════════════════════════════════════════════

// Epoch mode per cgroup. Absent = MODE_SPECULATIVE (default fence-all).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    // cgroup id
    __type(value, __u8);   // MODE_*
} epoch_mode SEC(".maps");

// Operation policy: per (cgroup, effect_class, operation) -> allow/fine/deny.
// Only consulted in MODE_ENFORCED.
// SIZING: one enforce_allow_all installs ~40 entries per cgroup (12 FS + 3
// NET + 7 IPC + 2 SIG + 5 PRIV + 4 OUT + 7 SYS). Entries are reclaimed when
// the cgroup is removed; 4096 headroom keeps a long-lived daemon healthy even
// if a few sessions leak entries through cleanup races.
struct class_policy_key {
    __u64 cgroup_id;
    __u8  effect_class;
    __u8  operation;
    __u8  _pad0[6];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct class_policy_key);
    __type(value, __u8);  // 1=allow, 0=deny
} class_policy SEC(".maps");

// Network policy: per (cgroup, family, addr, port) -> allow/deny.
struct net_policy_key {
    __u64 cgroup_id;
    __u8  family;
    __u8  operation;
    __u16 port;
    __u32 addr;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct net_policy_key);
    __type(value, __u8);
} network_policy SEC(".maps");

// IPC policy: per (cgroup, ipc_type, target) -> allow/deny.
struct ipc_policy_key {
    __u64 cgroup_id;
    __u8  ipc_type;
    __u8  operation;
    __u8  _pad0[6];
    __u64 target;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ipc_policy_key);
    __type(value, __u8);
} ipc_policy SEC(".maps");

// Signal policy: per (cgroup, target_cgroup) -> allow/deny.
struct sig_policy_key {
    __u64 cgroup_id;
    __u8  operation;
    __u8  _pad0[7];
    __u64 target_cgroup;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct sig_policy_key);
    __type(value, __u8);
} signal_policy SEC(".maps");

// ═══════════════════════════════════════════════════════════════
// Fine-grained policy (P0-5): per-effect endpoint descriptor.
// Hooks fill what they can parse; in MODE_ENFORCED a class_policy value of
// CLASS_POLICY_FINE makes check_policy_detail() consult the per-endpoint
// maps above (default-deny at the endpoint level). Endpoints the hook could
// not parse can never match a fine entry — they fail closed (DENY).
// ═══════════════════════════════════════════════════════════════

// class_policy value semantics:
#define CLASS_POLICY_ALLOW 1  // class-wide allow
#define CLASS_POLICY_FINE  2  // consult network/ipc/signal fine-grained maps

// IPC sub-types for ipc_policy_key.ipc_type / effect_detail.ipc_type
#define IPC_TYPE_SHM   1
#define IPC_TYPE_MSG   2
#define IPC_TYPE_SEM   3
#define IPC_TYPE_MQ    4
#define IPC_TYPE_MMAP  5

struct effect_detail {
    __u8  family;     // network: AF_* (0 = unparsed)
    __u8  _pad0;
    __u16 port;       // network: host-order port (0 = any/none)
    __u32 addr;       // network: host-order IPv4 (0 = any/none)
    __u8  ipc_type;   // ipc: IPC_TYPE_* (0 = none)
    __u8  _pad1[7];
    __u64 target;     // ipc: SysV key / inode no; signal: target cgroup id
};

// One-shot restart token: per tid -> (syscall_nr, effect_class, operation).
// Consumed (deleted) on first match. Grants a single syscall pass.
struct restart_token_val {
    __u32 syscall_nr;
    __u8  effect_class;
    __u8  operation;
    __u8  _pad0[2];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);    // tid (not tgid)
    __type(value, struct restart_token_val);
} restart_token SEC(".maps");

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

// ═══════════════════════════════════════════════════════════════
// Phase 2: Three-state decision logic
//
// check_policy() replaces should_intercept(). It returns:
//   DECISION_ALLOW  - let the syscall proceed
//   DECISION_FENCE  - block + SIGSTOP + notify userspace (reversible)
//   DECISION_DENY   - hard -EPERM (policy is final, irreversible)
//
// The decision depends on the cgroup's epoch mode:
//   MODE_SPECULATIVE        - fence all external effects
//   MODE_AUTHORIZED_PENDING - still fence (process not running until policy installed)
//   MODE_ENFORCED           - consult policy maps; allow if policy permits, deny otherwise
//
// A one-shot restart token (per tid) is checked FIRST in all modes:
// if a token matches the current syscall, it is consumed and the syscall
// is allowed. This replaces the old permanent allowed_pids bypass with
// per-syscall granularity: only the specific authorized syscall passes,
// and the token is deleted immediately after use.
// ═══════════════════════════════════════════════════════════════

// Fine-grained network check (MODE_ENFORCED + class mode CLASS_POLICY_FINE).
// Most-specific entry first: (family,addr,port) -> (family,addr,any-port) ->
// (family,any-addr,port) -> (family,any-endpoint). A found entry's value
// decides (1=allow, 0=explicit deny, short-circuiting the fallback chain);
// no entry anywhere = deny. An endpoint the hook could not parse
// (family == 0) can never match -> deny (fail-closed).
static __always_inline int net_detail_allows(__u64 cg, __u8 operation,
                                             const struct effect_detail *d)
{
    if (!d || d->family == 0)
        return 0;
    struct net_policy_key key = {};
    key.cgroup_id = cg;
    key.family = d->family;
    key.operation = operation;
    __u8 *v;
    key.addr = d->addr;
    key.port = d->port;
    v = bpf_map_lookup_elem(&network_policy, &key);
    if (v)
        return *v ? 1 : 0;
    if (d->port) {
        key.port = 0;
        v = bpf_map_lookup_elem(&network_policy, &key);
        if (v)
            return *v ? 1 : 0;
    }
    if (d->addr) {
        key.addr = 0;
        key.port = d->port;
        v = bpf_map_lookup_elem(&network_policy, &key);
        if (v)
            return *v ? 1 : 0;
    }
    key.addr = 0;
    key.port = 0;
    v = bpf_map_lookup_elem(&network_policy, &key);
    if (v)
        return *v ? 1 : 0;
    return 0;
}

// Fine-grained IPC check: (ipc_type,target) -> (ipc_type,any-target).
// An unparsed endpoint (ipc_type == 0) can never match -> deny.
static __always_inline int ipc_detail_allows(__u64 cg, __u8 operation,
                                             const struct effect_detail *d)
{
    if (!d || d->ipc_type == 0)
        return 0;
    struct ipc_policy_key key = {};
    key.cgroup_id = cg;
    key.ipc_type = d->ipc_type;
    key.operation = operation;
    __u8 *v;
    key.target = d->target;
    v = bpf_map_lookup_elem(&ipc_policy, &key);
    if (v)
        return *v ? 1 : 0;
    if (d->target) {
        key.target = 0;
        v = bpf_map_lookup_elem(&ipc_policy, &key);
        if (v)
            return *v ? 1 : 0;
    }
    return 0;
}

// Fine-grained signal check: (target_cgroup) -> (any-target).
// d == NULL or target == 0 means the hook could not resolve the target
// cgroup: only an explicit any-target entry can allow it.
static __always_inline int sig_detail_allows(__u64 cg, __u8 operation,
                                             const struct effect_detail *d)
{
    struct sig_policy_key key = {};
    key.cgroup_id = cg;
    key.operation = operation;
    key.target_cgroup = d ? d->target : 0;
    __u8 *v = bpf_map_lookup_elem(&signal_policy, &key);
    if (v)
        return *v ? 1 : 0;
    if (key.target_cgroup) {
        key.target_cgroup = 0;
        v = bpf_map_lookup_elem(&signal_policy, &key);
        if (v)
            return *v ? 1 : 0;
    }
    return 0;
}

// Three-state decision for a syscall + encoded event_type (+ endpoint detail).
static __always_inline int check_policy_detail(__u32 syscall_nr, __u32 event_type,
                                               const struct effect_detail *d)
{
    __u8 effect_class = (__u8)(event_type & 0xFF);
    __u8 operation = (__u8)((event_type >> 8) & 0xFF);

    if (!is_enabled() || !check_cgroup())
        return DECISION_ALLOW;  // not monitored -> no interception

    __u64 cg = bpf_get_current_cgroup_id();
    __u8 *mode_p = bpf_map_lookup_elem(&epoch_mode, &cg);
    __u8 mode = mode_p ? *mode_p : MODE_SPECULATIVE;

    // One-shot restart token: checked first in ALL modes.
    // If a token matches this tid + syscall_nr, consume it and allow.
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct restart_token_val *tok = bpf_map_lookup_elem(&restart_token, &tid);
    if (tok && tok->syscall_nr == syscall_nr &&
        tok->effect_class == effect_class && tok->operation == operation) {
        bpf_map_delete_elem(&restart_token, &tid);  // consume
        return DECISION_ALLOW;
    }

    if (mode == MODE_SPECULATIVE || mode == MODE_AUTHORIZED_PENDING)
        return DECISION_FENCE;  // block + notify, reversible

    // MODE_ENFORCED: consult the operation policy first.
    // NOTE: we deliberately do NOT pass merely because stopped_pids is set.
    // A set mark means a group-directed SIGSTOP is already in flight for this
    // tgid, but sibling threads keep running until the stop lands. In ENFORCED
    // mode those siblings get DECISION_DENY (hard -EPERM), which is fail-closed:
    // the syscall does not execute. In SPECULATIVE/AUTHORIZED_PENDING they get
    // DECISION_FENCE, routed through do_intercept() which dedups the in-flight
    // stop (no duplicate event/SIGSTOP) while still returning -ERESTARTSYS.
    struct class_policy_key ckey = {};
    ckey.cgroup_id = cg;
    ckey.effect_class = effect_class;
    ckey.operation = operation;
    __u8 *cv = bpf_map_lookup_elem(&class_policy, &ckey);
    __u8 cval = cv ? *cv : 0;
    if (cval == CLASS_POLICY_ALLOW)
        return DECISION_ALLOW;
    if (cval != CLASS_POLICY_FINE)
        return DECISION_DENY;  // absent / explicit class-level deny

    // CLASS_POLICY_FINE: consult the per-endpoint maps (default-deny at the
    // endpoint level; unparseable endpoints fail closed inside the helpers).
    switch (effect_class) {
    case EFFECT_CLASS_NETWORK:
        return net_detail_allows(cg, operation, d) ? DECISION_ALLOW : DECISION_DENY;
    case EFFECT_CLASS_IPC:
        return ipc_detail_allows(cg, operation, d) ? DECISION_ALLOW : DECISION_DENY;
    case EFFECT_CLASS_SIGNAL:
        return sig_detail_allows(cg, operation, d) ? DECISION_ALLOW : DECISION_DENY;
    default:
        // PRIVILEGE / OUTPUT have no fine-grained map: fine mode is
        // unenforceable for them -> deny (fail-closed).
        return DECISION_DENY;
    }
}

// Three-state decision without endpoint detail. In MODE_ENFORCED fine mode
// the missing endpoint can never match a fine entry -> deny (fail-closed).
static __always_inline int check_policy(__u32 syscall_nr, __u32 event_type)
{
    return check_policy_detail(syscall_nr, event_type, NULL);
}

static __always_inline void count_dropped_event(void)
{
    __u32 key = 0;
    __u64 init = 1;
    __u64 *cnt = bpf_map_lookup_elem(&dropped_events, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    else
        bpf_map_update_elem(&dropped_events, &key, &init, BPF_ANY);
}

static __always_inline void emit_policy_event(__u32 syscall_nr, __u32 event_type,
                                              __u8 decision)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_dropped_event();
        return;
    }
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->syscall_nr = syscall_nr;
    e->event_type = event_type;
    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->decision = decision;
    e->_pad0[0] = 0;
    e->_pad0[1] = 0;
    e->_pad0[2] = 0;
    e->_pad0[3] = 0;
    e->_pad0[4] = 0;
    e->_pad0[5] = 0;
    e->_pad0[6] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_policy_violation(__u32 syscall_nr,
                                                  __u32 event_type)
{
    emit_policy_event(syscall_nr, event_type, DECISION_DENY);
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

    emit_policy_event(syscall_nr, event_type, DECISION_FENCE);

    // SIGSTOP the process. If the signal could not be queued we must NOT leave
    // the tgid marked stopped: otherwise check_policy() would treat a
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
// Network address-family filtering.
//
// SCOPE: outbound association is intercepted as NETWORK operations. AF_NETLINK
// and AF_UNIX are NOT hard-coded bypasses: they are policy-governed operations
// because netlink can mutate kernel state and abstract/pathname Unix sockets are
// host-visible IPC channels that mount namespaces do not isolate.
//
// Exempt (not external):
//   - AF_UNSPEC (connect(AF_UNSPEC) just dissolves association)
// ═══════════════════════════════════════════════════════════════

#define AF_UNSPEC   0
#define AF_UNIX     1
#define AF_INET     2
#define AF_INET6    10

// Classify a connect()/bind() target. Returns 1 if it should be intercepted.
// `address` is a kernel copy (sockaddr_storage, 128 bytes), safe to over-read.
static __always_inline int net_addr_should_block(struct sockaddr *address, int addrlen)
{
    __u16 family = 0;
    if (addrlen >= 2)
        bpf_probe_read_kernel(&family, sizeof(family), address);

    if (family == AF_UNSPEC)
        return 0;  // exempt: disconnect-only association reset

    // AF_NETLINK, AF_UNIX, AF_INET/6, AF_PACKET, ... are policy-governed.
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
    // process completion. In the three-state model, the sentinel is handled
    // by check_policy(): if the orchestrator has granted a restart_token for
    // this tid+syscall, the token is consumed and the sentinel passes (full
    // release). Without a token, SPECULATIVE/AUTHORIZED_PENDING fence it,
    // and ENFORCED denies it (policy is final).
    if (addrlen >= 16) { // sizeof(struct sockaddr_in)
        __u16 family = 0;
        __u16 port = 0;
        __u32 ip = 0;
        bpf_probe_read_kernel(&family, 2, (void *)address);
        bpf_probe_read_kernel(&port, 2, (void *)address + 2);
        bpf_probe_read_kernel(&ip, 4, (void *)address + 4);
        // AF_INET=2, port=65535 (0xFFFF in network order), ip=192.0.2.255 (0xFF0200C0 on LE)
        if (family == 2 && port == 0xFFFF && ip == 0xFF0200C0) {
            int d = check_policy(42, EVENT_EXIT_HOLD);
            if (d == DECISION_ALLOW)
                return 0;
            if (d == DECISION_FENCE) {
                do_intercept(231, EVENT_EXIT_HOLD);
                return -ERESTARTSYS;
            }
            emit_policy_violation(231, EVENT_EXIT_HOLD);
            return -EPERM;  // DECISION_DENY: hard deny sentinel
        }
    }

    // General (non-sentinel) case: three-state enforcement. Parse the
    // endpoint for the fine-grained network policy (host-order addr/port;
    // unparsed fields stay 0 and can only match wildcard entries).
    struct effect_detail det = {};
    __u16 cfam = 0;
    if (addrlen >= 2)
        bpf_probe_read_kernel(&cfam, 2, (void *)address);
    det.family = (__u8)cfam;
    if (cfam == AF_INET && addrlen >= 8) {
        __u16 port_be = 0;
        __u32 addr_n = 0;
        bpf_probe_read_kernel(&port_be, 2, (void *)address + 2);
        bpf_probe_read_kernel(&addr_n, 4, (void *)address + 4);
        det.port = __bpf_ntohs(port_be);
        det.addr = __bpf_ntohl(addr_n);
    }
    int d = check_policy_detail(42, EVENT_NETWORK_CONNECT, &det);
    if (d == DECISION_ALLOW)
        return 0;

    // For FENCE and DENY, still allow only AF_UNSPEC disconnects. AF_NETLINK
    // and AF_UNIX are policy-governed and must be explicitly allowed.
    if (!net_addr_should_block(address, addrlen))
        return 0;

    if (d == DECISION_FENCE) {
        do_intercept(42, EVENT_NETWORK_CONNECT);
        return -ERESTARTSYS;
    }
    emit_policy_violation(42, EVENT_NETWORK_CONNECT);
    return -EPERM;  // DECISION_DENY
}

// --- Network: sendmsg (covers sendto, sendmsg) ---
SEC("lsm/socket_sendmsg")
int BPF_PROG(shadow_socket_sendmsg, struct socket *sock,
             struct msghdr *msg, int size)
{
    // Resolve the endpoint up front: the fine-grained network policy is
    // keyed by (family, addr, port) when class_policy selects fine mode.
    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u16 family = sk ? BPF_CORE_READ(sk, __sk_common.skc_family) : 0;
    struct effect_detail det = {};
    det.family = (__u8)family;
    if (family == AF_INET && sk) {
        det.addr = __bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
        det.port = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    }
    int d = check_policy_detail(46, EVENT_NETWORK_SEND, &det);
    if (d == DECISION_ALLOW)
        return 0;

    if (family == AF_UNSPEC)
        return 0;  // exempt: disconnect-only association reset

    // AF_NETLINK and AF_UNIX are policy-governed. Abstract Unix sockets are not
    // mount-namespace isolated, so no pathname-prefix whitelist is applied.

    // External destination (AF_INET / AF_INET6 / AF_NETLINK / AF_UNIX / other).
    if (d == DECISION_FENCE) {
        do_intercept(46, EVENT_NETWORK_SEND);
        return -ERESTARTSYS;
    }
    emit_policy_violation(46, EVENT_NETWORK_SEND);
    return -EPERM;  // DECISION_DENY
}

// --- Network: bind ---
SEC("lsm/socket_bind")
int BPF_PROG(shadow_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    struct effect_detail det = {};
    __u16 bfam = 0;
    if (addrlen >= 2)
        bpf_probe_read_kernel(&bfam, 2, (void *)address);
    det.family = (__u8)bfam;
    if (bfam == AF_INET && addrlen >= 8) {
        __u16 port_be = 0;
        __u32 addr_n = 0;
        bpf_probe_read_kernel(&port_be, 2, (void *)address + 2);
        bpf_probe_read_kernel(&addr_n, 4, (void *)address + 4);
        det.port = __bpf_ntohs(port_be);
        det.addr = __bpf_ntohl(addr_n);
    }
    int d = check_policy_detail(49, EVENT_NETWORK_BIND, &det);
    if (d == DECISION_ALLOW)
        return 0;
    // For FENCE and DENY, allow only AF_UNSPEC disconnect/reset binds.
    if (!net_addr_should_block(address, addrlen))
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(49, EVENT_NETWORK_BIND);
        return -ERESTARTSYS;
    }
    emit_policy_violation(49, EVENT_NETWORK_BIND);
    return -EPERM;  // DECISION_DENY
}

// ── SysV shared memory (shm) ──────────────────────────────────
// shmget: alloc_security fires when creating a new segment,
//         associate fires when attaching to an existing key.
// Together they cover every shmget() call.
SEC("lsm/shm_alloc_security")
int BPF_PROG(shadow_shm_alloc, struct kern_ipc_perm *perm)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SHM;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(29, EVENT_IPC_SHM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(29, EVENT_IPC_SHM); // 29 = shmget
        return -ERESTARTSYS;
    }
    emit_policy_violation(29, EVENT_IPC_SHM);
    return -EPERM;
}

SEC("lsm/shm_associate")
int BPF_PROG(shadow_shm_associate, struct kern_ipc_perm *perm, int shmflg)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SHM;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(29, EVENT_IPC_SHM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(29, EVENT_IPC_SHM); // 29 = shmget
        return -ERESTARTSYS;
    }
    emit_policy_violation(29, EVENT_IPC_SHM);
    return -EPERM;
}

// --- IPC: shmat ---
SEC("lsm/shm_shmat")
int BPF_PROG(shadow_shm_shmat, struct kern_ipc_perm *shp,
             char *shmaddr, int shmflg)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SHM;
    det.target = (__u64)(__u32)BPF_CORE_READ(shp, key);
    int d = check_policy_detail(30, EVENT_IPC_SHM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(30, EVENT_IPC_SHM); // 30 = shmat
        return -ERESTARTSYS;
    }
    emit_policy_violation(30, EVENT_IPC_SHM);
    return -EPERM;
}

// --- IPC: shmctl ---
SEC("lsm/shm_shmctl")
int BPF_PROG(shadow_shm_shmctl, struct kern_ipc_perm *perm, int cmd)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SHM;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(31, EVENT_IPC_SHM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(31, EVENT_IPC_SHM); // 31 = shmctl
        return -ERESTARTSYS;
    }
    emit_policy_violation(31, EVENT_IPC_SHM);
    return -EPERM;
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
    // Resolve the target inode for the fine-grained IPC policy
    // (IPC_TYPE_MMAP entries are keyed by inode number).
    struct inode *ino_p = file ? BPF_CORE_READ(file, f_inode) : NULL;
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MMAP;
    if (ino_p)
        det.target = BPF_CORE_READ(ino_p, i_ino);
    int d = check_policy_detail(9, EVENT_IPC_MMAP, &det);
    if (d == DECISION_ALLOW)
        return 0;

    // Exemptions (apply regardless of mode):
    // Only intercept MAP_SHARED mappings
    if (!(flags & MAP_SHARED))
        return 0;
    // Anonymous shared mapping (file == NULL) = parent-child IPC -> EXEMPT
    if (!file)
        return 0;
    // Read-only shared file mappings are NOT a write/exfil channel and must be
    // exempt: the dynamic loader maps ld.so.cache / locale-archive / gconv cache
    // as PROT_READ|MAP_SHARED during process startup (e.g. every bash launch).
    if (!((reqprot | prot) & PROT_WRITE))
        return 0;

    // Same-epoch verification (issue #5): a writable file-backed MAP_SHARED is
    // internal only if another process in the SAME cgroup (epoch) already owns
    // this inode. The FIRST monitored mapping is fail-closed (intercepted)
    // because a host peer may already share the file; once it is authorized and
    // released, later same-cgroup mappers are exempt while a DIFFERENT cgroup
    // is still intercepted as a cross-epoch channel.
    if (!ino_p) {
        if (d == DECISION_FENCE) {
            do_intercept(9, EVENT_IPC_MMAP);
            return -ERESTARTSYS;
        }
        emit_policy_violation(9, EVENT_IPC_MMAP);
        return -EPERM;
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
    if (d == DECISION_FENCE) {
        do_intercept(9, EVENT_IPC_MMAP); // 9 = mmap syscall number
        return -ERESTARTSYS;
    }
    emit_policy_violation(9, EVENT_IPC_MMAP);
    return -EPERM;
}

// ── SysV message queues (msg) ─────────────────────────────────
// msgget: alloc_security (create) + associate (open existing)
SEC("lsm/msg_queue_alloc_security")
int BPF_PROG(shadow_msg_alloc, struct kern_ipc_perm *perm)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MSG;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(68, EVENT_IPC_MSG, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(68, EVENT_IPC_MSG); // 68 = msgget
        return -ERESTARTSYS;
    }
    emit_policy_violation(68, EVENT_IPC_MSG);
    return -EPERM;
}

SEC("lsm/msg_queue_associate")
int BPF_PROG(shadow_msg_associate, struct kern_ipc_perm *perm, int msqflg)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MSG;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(68, EVENT_IPC_MSG, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(68, EVENT_IPC_MSG); // 68 = msgget
        return -ERESTARTSYS;
    }
    emit_policy_violation(68, EVENT_IPC_MSG);
    return -EPERM;
}

// --- IPC: msg send ---
SEC("lsm/msg_queue_msgsnd")
int BPF_PROG(shadow_msg_msgsnd, struct kern_ipc_perm *msq,
             struct msg_msg *msg, int msqflg)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MSG;
    det.target = (__u64)(__u32)BPF_CORE_READ(msq, key);
    int d = check_policy_detail(69, EVENT_IPC_MSG, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(69, EVENT_IPC_MSG); // 69 = msgsnd
        return -ERESTARTSYS;
    }
    emit_policy_violation(69, EVENT_IPC_MSG);
    return -EPERM;
}

// --- IPC: msg receive ---
SEC("lsm/msg_queue_msgrcv")
int BPF_PROG(shadow_msg_msgrcv, struct kern_ipc_perm *msq,
             struct msg_msg *msg, struct task_struct *target,
             long type, int mode)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MSG;
    det.target = (__u64)(__u32)BPF_CORE_READ(msq, key);
    int d = check_policy_detail(70, EVENT_IPC_MSG, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(70, EVENT_IPC_MSG); // 70 = msgrcv
        return -ERESTARTSYS;
    }
    emit_policy_violation(70, EVENT_IPC_MSG);
    return -EPERM;
}

// --- IPC: msgctl ---
SEC("lsm/msg_queue_msgctl")
int BPF_PROG(shadow_msg_msgctl, struct kern_ipc_perm *perm, int cmd)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MSG;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(71, EVENT_IPC_MSG, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(71, EVENT_IPC_MSG); // 71 = msgctl
        return -ERESTARTSYS;
    }
    emit_policy_violation(71, EVENT_IPC_MSG);
    return -EPERM;
}

// ── SysV semaphores (sem) ─────────────────────────────────────
// semget: alloc_security (create) + associate (open existing)
SEC("lsm/sem_alloc_security")
int BPF_PROG(shadow_sem_alloc, struct kern_ipc_perm *perm)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SEM;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(64, EVENT_IPC_SEM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(64, EVENT_IPC_SEM); // 64 = semget
        return -ERESTARTSYS;
    }
    emit_policy_violation(64, EVENT_IPC_SEM);
    return -EPERM;
}

SEC("lsm/sem_associate")
int BPF_PROG(shadow_sem_associate, struct kern_ipc_perm *perm, int semflg)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SEM;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(64, EVENT_IPC_SEM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(64, EVENT_IPC_SEM); // 64 = semget
        return -ERESTARTSYS;
    }
    emit_policy_violation(64, EVENT_IPC_SEM);
    return -EPERM;
}

// --- IPC: semop / semtimedop ---
SEC("lsm/sem_semop")
int BPF_PROG(shadow_sem_semop, struct kern_ipc_perm *perm,
             struct sembuf *sops, unsigned int nsops, int alter)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SEM;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(65, EVENT_IPC_SEM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(65, EVENT_IPC_SEM); // 65 = semop
        return -ERESTARTSYS;
    }
    emit_policy_violation(65, EVENT_IPC_SEM);
    return -EPERM;
}

// --- IPC: semctl ---
SEC("lsm/sem_semctl")
int BPF_PROG(shadow_sem_semctl, struct kern_ipc_perm *perm, int cmd)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SEM;
    det.target = (__u64)(__u32)BPF_CORE_READ(perm, key);
    int d = check_policy_detail(66, EVENT_IPC_SEM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(66, EVENT_IPC_SEM); // 66 = semctl
        return -ERESTARTSYS;
    }
    emit_policy_violation(66, EVENT_IPC_SEM);
    return -EPERM;
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
    struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
    __u32 my_tgid = BPF_CORE_READ(cur, tgid);
    __u32 target_tgid = BPF_CORE_READ(p, tgid);

    // 1. Same thread group (self or sibling thread) -> exempt (fast path)
    if (target_tgid == my_tgid)
        return 0;

    // Resolve the target cgroup up front: it is both the same-epoch
    // exemption key and the signal-policy endpoint.
    __u64 my_cg = bpf_get_current_cgroup_id();
    __u64 tgt_cg = BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id);
    struct effect_detail det = {};
    det.target = tgt_cg;
    int d = check_policy_detail(62, EVENT_SIGNAL_KILL, &det);
    if (d == DECISION_ALLOW)
        return 0;

    // 2. Same monitored cgroup (== same speculative epoch) -> exempt.
    // Only checked for monitored processes (check_policy already filtered
    // non-monitored ones above).
    if (my_cg && my_cg == tgt_cg)
        return 0;

    if (d == DECISION_FENCE) {
        do_intercept(62, EVENT_SIGNAL_KILL);
        return -ERESTARTSYS;
    }
    emit_policy_violation(62, EVENT_SIGNAL_KILL);
    return -EPERM;  // DECISION_DENY
}

// --- Ptrace ---
SEC("lsm/ptrace_access_check")
int BPF_PROG(shadow_ptrace, struct task_struct *child, unsigned int mode)
{
    int d = check_policy(101, EVENT_SIGNAL_PTRACE);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(101, EVENT_SIGNAL_PTRACE);
        return -ERESTARTSYS;
    }
    emit_policy_violation(101, EVENT_SIGNAL_PTRACE);
    return -EPERM;
}

// ═══════════════════════════════════════════════════════════════
// fmod_ret on ksys_write - intercept write to stdout/stderr/pipe
// fmod_ret runs BEFORE the function body; returning non-zero
// overrides the function return value (function does NOT execute)
// ═══════════════════════════════════════════════════════════════

SEC("fmod_ret/__x64_sys_write")
int BPF_PROG(shadow_sys_write, struct pt_regs *regs)
{
    int d = check_policy(1, EVENT_OUTPUT_WRITE);
    if (d == DECISION_ALLOW)
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
    // data out, so we FAIL CLOSED rather than pass.
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if (fd >= max_fds) {
        if (d == DECISION_FENCE) {
            do_intercept(1, EVENT_OUTPUT_WRITE);
            return -ERESTARTSYS;
        }
        emit_policy_violation(1, EVENT_OUTPUT_WRITE);
        return -EPERM;
    }

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return 0;

    // Above this constant bound the verifier cannot prove fd_array[fd] is in
    // range, so the fd type is un-inspectable. FAIL CLOSED.
    if (fd > 1023) {
        if (d == DECISION_FENCE) {
            do_intercept(1, EVENT_OUTPUT_WRITE);
            return -ERESTARTSYS;
        }
        emit_policy_violation(1, EVENT_OUTPUT_WRITE);
        return -EPERM;
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
        if (d == DECISION_FENCE) {
            do_intercept(1, EVENT_OUTPUT_WRITE);
            return -ERESTARTSYS;
        }
        emit_policy_violation(1, EVENT_OUTPUT_WRITE);
        return -EPERM;
    }

    return 0;
}

// Also intercept writev for completeness
SEC("fmod_ret/__x64_sys_writev")
int BPF_PROG(shadow_sys_writev, struct pt_regs *regs)
{
    int d = check_policy(20, EVENT_OUTPUT_WRITE);
    if (d == DECISION_ALLOW)
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

    // Reject fds beyond the process's actual fd-table capacity.
    // Un-inspectable fd => FAIL CLOSED.
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if (fd >= max_fds) {
        if (d == DECISION_FENCE) {
            do_intercept(20, EVENT_OUTPUT_WRITE);
            return -ERESTARTSYS;
        }
        emit_policy_violation(20, EVENT_OUTPUT_WRITE);
        return -EPERM;
    }

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return 0;

    // Above this constant bound the verifier cannot prove fd_array[fd] is in
    // range. FAIL CLOSED.
    if (fd > 1023) {
        if (d == DECISION_FENCE) {
            do_intercept(20, EVENT_OUTPUT_WRITE);
            return -ERESTARTSYS;
        }
        emit_policy_violation(20, EVENT_OUTPUT_WRITE);
        return -EPERM;
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
        if (d == DECISION_FENCE) {
            do_intercept(20, EVENT_OUTPUT_WRITE);
            return -ERESTARTSYS;
        }
        emit_policy_violation(20, EVENT_OUTPUT_WRITE);
        return -EPERM;
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
// armed, any of these is intercepted and the process is frozen at its first
// use, exactly like an external write. Fine-grained same-epoch fd-pair
// inspection is deferred; failing closed is the safe base.
// ═══════════════════════════════════════════════════════════════

SEC("fmod_ret/__x64_sys_sendfile64")
int BPF_PROG(shadow_sys_sendfile, struct pt_regs *regs)
{
    int d = check_policy(40, EVENT_OUTPUT_SENDFILE);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(40, EVENT_OUTPUT_SENDFILE); // 40 = sendfile
        return -ERESTARTSYS;
    }
    emit_policy_violation(40, EVENT_OUTPUT_SENDFILE);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_splice")
int BPF_PROG(shadow_sys_splice, struct pt_regs *regs)
{
    int d = check_policy(275, EVENT_OUTPUT_SPLICE);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(275, EVENT_OUTPUT_SPLICE); // 275 = splice
        return -ERESTARTSYS;
    }
    emit_policy_violation(275, EVENT_OUTPUT_SPLICE);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_vmsplice")
int BPF_PROG(shadow_sys_vmsplice, struct pt_regs *regs)
{
    int d = check_policy(278, EVENT_OUTPUT_SPLICE);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(278, EVENT_OUTPUT_SPLICE); // 278 = vmsplice
        return -ERESTARTSYS;
    }
    emit_policy_violation(278, EVENT_OUTPUT_SPLICE);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_tee")
int BPF_PROG(shadow_sys_tee, struct pt_regs *regs)
{
    int d = check_policy(276, EVENT_OUTPUT_SPLICE);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(276, EVENT_OUTPUT_SPLICE); // 276 = tee
        return -ERESTARTSYS;
    }
    emit_policy_violation(276, EVENT_OUTPUT_SPLICE);
    return -EPERM;
}

// io_uring: async submission of network/file I/O can move data out WITHOUT the
// per-syscall write/sendmsg hooks ever firing. Default-deny while armed: block
// setup/enter/register so a monitored process is frozen at its first io_uring
// use (issue #5). Fine-grained SQE inspection is deferred.
SEC("fmod_ret/__x64_sys_io_uring_setup")
int BPF_PROG(shadow_sys_io_uring_setup, struct pt_regs *regs)
{
    int d = check_policy(425, EVENT_OUTPUT_IO_URING);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(425, EVENT_OUTPUT_IO_URING); // 425 = io_uring_setup
        return -ERESTARTSYS;
    }
    emit_policy_violation(425, EVENT_OUTPUT_IO_URING);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_io_uring_enter")
int BPF_PROG(shadow_sys_io_uring_enter, struct pt_regs *regs)
{
    int d = check_policy(426, EVENT_OUTPUT_IO_URING);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(426, EVENT_OUTPUT_IO_URING); // 426 = io_uring_enter
        return -ERESTARTSYS;
    }
    emit_policy_violation(426, EVENT_OUTPUT_IO_URING);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_io_uring_register")
int BPF_PROG(shadow_sys_io_uring_register, struct pt_regs *regs)
{
    int d = check_policy(427, EVENT_OUTPUT_IO_URING);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(427, EVENT_OUTPUT_IO_URING); // 427 = io_uring_register
        return -ERESTARTSYS;
    }
    emit_policy_violation(427, EVENT_OUTPUT_IO_URING);
    return -EPERM;
}

// ═══════════════════════════════════════════════════════════════
// SYSTEM fail-closed hooks for dangerous kernel-control interfaces.
// These syscalls can change namespaces/mounts, install kernel programs,
// inspect other processes, or reach terminal device state.  They previously
// had no schema entry and no hook, so ENFORCED mode could not control them.
// They now share EFFECT_CLASS_SYSTEM: SPECULATIVE/AUTHORIZED_PENDING fence;
// ENFORCED defaults to EPERM unless a class-wide SYSTEM allow is installed.
// ═══════════════════════════════════════════════════════════════

static __always_inline int system_guard(__u32 syscall_nr, __u32 event_type)
{
    int d = check_policy(syscall_nr, event_type);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(syscall_nr, event_type);
        return -ERESTARTSYS;
    }
    emit_policy_violation(syscall_nr, event_type);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_mount")
int BPF_PROG(shadow_sys_mount, struct pt_regs *regs)
{
    return system_guard(165, EVENT_SYSTEM_MOUNT);
}

/* umount2(2) 的内核实现是 SYSCALL_DEFINE2(umount, ...)，符号名无 "2" 后缀 */
SEC("fmod_ret/__x64_sys_umount")
int BPF_PROG(shadow_sys_umount2, struct pt_regs *regs)
{
    return system_guard(166, EVENT_SYSTEM_MOUNT);
}

SEC("fmod_ret/__x64_sys_unshare")
int BPF_PROG(shadow_sys_unshare, struct pt_regs *regs)
{
    return system_guard(272, EVENT_SYSTEM_NAMESPACE);
}

SEC("fmod_ret/__x64_sys_setns")
int BPF_PROG(shadow_sys_setns, struct pt_regs *regs)
{
    return system_guard(308, EVENT_SYSTEM_NAMESPACE);
}

SEC("fmod_ret/__x64_sys_keyctl")
int BPF_PROG(shadow_sys_keyctl, struct pt_regs *regs)
{
    return system_guard(250, EVENT_SYSTEM_KEYRING);
}

SEC("fmod_ret/__x64_sys_add_key")
int BPF_PROG(shadow_sys_add_key, struct pt_regs *regs)
{
    return system_guard(248, EVENT_SYSTEM_KEYRING);
}

SEC("fmod_ret/__x64_sys_request_key")
int BPF_PROG(shadow_sys_request_key, struct pt_regs *regs)
{
    return system_guard(249, EVENT_SYSTEM_KEYRING);
}

SEC("fmod_ret/__x64_sys_bpf")
int BPF_PROG(shadow_sys_bpf, struct pt_regs *regs)
{
    return system_guard(321, EVENT_SYSTEM_BPF);
}

SEC("fmod_ret/__x64_sys_perf_event_open")
int BPF_PROG(shadow_sys_perf_event_open, struct pt_regs *regs)
{
    return system_guard(298, EVENT_SYSTEM_PERF);
}

SEC("fmod_ret/__x64_sys_process_vm_readv")
int BPF_PROG(shadow_sys_process_vm_readv, struct pt_regs *regs)
{
    return system_guard(310, EVENT_SYSTEM_PROCESS_VM);
}

SEC("fmod_ret/__x64_sys_process_vm_writev")
int BPF_PROG(shadow_sys_process_vm_writev, struct pt_regs *regs)
{
    return system_guard(311, EVENT_SYSTEM_PROCESS_VM);
}

SEC("fmod_ret/__x64_sys_ioctl")
int BPF_PROG(shadow_sys_ioctl, struct pt_regs *regs)
{
    int d = check_policy(16, EVENT_SYSTEM_TTY_IOCTL);
    if (d == DECISION_ALLOW)
        return 0;

    unsigned long fd = PT_REGS_PARM1_CORE_SYSCALL(regs);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        goto block;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        goto block;
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    // An fd outside the fd table cannot name an open file: the syscall is
    // guaranteed to fail with EBADF before touching anything, so it has no
    // external effect to fence.  This case is not exotic -- bash probes job
    // control with ioctl(-1, TIOCSPGRP) on every startup, and fencing that
    // froze the shell before it could run a single command.  Note the
    // difference from the goto block cases: there we could not *read* the fd
    // table and stay fail-closed; here we positively established the fd is
    // not open.
    if (fd >= max_fds || fd > 1023)
        return 0;
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        goto block;
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);
    if (!f)
        return 0;  // closed slot -> EBADF, same reasoning as above
    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode)
        goto block;
    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    if ((mode & S_IFMT) != S_IFCHR)
        return 0;

block:
    if (d == DECISION_FENCE) {
        do_intercept(16, EVENT_SYSTEM_TTY_IOCTL);
        return -ERESTARTSYS;
    }
    emit_policy_violation(16, EVENT_SYSTEM_TTY_IOCTL);
    return -EPERM;
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
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_SHM;  // detach: target unknown -> wildcard only
    int d = check_policy_detail(67, EVENT_IPC_SHM, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(67, EVENT_IPC_SHM); // 67 = shmdt
        return -ERESTARTSYS;
    }
    emit_policy_violation(67, EVENT_IPC_SHM);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_mq_open")
int BPF_PROG(shadow_sys_mq_open, struct pt_regs *regs)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MQ;  // queue name not parsed -> wildcard only
    int d = check_policy_detail(240, EVENT_IPC_MQ, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(240, EVENT_IPC_MQ); // 240 = mq_open
        return -ERESTARTSYS;
    }
    emit_policy_violation(240, EVENT_IPC_MQ);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_mq_timedsend")
int BPF_PROG(shadow_sys_mq_timedsend, struct pt_regs *regs)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MQ;
    int d = check_policy_detail(242, EVENT_IPC_MQ, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(242, EVENT_IPC_MQ); // 242 = mq_timedsend (mq_send)
        return -ERESTARTSYS;
    }
    emit_policy_violation(242, EVENT_IPC_MQ);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_mq_timedreceive")
int BPF_PROG(shadow_sys_mq_timedreceive, struct pt_regs *regs)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MQ;
    int d = check_policy_detail(243, EVENT_IPC_MQ, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(243, EVENT_IPC_MQ); // 243 = mq_timedreceive (mq_receive)
        return -ERESTARTSYS;
    }
    emit_policy_violation(243, EVENT_IPC_MQ);
    return -EPERM;
}

SEC("fmod_ret/__x64_sys_mq_notify")
int BPF_PROG(shadow_sys_mq_notify, struct pt_regs *regs)
{
    struct effect_detail det = {};
    det.ipc_type = IPC_TYPE_MQ;
    int d = check_policy_detail(244, EVENT_IPC_MQ, &det);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(244, EVENT_IPC_MQ); // 244 = mq_notify
        return -ERESTARTSYS;
    }
    emit_policy_violation(244, EVENT_IPC_MQ);
    return -EPERM;
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
    int d = check_policy(59, EVENT_PRIV_EXEC);
    if (d == DECISION_ALLOW)
        return 0;

    // Check if the binary has setuid or setgid bit set
    struct inode *inode = BPF_CORE_READ(bprm, file, f_inode);
    if (!inode)
        return 0;

    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    if (!(mode & S_ISUID) && !(mode & S_ISGID))
        return 0;  // not setuid/setgid, allow

    if (d == DECISION_FENCE) {
        do_intercept(59, EVENT_PRIV_EXEC);  // 59 = execve syscall nr
        return -ERESTARTSYS;
    }
    emit_policy_violation(59, EVENT_PRIV_EXEC);
    return -EPERM;
}

// --- Privilege: UID changes (setuid/setreuid/setresuid/setfsuid) ---
SEC("lsm/task_fix_setuid")
int BPF_PROG(shadow_task_fix_setuid, struct cred *new_cred,
             const struct cred *old, int flags)
{
    int d = check_policy(105, EVENT_PRIV_SETUID);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(105, EVENT_PRIV_SETUID);  // 105 = setuid
        return -ERESTARTSYS;
    }
    emit_policy_violation(105, EVENT_PRIV_SETUID);
    return -EPERM;
}

// --- Privilege: GID changes (setgid/setregid/setresgid/setfsgid) ---
SEC("lsm/task_fix_setgid")
int BPF_PROG(shadow_task_fix_setgid, struct cred *new_cred,
             const struct cred *old, int flags)
{
    int d = check_policy(106, EVENT_PRIV_SETGID);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(106, EVENT_PRIV_SETGID);  // 106 = setgid
        return -ERESTARTSYS;
    }
    emit_policy_violation(106, EVENT_PRIV_SETGID);
    return -EPERM;
}

// --- Privilege: setgroups ---
SEC("lsm/task_fix_setgroups")
int BPF_PROG(shadow_task_fix_setgroups, struct cred *new_cred,
             const struct cred *old)
{
    int d = check_policy(116, EVENT_PRIV_SETGROUPS);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(116, EVENT_PRIV_SETGROUPS);  // 116 = setgroups
        return -ERESTARTSYS;
    }
    emit_policy_violation(116, EVENT_PRIV_SETGROUPS);
    return -EPERM;
}

// --- Privilege: capset (capability changes) ---
SEC("lsm/capset")
int BPF_PROG(shadow_capset, struct cred *new_cred, const struct cred *old,
             const kernel_cap_t *effective, const kernel_cap_t *inheritable,
             const kernel_cap_t *permitted)
{
    int d = check_policy(126, EVENT_PRIV_CAPSET);
    if (d == DECISION_ALLOW)
        return 0;
    if (d == DECISION_FENCE) {
        do_intercept(126, EVENT_PRIV_CAPSET);  // 126 = capset
        return -ERESTARTSYS;
    }
    emit_policy_violation(126, EVENT_PRIV_CAPSET);
    return -EPERM;
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
        e->cgroup_id = bpf_get_current_cgroup_id();
        e->decision = DECISION_ALLOW;
        e->_pad0[0] = 0;
        e->_pad0[1] = 0;
        e->_pad0[2] = 0;
        e->_pad0[3] = 0;
        e->_pad0[4] = 0;
        e->_pad0[5] = 0;
        e->_pad0[6] = 0;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════
// Process-exit cleanup - drop all per-tgid / per-tid state when a process
// leaves.
//
// restart_token is keyed by tid (thread id): clean on EVERY thread exit.
// stopped_pids is keyed by tgid: clean only on thread-group-leader exit.
// epoch_mode / class_policy / etc. are cgroup-scoped and cleaned by userspace
// (clear_all_policies) at epoch end, NOT here.
// ═══════════════════════════════════════════════════════════════
SEC("tp_btf/sched_process_exit")
int BPF_PROG(shadow_sched_exit, struct task_struct *task)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    __u32 pid  = BPF_CORE_READ(task, pid);

    // Clean restart_token for this thread (tid = pid).
    // Tokens are per-thread, so every exiting thread's token is stale.
    bpf_map_delete_elem(&restart_token, &pid);

    // Only clean tgid-keyed state when the whole thread group is gone.
    if (pid != tgid)
        return 0;
    bpf_map_delete_elem(&stopped_pids, &tgid);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// Shared-mapping owner cleanup - reclaim a shared_map_owner entry when its
// inode is torn down, so a later REUSED inode pointer can never inherit a
// stale owner cgroup (which could otherwise wrongly exempt a cross-epoch
// MAP_SHARED). A live mapping pins the inode, so an entry is only reclaimed
// once every mapping is gone. This fires for every inode teardown; the delete
// is a cheap no-op for the (vast majority of) inodes that were never a tracked
// writable MAP_SHARED target.
// ═══════════════════════════════════════════════════════════════
SEC("lsm/inode_free_security")
int BPF_PROG(shadow_inode_free, struct inode *inode)
{
    __u64 ino_key = (__u64)(unsigned long)inode;
    bpf_map_delete_elem(&shared_map_owner, &ino_key);
    return 0;
}
