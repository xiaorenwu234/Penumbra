#!/usr/bin/env python3
"""
PolicyIR – Unified event schema compiler and multi-language header generator.

This module is the single source of truth for the Speculative Shadow effect
event model. It loads ``effect_schema.json`` and provides:

1. **PolicyIR** – compiles user-facing ``allowed_ops`` (string event names like
   "OPEN", "CREATE") into a unified intermediate representation that can emit
   audit rules, BPF whitelist entries, and class-level policy maps.

2. **Header generation** – generates C, C++, Rust, and Go headers from the
   schema so all components share identical constant definitions.

The unified model replaces the two colliding event numbering schemes:
  - ShadowObserve: FS_EVENT_* (1–11) and PROC_EVENT_* (100–108)
  - ShadowProc:    EVENT_* (1–10)

with a two-level ``(effect_class, operation)`` encoding that eliminates
collisions:

  event_type = effect_class | (operation << 8)

Usage (library):
    from policy.policy_ir import PolicyIR
    ir = PolicyIR.from_allowed_ops(allowed_ops, cgroup_inode)
    audit_rules = ir.to_audit_rules()
    whitelist   = ir.to_bpf_whitelist()

Usage (CLI header generation):
    python3 policy/policy_ir.py gen --lang c    --out ShadowObserve/bpf/effect_schema.h
    python3 policy/policy_ir.py gen --lang cpp   --out ShadowObserve/include/ghostbpf-observ/effect_schema.hpp
    python3 policy/policy_ir.py gen --lang rust  --out ShadowProc/src/policy_generated.rs
    python3 policy/policy_ir.py gen --lang go    --out ShadowFS/backend/policy_generated.go
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ─── schema loading ──────────────────────────────────────────────────────

_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "effect_schema.json")


def _load_schema() -> dict:
    with open(_SCHEMA_PATH, "r") as f:
        return json.load(f)


SCHEMA = _load_schema()

# Build lookup tables from the schema.

#: effect class name → id
CLASS_IDS: Dict[str, int] = {
    name: info["id"] for name, info in SCHEMA["effect_classes"].items()
}

#: (class_name, op_name) → op_id
OP_IDS: Dict[Tuple[str, str], int] = {}
for cls_name, cls_info in SCHEMA["effect_classes"].items():
    for op_name, op_id in cls_info["operations"].items():
        OP_IDS[(cls_name, op_name)] = op_id

#: Reverse: (class_id, op_id) → (class_name, op_name)
OP_NAMES: Dict[Tuple[int, int], Tuple[str, str]] = {}
for cls_name, cls_info in SCHEMA["effect_classes"].items():
    for op_name, op_id in cls_info["operations"].items():
        OP_NAMES[(cls_info["id"], op_id)] = (cls_name, op_name)

#: Legacy string event name → (class_id, op_id)
LEGACY_MAP: Dict[str, Tuple[int, int]] = {}
for evt_name, mapping in SCHEMA["legacy_event_map"].items():
    cls_name = mapping["class"]
    op_name = mapping["op"]
    LEGACY_MAP[evt_name] = (CLASS_IDS[cls_name], OP_IDS[(cls_name, op_name)])

#: Legacy unmapped events (FORK, EXIT, PRCTL) → old numeric value
LEGACY_UNMAPPED: Dict[str, int] = SCHEMA["legacy_unmapped"]

#: Source name → id
SOURCE_IDS: Dict[str, int] = {
    name: sid for name, sid in SCHEMA["sources"].items()
}

#: IPC endpoint type name → id (must match IPC_TYPE_* in shadow_proc.bpf.c).
IPC_TYPE_IDS: Dict[str, int] = {
    "SHM": 1,
    "MSG": 2,
    "SEM": 3,
    "MQ": 4,
    "MMAP": 5,
}


def _int_field(obj: Dict, name: str, default: int, lo: int, hi: int) -> int:
    """Fetch an optional integer field with range checking (fail-closed)."""
    v = obj.get(name, default)
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"endpoint field {name!r} must be an integer, got {v!r}")
    if not (lo <= v <= hi):
        raise ValueError(f"endpoint field {name!r}={v} out of range [{lo}, {hi}]")
    return v


def _validate_endpoint(cls_id: int, ep: Dict) -> Dict:
    """Validate/normalize an endpoint descriptor for a fine-grained rule.

    Endpoint schemas (missing fields default to 0 = wildcard at that
    position; all values host order):
      NETWORK: {"family": u8, "addr": u32, "port": u16}
      IPC:     {"ipc_type": 1..5 | "SHM"|"MSG"|"SEM"|"MQ"|"MMAP", "target": u64}
      SIGNAL:  {"target_cgroup": u64}

    Raises ValueError on anything malformed (fail-closed).
    """
    if not isinstance(ep, dict):
        raise ValueError(f"endpoint must be an object, got {ep!r}")
    if cls_id == CLASS_IDS["NETWORK"]:
        return {
            "family": _int_field(ep, "family", 0, 0, 0xFF),
            "addr":   _int_field(ep, "addr", 0, 0, 0xFFFFFFFF),
            "port":   _int_field(ep, "port", 0, 0, 0xFFFF),
        }
    if cls_id == CLASS_IDS["IPC"]:
        ipc_type = ep.get("ipc_type", 0)
        if isinstance(ipc_type, str):
            name = ipc_type.upper()
            if name not in IPC_TYPE_IDS:
                raise ValueError(f"unknown ipc_type name: {ipc_type!r}")
            ipc_type = IPC_TYPE_IDS[name]
        if isinstance(ipc_type, bool) or not isinstance(ipc_type, int) \
                or not (1 <= ipc_type <= 5):
            raise ValueError(f"ipc_type must be 1..5, got {ipc_type!r}")
        return {
            "ipc_type": ipc_type,
            "target": _int_field(ep, "target", 0, 0, 0xFFFFFFFFFFFFFFFF),
        }
    if cls_id == CLASS_IDS["SIGNAL"]:
        return {
            "target_cgroup": _int_field(ep, "target_cgroup", 0, 0, 0xFFFFFFFFFFFFFFFF),
        }
    raise ValueError(
        f"endpoints are only supported for NETWORK/IPC/SIGNAL rules "
        f"(rule references class id {cls_id})"
    )


def encode_event_type(effect_class: int, operation: int) -> int:
    """Encode (effect_class, operation) into a single uint16 event_type.

    Layout (little-endian): effect_class is the low byte, operation is the
    high byte. This matches the anonymous-union overlay in ``struct
    effect_event`` so BPF code that writes ``evt->effect_class`` and
    ``evt->operation`` produces the same ``event_type`` value that the audit
    engine and whitelist enforcer match on.
    """
    return (effect_class & 0xFF) | ((operation & 0xFF) << 8)


def decode_event_type(event_type: int) -> Tuple[int, int]:
    """Decode a uint16 event_type into (effect_class, operation)."""
    return (event_type & 0xFF), ((event_type >> 8) & 0xFF)


def event_name_to_type(name: str) -> int:
    """Map a user-facing string event name to its encoded event_type value.

    Accepts legacy names ("OPEN", "CREATE", "EXEC", ...) and the explicit
    wildcards "*" / "ANY" (returns -1 for audit, 0xFFFF for BPF).

    Raises ValueError for unknown names, fail-closed.
    """
    upper = name.upper()
    if upper in ("*", "ANY"):
        return -1  # sentinel; callers translate to -1 (audit) or 0xFFFF (BPF)
    if upper in LEGACY_MAP:
        cls, op = LEGACY_MAP[upper]
        return encode_event_type(cls, op)
    if upper in LEGACY_UNMAPPED:
        # FORK/EXIT/PRCTL are process lifecycle events, not auditable effects.
        raise ValueError(
            f"event type '{upper}' is a process lifecycle event, not an "
            f"auditable effect — cannot be used in a policy rule"
        )
    raise ValueError(f"unknown policy event_type: {name!r}")


def event_name_to_bpf_type(name: str) -> int:
    """Like event_name_to_type but returns 0xFFFF for wildcards (BPF side)."""
    t = event_name_to_type(name)
    return 0xFFFF if t == -1 else t


def event_type_to_name(event_type: int) -> str:
    """Reverse mapping: encoded event_type → human-readable name.

    Returns the legacy name if one exists, else "CLASS_OP". Returns
    "UNKNOWN" for unmapped values.
    """
    # Check legacy unmapped values first (FORK=101, EXIT=102, PRCTL=104).
    for name, val in LEGACY_UNMAPPED.items():
        if event_type == val:
            return name
    cls, op = decode_event_type(event_type)
    if (cls, op) in OP_NAMES:
        cls_name, op_name = OP_NAMES[(cls, op)]
        # Return the legacy short name if available.
        for legacy_name, (lcls, lop) in LEGACY_MAP.items():
            if lcls == cls and lop == op:
                return legacy_name
        return f"{cls_name}_{op_name}"
    return "UNKNOWN"


# ─── path normalization ──────────────────────────────────────────────────

def normalize_fs_prefix(pattern: str) -> str:
    """Normalize a policy path prefix to canonical form.

    Rejects relative paths, paths containing '..' or NUL, and paths >= 256
    chars. Strips trailing slashes (a lone "/" is kept as the root marker).
    Empty patterns (match-any) are preserved.
    """
    if not pattern:
        return ""
    if "\x00" in pattern:
        raise ValueError("path prefix contains NUL byte")
    if len(pattern) >= 256:
        raise ValueError(f"path prefix too long ({len(pattern)} >= 256)")
    if not pattern.startswith("/"):
        raise ValueError(f"path prefix must be absolute: {pattern!r}")
    if "/../" in pattern or pattern.endswith("/.."):
        raise ValueError(f"path prefix contains '..': {pattern!r}")
    p = pattern
    while len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p


# ─── PolicyIR ────────────────────────────────────────────────────────────

@dataclass
class PolicyIR:
    """Compiled policy intermediate representation.

    Built from user-facing ``allowed_ops`` (list of dicts with string
    ``event_type``, ``action``, ``path_pattern``). Produces audit rules,
    BPF whitelist entries, and (for Phase 2) class-level policy maps.
    """

    #: List of (event_type_encoded, action_str, path_prefix) tuples.
    rules: List[Dict] = field(default_factory=list)
    #: The cgroup inode this IR was compiled for.
    cgroup_inode: int = 0

    @classmethod
    def from_allowed_ops(cls, allowed_ops: List[Dict],
                         cgroup_inode: int = 0) -> "PolicyIR":
        """Compile user-facing allowed_ops into the unified IR.

        Raises ValueError on unknown event types, unknown actions, or
        invalid path prefixes — the caller is expected to fail closed.
        """
        rules: List[Dict] = []
        for op in allowed_ops:
            event_str = op.get("event_type", "*")
            action = op.get("action", "allow").lower()
            if action not in ("allow", "deny"):
                raise ValueError(f"unknown policy action: {op.get('action')!r}")
            event_num = event_name_to_type(event_str)
            path = normalize_fs_prefix(op.get("path_pattern", ""))
            rule = {
                "event_type": event_num,
                "action": action,
                "path_pattern": path,
            }
            # Optional fine-grained endpoint (P0-5). Validated eagerly so a
            # malformed endpoint fails the whole compile, not just one rule.
            if "endpoint" in op and op["endpoint"] is not None:
                if event_num == -1:
                    raise ValueError(
                        "wildcard event_type cannot carry an endpoint"
                    )
                cls_id, _ = decode_event_type(event_num)
                rule["endpoint"] = _validate_endpoint(cls_id, op["endpoint"])
            rules.append(rule)
        return cls(rules=rules, cgroup_inode=cgroup_inode)

    def to_audit_rules(self) -> List[Dict]:
        """Emit rules in the format expected by ShadowObserve's audit engine.

        Wildcard event_type (-1) is kept as-is for the audit engine, which
        uses -1 to mean "any event type".
        """
        return [
            {
                "event_type": r["event_type"],  # -1 for wildcard
                "action": r["action"],
                "path_pattern": r["path_pattern"],
            }
            for r in self.rules
        ]

    def to_bpf_whitelist(self) -> List[Dict]:
        """Emit whitelist entries for the ShadowObserve BPF enforcer.

        Only ``allow`` rules are emitted (deny = absence from whitelist).
        Wildcard event_type (-1) is translated to 0xFFFF (BPF wildcard).
        """
        wl: List[Dict] = []
        for r in self.rules:
            if r["action"] != "allow":
                continue
            etype = r["event_type"]
            if etype == -1:
                etype = 0xFFFF
            wl.append({
                "event_type": etype,
                "path_prefix": r["path_pattern"],
            })
        return wl

    def to_bpf_class_policy(self) -> List[Dict]:
        """Emit operation-level allow/deny policy entries for ShadowProc.

        Each entry is keyed by ``(effect_class, operation)``. A concrete allow
        rule authorizes only that operation; wildcard allow expands to every
        operation in the schema. This deliberately avoids class-wide broadening
        such as CONNECT permitting BIND or MOUNT permitting BPF.
        """
        allowed_ops: set = set()
        for r in self.rules:
            if r["action"] != "allow":
                continue
            if r["event_type"] == -1:
                for cls_name, cls_id in CLASS_IDS.items():
                    for op_name, op_id in SCHEMA["effect_classes"][cls_name]["operations"].items():
                        allowed_ops.add((cls_id, op_id))
                break
            allowed_ops.add(decode_event_type(r["event_type"]))
        out = []
        for cls_name, cls_id in sorted(CLASS_IDS.items(), key=lambda x: x[1]):
            for op_name, op_id in sorted(
                    SCHEMA["effect_classes"][cls_name]["operations"].items(),
                    key=lambda x: x[1]):
                out.append({
                    "effect_class": cls_id,
                    "operation": op_id,
                    "allow": 1 if (cls_id, op_id) in allowed_ops else 0,
                })
        return out

    def to_proc_policy(self) -> Dict:
        """Emit an operation-aware process-layer policy for ShadowProc (P0-5).

        Rule semantics:
          * allow rule WITHOUT endpoint → operation-wide allow (mode 1);
          * rule WITH endpoint          → fine-grained entry for that operation
            (mode 2, per-endpoint maps decide, default-deny);
          * deny rule without endpoint  → contributes nothing (absence of an
            allow already denies, matching to_bpf_class_policy);
          * deny rule with endpoint     → explicit fine-grained deny entry
            (allow=0), which short-circuits wildcard allow entries in BPF.

        A concrete operation with BOTH an operation-wide allow and endpoint
        rules is a contradiction → ValueError (fail-closed). When the same
        endpoint key is named by conflicting rules, deny dominates.

        Output schema (consumed by ShadowProc's parse_proc_policy):
          {"classes": [{"effect_class": N, "operation": M, "mode": 1|2}],
           "network": [{"operation": M,"family":..,"addr":..,"port":..,"allow":0|1}],
           "ipc":     [{"operation": M,"ipc_type":..,"target":..,"allow":0|1}],
           "signal":  [{"operation": M,"target_cgroup":..,"allow":0|1}]}
        """
        cls_net = CLASS_IDS["NETWORK"]
        cls_ipc = CLASS_IDS["IPC"]
        cls_sig = CLASS_IDS["SIGNAL"]

        operation_allow: set = set()
        fine_operations: set = set()
        # key → allow bit; deny (0) dominates conflicting duplicates.
        net: Dict[Tuple[int, int, int, int], int] = {}
        ipc: Dict[Tuple[int, int, int], int] = {}
        sig: Dict[Tuple[int, int], int] = {}

        def merge(d, key, bit):
            d[key] = min(d.get(key, 1), bit)

        def all_schema_ops():
            for cls_name, cls_id in CLASS_IDS.items():
                for _op_name, op_id in SCHEMA["effect_classes"][cls_name]["operations"].items():
                    yield cls_id, op_id

        for r in self.rules:
            ep = r.get("endpoint")
            bit = 1 if r["action"] == "allow" else 0
            if r["event_type"] == -1:
                # Wildcard allow → operation-wide allow for every schema op.
                # (Wildcard + endpoint was rejected at compile time.)
                if bit:
                    operation_allow.update(all_schema_ops())
                continue
            cls, op = decode_event_type(r["event_type"])
            op_key = (cls, op)
            if ep is None:
                if bit:
                    operation_allow.add(op_key)
                continue
            fine_operations.add(op_key)
            if cls == cls_net:
                merge(net, (op, ep["family"], ep["addr"], ep["port"]), bit)
            elif cls == cls_ipc:
                merge(ipc, (op, ep["ipc_type"], ep["target"]), bit)
            elif cls == cls_sig:
                merge(sig, (op, ep["target_cgroup"]), bit)
            # other classes were rejected by _validate_endpoint.

        contradictory = operation_allow & fine_operations
        if contradictory:
            raise ValueError(
                f"contradictory policy: operations {sorted(contradictory)} have "
                f"both operation-wide allow rules and endpoint-scoped rules"
            )

        classes = [
            {"effect_class": c, "operation": op, "mode": 1}
            for c, op in sorted(operation_allow)
        ] + [
            {"effect_class": c, "operation": op, "mode": 2}
            for c, op in sorted(fine_operations)
        ]
        return {
            "classes": classes,
            "network": [
                {"operation": op, "family": f, "addr": a, "port": p, "allow": bit}
                for (op, f, a, p), bit in sorted(net.items())
            ],
            "ipc": [
                {"operation": op, "ipc_type": t, "target": tg, "allow": bit}
                for (op, t, tg), bit in sorted(ipc.items())
            ],
            "signal": [
                {"operation": op, "target_cgroup": tg, "allow": bit}
                for (op, tg), bit in sorted(sig.items())
            ],
        }


# ─── header generation ──────────────────────────────────────────────────

def _gen_c_header() -> str:
    """Generate the C header (effect_schema.h) from the schema."""
    lines = [
        "/* SPDX-License-Identifier: GPL-2.0 */",
        "/*",
        " * effect_schema.h - AUTO-GENERATED by policy/policy_ir.py.",
        " * Unified effect event schema for Speculative Shadow.",
        " *",
        " * Defines the (effect_class, operation) model that replaces the two",
        " * colliding event numbering schemes (FS_EVENT_*, PROC_EVENT_* and",
        " * ShadowProc EVENT_*). All BPF programs and userspace components",
        " * include this header to share identical constant definitions.",
        " *",
        " * Encoding: event_type = effect_class | (operation << 8)",
        " *   - effect_class is the low byte (1-6)",
        " *   - operation is the high byte (1-12)",
        " *   - 0xFFFF = wildcard (any event)",
        " *   - -1 = wildcard (audit engine, int)",
        " */",
        "#ifndef EFFECT_SCHEMA_H",
        "#define EFFECT_SCHEMA_H",
        "",
        "#ifndef __VMLINUX_H__",
        "#include <linux/types.h>",
        "#endif",
        "",
        "/* ---- constants ------------------------------------------------------ */",
        "",
        "#define MAX_PATH        256",
        "#define MAX_COMM        16",
        "#define MAX_ARGS        640",
        "#define RING_BUF_SIZE   (512 * 1024)",
        "",
        "/* ---- audit actions -------------------------------------------------- */",
        "",
        "#define AUDIT_DENY  0",
        "#define AUDIT_ALLOW 1",
        "",
        "/* ---- event flags (arg3, FS events only) ------------------------------ */",
        "/*",
        " * Set by the observer when cri_build_path() failed for this event",
        " * (path buffer emptied); consumers must treat the event's path as",
        " * unreliable and count it against audit completeness.",
        " */",
        "#define OBSERV_FL_PATH_ERROR 0x1u",
        "",
    ]

    # Effect class constants.
    lines.append("/* ---- effect classes ------------------------------------------------- */")
    for cls_name, cls_info in SCHEMA["effect_classes"].items():
        lines.append(f"#define EFFECT_CLASS_{cls_name}  {cls_info['id']}")
    lines.append("")

    # Operation constants per class.
    lines.append("/* ---- operations per class ------------------------------------------- */")
    for cls_name, cls_info in SCHEMA["effect_classes"].items():
        lines.append(f"/* {cls_name} */")
        for op_name, op_id in cls_info["operations"].items():
            lines.append(f"#define EFFECT_OP_{op_name}  {op_id}")
        lines.append("")

    # Source constants.
    lines.append("/* ---- event sources ------------------------------------------------- */")
    for src_name, src_id in SCHEMA["sources"].items():
        lines.append(f"#define EFFECT_SOURCE_{src_name}  {src_id}")
    lines.append("")

    # Encoding macro.
    lines.extend([
        "/* ---- encoding macro ------------------------------------------------- */",
        "/*",
        " * Encode (effect_class, operation) into a single uint16 event_type.",
        " * Layout: low byte = effect_class, high byte = operation.",
        " * This matches the anonymous-union overlay in struct effect_event.",
        " */",
        "#define EFFECT_EVENT_TYPE(cls, op) ((__u16)(cls) | ((__u16)(op) << 8))",
        "",
    ])

    # Legacy aliases.
    lines.append("/* ---- legacy event type aliases ------------------------------------- */")
    lines.append("/* These map the old FS_EVENT_*, PROC_EVENT_* names to the new encoding. */")
    for evt_name, mapping in SCHEMA["legacy_event_map"].items():
        cls_name = mapping["class"]
        op_name = mapping["op"]
        prefix = "FS_EVENT" if cls_name == "FILESYSTEM" else "PROC_EVENT"
        lines.append(
            f"#define {prefix}_{evt_name}  "
            f"EFFECT_EVENT_TYPE(EFFECT_CLASS_{cls_name}, EFFECT_OP_{op_name})"
        )
    lines.append("")

    # Legacy unmapped constants.
    lines.append("/* ---- legacy unmapped events (process lifecycle, not effects) ------- */")
    for evt_name, val in SCHEMA["legacy_unmapped"].items():
        lines.append(f"#define PROC_EVENT_{evt_name}  {val}")
    lines.append("")

    # Event struct.
    lines.extend([
        "/* ---- unified event struct (ring-buffer compatible) ------------------ */",
        "/*",
        " * effect_event replaces observ_event. The anonymous union lets code",
        " * access either the combined event_type or the split (effect_class,",
        " * operation) fields. The source field (new) identifies which subsystem",
        " * originated the event.",
        " *",
        " * Field semantics:",
        " *   effect_class  = EFFECT_CLASS_FILESYSTEM / NETWORK / IPC / ...",
        " *   operation     = EFFECT_OP_READ / CREATE / CONNECT / ...",
        " *   source        = EFFECT_SOURCE_FS / PROC / NET / ...",
        " *   arg1          = flags(open) / mode(chmod,mkdir) / pid(kill) / ...",
        " *   arg2          = signal(kill) / target_pid(ptrace) / euid / ...",
        " *   arg3          = suid / tgid(tgkill) / ...",
        " *   path          = primary resource (file path, exec filename, ...)",
        " *   new_path      = secondary resource (rename dst, link target, ...)",
        " */",
        "struct observ_event {",
        "    __u64 timestamp_ns;",
        "    __u32 pid;",
        "    __u32 tid;",
        "    __u32 uid;",
        "    __u32 gid;",
        "    __u64 cgroup_id;",
        "    __u64 seq;              /* monotonic per-cgroup sequence */",
        "    union {",
        "        __u16 event_type;   /* legacy combined type */",
        "        struct {",
        "            __u8 effect_class;  /* EFFECT_CLASS_* */",
        "            __u8 operation;     /* EFFECT_OP_* */",
        "        };",
        "    };",
        "    __u8  source;           /* EFFECT_SOURCE_* */",
        "    __u8  _pad0;",
        "    __u32 arg1;",
        "    __u32 arg2;",
        "    __u32 arg3;",
        "    __u32 _pad1;",
        "    char  comm[MAX_COMM];",
        "    char  path[MAX_PATH];         /* primary resource */",
        "    char  new_path[MAX_PATH];     /* secondary resource */",
        "};",
        "",
        "/* Unified name: effect_event is an alias for observ_event. */",
        "typedef struct observ_event effect_event;",
        "",
        "/* ---- audit rule (userspace only) ----------------------------------- */",
        "",
        "struct audit_rule {",
        "    int  event_type;              /* encoded, or -1 for any */",
        "    int  action;                  /* AUDIT_ALLOW or AUDIT_DENY */",
        "    char path_pattern[MAX_PATH];  /* prefix to match */",
        "};",
        "",
        "#endif /* EFFECT_SCHEMA_H */",
    ])

    return "\n".join(lines) + "\n"


def _gen_cpp_header() -> str:
    """Generate the C++ header (effect_schema.hpp) from the schema."""
    lines = [
        "/* SPDX-License-Identifier: MIT */",
        "/*",
        " * effect_schema.hpp - AUTO-GENERATED by policy/policy_ir.py.",
        " * C++ constants and helpers for the unified effect event model.",
        " */",
        "#ifndef GHOSTBPF_OBSERV_EFFECT_SCHEMA_HPP",
        "#define GHOSTBPF_OBSERV_EFFECT_SCHEMA_HPP",
        "",
        "#include <cstdint>",
        "#include <string>",
        "",
        "namespace ghostbpf_observ {",
        "",
        "/* ---- effect classes ---- */",
    ]
    for cls_name, cls_info in SCHEMA["effect_classes"].items():
        lines.append(f"inline constexpr uint8_t CLASS_{cls_name} = {cls_info['id']};")
    lines.append("")

    lines.append("/* ---- operations per class ---- */")
    for cls_name, cls_info in SCHEMA["effect_classes"].items():
        lines.append(f"/* {cls_name} */")
        for op_name, op_id in cls_info["operations"].items():
            lines.append(f"inline constexpr uint8_t OP_{op_name} = {op_id};")
        lines.append("")

    lines.extend([
        "/* ---- sources ---- */",
    ])
    for src_name, src_id in SCHEMA["sources"].items():
        lines.append(f"inline constexpr uint8_t SOURCE_{src_name} = {src_id};")
    lines.append("")

    lines.extend([
        "/* ---- encoding ---- */",
        "inline constexpr uint16_t encode_event_type(uint8_t cls, uint8_t op) {",
        "    return static_cast<uint16_t>(cls) | (static_cast<uint16_t>(op) << 8);",
        "}",
        "inline constexpr uint8_t event_class_of(uint16_t type) {",
        "    return static_cast<uint8_t>(type & 0xFF);",
        "}",
        "inline constexpr uint8_t event_op_of(uint16_t type) {",
        "    return static_cast<uint8_t>((type >> 8) & 0xFF);",
        "}",
        "",
        "/* ---- legacy aliases ---- */",
    ])
    for evt_name, mapping in SCHEMA["legacy_event_map"].items():
        cls_name = mapping["class"]
        op_name = mapping["op"]
        prefix = "FS_EVENT" if cls_name == "FILESYSTEM" else "PROC_EVENT"
        lines.append(
            f"inline constexpr uint16_t {prefix}_{evt_name} = "
            f"encode_event_type(CLASS_{cls_name}, OP_{op_name});"
        )
    lines.append("")

    lines.extend([
        "/* ---- event name lookup ---- */",
        "const char *effect_event_name(uint16_t event_type);",
        "",
        "} // namespace ghostbpf_observ",
        "",
        "#endif // GHOSTBPF_OBSERV_EFFECT_SCHEMA_HPP",
    ])

    return "\n".join(lines) + "\n"


def _gen_rust() -> str:
    """Generate Rust constants (policy_generated.rs) from the schema."""
    lines = [
        "//! AUTO-GENERATED by policy/policy_ir.py.",
        "//! Unified effect event schema constants for ShadowProc.",
        "",
        "#![allow(dead_code)]",
        "",
        "/* ---- effect classes ---- */",
    ]
    for cls_name, cls_info in SCHEMA["effect_classes"].items():
        lines.append(f"pub const CLASS_{cls_name}: u8 = {cls_info['id']};")
    lines.append("")

    lines.append("/* ---- operations per class ---- */")
    for cls_name, cls_info in SCHEMA["effect_classes"].items():
        lines.append(f"// {cls_name}")
        for op_name, op_id in cls_info["operations"].items():
            lines.append(f"pub const OP_{op_name}: u8 = {op_id};")
        lines.append("")

    lines.append("/* ---- sources ---- */")
    for src_name, src_id in SCHEMA["sources"].items():
        lines.append(f"pub const SOURCE_{src_name}: u8 = {src_id};")
    lines.append("")

    lines.extend([
        "/* ---- encoding ---- */",
        "pub fn encode_event_type(cls: u8, op: u8) -> u16 {",
        "    (cls as u16) | ((op as u16) << 8)",
        "}",
        "pub fn event_class_of(ty: u16) -> u8 {",
        "    (ty & 0xFF) as u8",
        "}",
        "pub fn event_op_of(ty: u16) -> u8 {",
        "    ((ty >> 8) & 0xFF) as u8",
        "}",
        "",
        "/* ---- epoch modes (Phase 2) ---- */",
        "pub const MODE_SPECULATIVE: u8 = 0;",
        "pub const MODE_AUTHORIZED_PENDING: u8 = 1;",
        "pub const MODE_ENFORCED: u8 = 2;",
        "",
        "pub const DECISION_ALLOW: u8 = 0;",
        "pub const DECISION_FENCE: u8 = 1;",
        "pub const DECISION_DENY: u8 = 2;",
    ])

    return "\n".join(lines) + "\n"


def _gen_go() -> str:
    """Generate Go constants (policy_generated.go) from the schema."""
    lines = [
        "// Code generated by policy/policy_ir.py. DO NOT EDIT.",
        "",
        "package backend",
        "",
        "/* ---- effect classes ---- */",
    ]
    for cls_name, cls_info in SCHEMA["effect_classes"].items():
        lines.append(f"const EffectClass{cls_name.title()} uint8 = {cls_info['id']}")
    lines.append("")

    lines.append("/* ---- operations per class ---- */")
    for cls_name, cls_info in SCHEMA["effect_classes"].items():
        lines.append(f"// {cls_name}")
        for op_name, op_id in cls_info["operations"].items():
            # Go exported names: capitalize first letter
            go_name = op_name.title().replace("_", "")
            lines.append(f"const EffectOp{go_name} uint8 = {op_id}")
        lines.append("")

    lines.append("/* ---- sources ---- */")
    for src_name, src_id in SCHEMA["sources"].items():
        lines.append(f"const EffectSource{src_name.title()} uint8 = {src_id}")
    lines.append("")

    lines.extend([
        "/* ---- encoding ---- */",
        "func EncodeEventType(cls uint8, op uint8) uint16 {",
        "    return uint16(cls) | (uint16(op) << 8)",
        "}",
        "func EventClassOf(ty uint16) uint8 {",
        "    return uint8(ty & 0xFF)",
        "}",
        "func EventOpOf(ty uint16) uint8 {",
        "    return uint8((ty >> 8) & 0xFF)",
        "}",
    ])

    return "\n".join(lines) + "\n"


def generate_header(lang: str, out_path: str) -> None:
    """Generate a header file for the given language."""
    generators = {
        "c":    _gen_c_header,
        "cpp":  _gen_cpp_header,
        "rust": _gen_rust,
        "go":   _gen_go,
    }
    gen = generators.get(lang)
    if gen is None:
        raise ValueError(f"unknown language: {lang!r} (expected one of: {', '.join(generators)})")
    content = gen()
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as f:
        f.write(content)
    print(f"[policy_ir] generated {lang} header → {out_path}")


# ─── CLI ─────────────────────────────────────────────────────────────────

def _cli():
    if len(sys.argv) < 2:
        print("usage: policy_ir.py gen --lang LANG --out PATH")
        print("       policy_ir.py list")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "gen":
        lang = None
        out = None
        i = 2
        while i < len(sys.argv):
            if sys.argv[i] == "--lang":
                lang = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == "--out":
                out = sys.argv[i + 1]
                i += 2
            else:
                i += 1
        if not lang or not out:
            print("error: --lang and --out required")
            sys.exit(1)
        generate_header(lang, out)

    elif cmd == "list":
        print("Effect classes:")
        for cls_name, cls_info in SCHEMA["effect_classes"].items():
            ops = ", ".join(f"{op_name}={op_id}"
                            for op_name, op_id in cls_info["operations"].items())
            print(f"  {cls_name} (id={cls_info['id']}): {ops}")
        print("\nLegacy event map:")
        for evt_name, mapping in SCHEMA["legacy_event_map"].items():
            cls, op = LEGACY_MAP[evt_name]
            print(f"  {evt_name:12s} → class={mapping['class']:12s} op={mapping['op']:12s} "
                  f"(encoded={encode_event_type(cls, op)})")
        print("\nLegacy unmapped:")
        for evt_name, val in SCHEMA["legacy_unmapped"].items():
            print(f"  {evt_name:12s} → {val}")

    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    _cli()
