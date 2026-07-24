/* SPDX-License-Identifier: MIT */
/*
 * audit_engine.h – public API for post-event file-system audit.
 */
#ifndef GHOSTBPF_OBSERV_AUDIT_ENGINE_H
#define GHOSTBPF_OBSERV_AUDIT_ENGINE_H

#include <cstdint>
#include <string>
#include <vector>

namespace ghostbpf_observ {

/* ---- types ------------------------------------------------------------ */

/** Mirrors the BPF-side observ_event for audit consumption. */
struct ObservEvent {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint32_t gid;
    uint64_t cgroup_id;
    uint16_t event_type;  /* FS_EVENT_* or PROC_EVENT_* */
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    char     comm[16];
    char     path[256];
    char     new_path[256];

    /** Human-readable event type name. */
    const char *event_name() const;
};

/** One rule – path prefix + action. */
struct AuditRule {
    int         event_type;       /* FS_EVENT_*, or -1 for any */
    int         action;           /* AUDIT_ALLOW or AUDIT_DENY */
    std::string path_pattern;     /* prefix to match */
};

/** A single violation – the event and the rule it matched. */
struct Violation {
    ObservEvent event;
    AuditRule   matched_rule;
    std::string description;
};

/** Summary produced by AuditEngine::audit(). */
struct AuditReport {
    std::vector<Violation> violations;
    size_t total_events     = 0;
    size_t total_violations = 0;
    /* Log-integrity status. `complete` is false if the log could not be opened
     * or any line failed to parse: an unparsable record is an unknown event
     * that could hide a violation, so the epoch must fail closed rather than
     * silently skip it. */
    size_t      parse_errors = 0;
    bool        complete     = true;
    std::string integrity_reason;
};

/* ---- engine ----------------------------------------------------------- */

/**
 * AuditEngine – loads rules, reads a JSONL event log, and produces a report.
 *
 * Usage:
 *   AuditEngine engine;
 *   engine.add_deny_rule(FS_EVENT_DELETE, "/etc/");
 *   engine.add_allow_rule(-1, "/tmp/");          // -1 = any event type
 *   auto report = engine.audit("events.jsonl");
 *   for (auto &v : report.violations) { ... }
 */
class AuditEngine {
public:
    AuditEngine() = default;

    /** Add a whitelist rule (events matching this are *allowed*). */
    void add_allow_rule(int event_type, const std::string &path_prefix);

    /** Add a blacklist rule (events matching this are *denied*). */
    void add_deny_rule(int event_type, const std::string &path_prefix);

    /** Remove all rules. */
    void clear_rules();

    /**
     * Audit a JSONL log file against the current rule set.
     *
     * Single-resource events (OPEN/CREATE/DELETE/... and all PROC events) are
     * matched against event.path. DUAL-RESOURCE file operations (RENAME and
     * hard LINK) carry a second resource in event.new_path and are governed by
     * two-endpoint semantics: the operation is a violation if EITHER endpoint
     * (source or destination) fails the policy. This mirrors the BPF enforcer,
     * which denies a rename/link unless BOTH dentries are whitelisted, so a
     * file in an allowed directory cannot be renamed/linked into a forbidden
     * one.
     * @return AuditReport with violations and summary counts.
     */
    AuditReport audit(const std::string &log_file_path) const;

private:
    std::vector<AuditRule> rules_;

    static bool path_matches(const std::string &pattern,
                             const std::string &path);

    /**
     * Evaluate a single resource endpoint (event_type + path) against the rule
     * set. Returns true if the endpoint is a violation (matched a deny rule, or
     * -- under default-deny with a non-empty rule set -- lacked any allow
     * rule). On a violation, matched_out receives the offending rule (a real
     * deny rule or the synthetic "(default-deny)").
     */
    bool endpoint_violation(int event_type, const std::string &path,
                            AuditRule &matched_out) const;
};

} // namespace ghostbpf_observ

#endif // GHOSTBPF_OBSERV_AUDIT_ENGINE_H
