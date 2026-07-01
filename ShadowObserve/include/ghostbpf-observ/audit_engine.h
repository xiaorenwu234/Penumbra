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
     * Matches against event.path for all event types.
     * @return AuditReport with violations and summary counts.
     */
    AuditReport audit(const std::string &log_file_path) const;

private:
    std::vector<AuditRule> rules_;

    static bool path_matches(const std::string &pattern,
                             const std::string &path);
};

} // namespace ghostbpf_observ

#endif // GHOSTBPF_OBSERV_AUDIT_ENGINE_H
