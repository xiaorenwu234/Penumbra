/* SPDX-License-Identifier: MIT */
/*
 * audit_engine.cpp – post-event audit engine implementation.
 */
#include "ghostbpf-observ/audit_engine.h"

#include "observ_common.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace ghostbpf_observ {

/* ===================================================================== */
/*  ObservEvent                                                         */
/* ===================================================================== */

const char *ObservEvent::event_name() const {
    switch (event_type) {
    case FS_EVENT_OPEN:     return "OPEN";
    case FS_EVENT_CREATE:   return "CREATE";
    case FS_EVENT_DELETE:   return "DELETE";
    case FS_EVENT_RENAME:   return "RENAME";
    case FS_EVENT_CHMOD:    return "CHMOD";
    case FS_EVENT_CHOWN:    return "CHOWN";
    case FS_EVENT_MKDIR:    return "MKDIR";
    case FS_EVENT_RMDIR:    return "RMDIR";
    case FS_EVENT_LINK:     return "LINK";
    case FS_EVENT_SYMLINK:  return "SYMLINK";
    case FS_EVENT_TRUNCATE: return "TRUNCATE";
    case PROC_EVENT_EXEC:   return "EXEC";
    case PROC_EVENT_FORK:   return "FORK";
    case PROC_EVENT_EXIT:   return "EXIT";
    case PROC_EVENT_KILL:   return "KILL";
    case PROC_EVENT_PRCTL:  return "PRCTL";
    case PROC_EVENT_PTRACE: return "PTRACE";
    case PROC_EVENT_SETUID: return "SETUID";
    case PROC_EVENT_CAPSET: return "CAPSET";
    default:                return "UNKNOWN";
    }
}

/* ===================================================================== */
/*  minimal JSON-line parser                                            */
/* ===================================================================== */

static void skip_whitespace(const std::string &s, size_t &pos) {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t'))
        pos++;
}

static std::string extract_string(const std::string &s, size_t &pos) {
    if (pos >= s.size() || s[pos] != '"') return "";
    pos++;
    std::string val;
    while (pos < s.size() && s[pos] != '"') {
        if (s[pos] == '\\' && pos + 1 < s.size()) {
            pos++;
            switch (s[pos]) {
            case '"':  val += '"';  break;
            case '\\': val += '\\'; break;
            case 'n':  val += '\n'; break;
            case 'r':  val += '\r'; break;
            case 't':  val += '\t'; break;
            default:   val += s[pos]; break;
            }
        } else {
            val += s[pos];
        }
        pos++;
    }
    if (pos < s.size()) pos++;
    return val;
}

static bool parse_json_line(const std::string &line, ObservEvent &evt) {
    std::memset(&evt, 0, sizeof(evt));
    size_t pos = 0;
    skip_whitespace(line, pos);
    if (pos >= line.size() || line[pos] != '{') return false;
    pos++;

    std::string key, val;
    while (pos < line.size()) {
        skip_whitespace(line, pos);
        if (pos >= line.size()) break;
        if (line[pos] == '}') { pos++; break; }
        if (line[pos] == ',') { pos++; continue; }

        key = extract_string(line, pos);
        skip_whitespace(line, pos);
        if (pos >= line.size() || line[pos] != ':') return false;
        pos++;
        skip_whitespace(line, pos);

        if (line[pos] == '"') {
            val = extract_string(line, pos);
        } else {
            size_t start = pos;
            while (pos < line.size() && line[pos] != ',' && line[pos] != '}')
                pos++;
            val = line.substr(start, pos - start);
            while (!val.empty() && (val.back() == ' ' || val.back() == '\t'))
                val.pop_back();
        }

        if (key == "ts")            evt.timestamp_ns = static_cast<uint64_t>(std::stoull(val));
        else if (key == "pid")      evt.pid          = static_cast<uint32_t>(std::stoul(val));
        else if (key == "tid")      evt.tid          = static_cast<uint32_t>(std::stoul(val));
        else if (key == "uid")      evt.uid          = static_cast<uint32_t>(std::stoul(val));
        else if (key == "gid")      evt.gid          = static_cast<uint32_t>(std::stoul(val));
        else if (key == "cgroup_id") evt.cgroup_id   = static_cast<uint64_t>(std::stoull(val));
        else if (key == "arg1")     evt.arg1         = static_cast<uint32_t>(std::stoul(val));
        else if (key == "arg2")     evt.arg2         = static_cast<uint32_t>(std::stoul(val));
        else if (key == "arg3")     evt.arg3         = static_cast<uint32_t>(std::stoul(val));
        else if (key == "event") {
            if (val == "OPEN")       evt.event_type = FS_EVENT_OPEN;
            else if (val == "CREATE") evt.event_type = FS_EVENT_CREATE;
            else if (val == "DELETE") evt.event_type = FS_EVENT_DELETE;
            else if (val == "RENAME") evt.event_type = FS_EVENT_RENAME;
            else if (val == "CHMOD")  evt.event_type = FS_EVENT_CHMOD;
            else if (val == "CHOWN")  evt.event_type = FS_EVENT_CHOWN;
            else if (val == "MKDIR")  evt.event_type = FS_EVENT_MKDIR;
            else if (val == "RMDIR")  evt.event_type = FS_EVENT_RMDIR;
            else if (val == "LINK")   evt.event_type = FS_EVENT_LINK;
            else if (val == "SYMLINK") evt.event_type = FS_EVENT_SYMLINK;
            else if (val == "TRUNCATE") evt.event_type = FS_EVENT_TRUNCATE;
            else if (val == "EXEC")   evt.event_type = PROC_EVENT_EXEC;
            else if (val == "FORK")   evt.event_type = PROC_EVENT_FORK;
            else if (val == "EXIT")   evt.event_type = PROC_EVENT_EXIT;
            else if (val == "KILL")   evt.event_type = PROC_EVENT_KILL;
            else if (val == "PRCTL")  evt.event_type = PROC_EVENT_PRCTL;
            else if (val == "PTRACE") evt.event_type = PROC_EVENT_PTRACE;
            else if (val == "SETUID") evt.event_type = PROC_EVENT_SETUID;
            else if (val == "CAPSET") evt.event_type = PROC_EVENT_CAPSET;
        }
        else if (key == "comm")     std::strncpy(evt.comm, val.c_str(), sizeof(evt.comm) - 1);
        else if (key == "path")     std::strncpy(evt.path, val.c_str(), sizeof(evt.path) - 1);
        else if (key == "new_path") std::strncpy(evt.new_path, val.c_str(), sizeof(evt.new_path) - 1);
    }
    return true;
}

/* ===================================================================== */
/*  path matching                                                       */
/* ===================================================================== */

bool AuditEngine::path_matches(const std::string &pattern,
                               const std::string &path) {
    // Unified component-boundary prefix rule, identical to the BPF enforcer's
    // cri_check_whitelist (bpf/cri.bpf.h): a pattern matches iff it is empty
    // (any path), or equals the path, or is a directory prefix of it (path
    // starts with pattern followed by '/'). This ensures a policy that passes
    // this historical audit is enforced the same way at runtime -- e.g. "/tmp"
    // matches "/tmp/a/b" but NOT "/tmpfoo".
    if (pattern.empty()) return true;

    // Normalize away trailing slashes (keep a lone "/" as the root marker).
    std::string p = pattern;
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    if (p == "/") return true;            // root prefix matches every abs path
    if (p.empty()) return true;

    if (path.size() < p.size()) return false;
    if (path.compare(0, p.size(), p) != 0) return false;
    // Exact match, or the next char is a component boundary.
    return path.size() == p.size() || path[p.size()] == '/';
}

/* ===================================================================== */
/*  AuditEngine                                                         */
/* ===================================================================== */

void AuditEngine::add_allow_rule(int event_type, const std::string &path_prefix) {
    rules_.push_back({event_type, AUDIT_ALLOW, path_prefix});
}

void AuditEngine::add_deny_rule(int event_type, const std::string &path_prefix) {
    rules_.push_back({event_type, AUDIT_DENY, path_prefix});
}

void AuditEngine::clear_rules() { rules_.clear(); }

bool AuditEngine::endpoint_violation(int event_type, const std::string &path,
                                     AuditRule &matched_out) const {
    bool has_allow = false;
    const AuditRule *deny_rule = nullptr;

    for (const auto &r : rules_) {
        if (r.event_type != -1 && r.event_type != event_type)
            continue;
        if (!path_matches(r.path_pattern, path))
            continue;
        if (r.action == AUDIT_DENY) {
            deny_rule = &r;
            break;
        } else {
            has_allow = true;
        }
    }

    if (deny_rule) {
        matched_out = *deny_rule;
        return true;
    }
    // Default-deny: a non-empty rule set with no matching allow rule is a
    // violation. An empty rule set audits nothing (allows all).
    if (!has_allow && !rules_.empty()) {
        matched_out = {-1, AUDIT_DENY, "(default-deny)"};
        return true;
    }
    return false;
}

AuditReport AuditEngine::audit(const std::string &log_file_path) const {
    AuditReport report;

    std::ifstream log(log_file_path);
    if (!log) {
        fprintf(stderr, "[AuditEngine] cannot open %s\n", log_file_path.c_str());
        // Cannot read the log at all: treat as an incomplete log (fail closed).
        report.complete = false;
        report.integrity_reason = "cannot open log file";
        return report;
    }

    std::string line;
    while (std::getline(log, line)) {
        if (line.empty()) continue;

        ObservEvent evt;
        bool parsed = false;
        try {
            parsed = parse_json_line(line, evt);
        } catch (const std::exception &) {
            // A malformed numeric field (stoull/stoul) throws: count as a
            // parse failure rather than letting it abort the audit.
            parsed = false;
        }
        if (!parsed) {
            // An unparsable record is an UNKNOWN event that may hide a
            // violation. Do NOT silently skip it as if it passed: mark the
            // log incomplete so the caller fails the epoch closed.
            report.parse_errors++;
            report.complete = false;
            fprintf(stderr, "[AuditEngine] parse error: %s\n", line.c_str());
            continue;
        }

        report.total_events++;

        // Evaluate the primary/source resource (event.path).
        AuditRule matched_src;
        bool src_viol = endpoint_violation(static_cast<int>(evt.event_type),
                                           std::string(evt.path), matched_src);

        // DUAL-RESOURCE operations (RENAME, hard LINK) also touch a second
        // resource carried in new_path (rename destination / existing link
        // target). The operation must satisfy the policy for BOTH endpoints,
        // so evaluate the destination too and treat a violation on EITHER
        // side as a violation of the whole operation. This closes the
        // "rename an allowed file into a forbidden directory" bypass and
        // matches the BPF enforcer, which denies unless both dentries pass.
        bool is_dual = (evt.event_type == FS_EVENT_RENAME ||
                        evt.event_type == FS_EVENT_LINK);
        std::string dst_path(evt.new_path);
        AuditRule matched_dst;
        bool dst_viol = false;
        if (is_dual && !dst_path.empty())
            dst_viol = endpoint_violation(static_cast<int>(evt.event_type),
                                          dst_path, matched_dst);

        if (src_viol || dst_viol) {
            Violation v;
            v.event = evt;
            std::ostringstream desc;
            desc << "DENY: " << evt.event_name();
            if (src_viol && dst_viol) {
                v.matched_rule = matched_src;
                desc << " source '" << evt.path << "' and destination '"
                     << evt.new_path << "'";
            } else if (src_viol) {
                v.matched_rule = matched_src;
                desc << (is_dual ? " source '" : " '") << evt.path << "'";
            } else {
                v.matched_rule = matched_dst;
                desc << " destination '" << evt.new_path << "'";
            }
            desc << " (pid=" << evt.pid << " comm=" << evt.comm << ")";
            const AuditRule &mr = src_viol ? matched_src : matched_dst;
            if (mr.path_pattern == "(default-deny)")
                desc << " -- no matching allow rule";
            else
                desc << " matches blacklist '" << mr.path_pattern << "'";
            v.description = desc.str();
            report.violations.push_back(std::move(v));
            report.total_violations++;
        }
    }

    if (!report.complete && report.integrity_reason.empty()) {
        std::ostringstream r;
        r << "parse_errors=" << report.parse_errors;
        report.integrity_reason = r.str();
    }

    return report;
}

} // namespace ghostbpf_observ
