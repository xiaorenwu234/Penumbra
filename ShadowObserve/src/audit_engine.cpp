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
    if (pattern.empty()) return true;
    if (path.size() < pattern.size()) return false;
    return path.compare(0, pattern.size(), pattern) == 0;
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

AuditReport AuditEngine::audit(const std::string &log_file_path) const {
    AuditReport report;

    std::ifstream log(log_file_path);
    if (!log) {
        fprintf(stderr, "[AuditEngine] cannot open %s\n", log_file_path.c_str());
        return report;
    }

    std::string line;
    while (std::getline(log, line)) {
        if (line.empty()) continue;

        ObservEvent evt;
        if (!parse_json_line(line, evt)) {
            fprintf(stderr, "[AuditEngine] parse error: %s\n", line.c_str());
            continue;
        }

        report.total_events++;

        bool has_allow = false;
        bool has_deny  = false;
        const AuditRule *deny_rule = nullptr;

        for (const auto &r : rules_) {
            if (r.event_type != -1 && r.event_type != static_cast<int>(evt.event_type))
                continue;

            if (!path_matches(r.path_pattern, std::string(evt.path)))
                continue;

            if (r.action == AUDIT_DENY) {
                has_deny = true;
                deny_rule = &r;
                break;
            } else {
                has_allow = true;
            }
        }

        if (has_deny) {
            Violation v;
            v.event = evt;
            v.matched_rule = *deny_rule;
            std::ostringstream desc;
            desc << "DENY: " << evt.event_name()
                 << " on '" << evt.path << "'"
                 << " (pid=" << evt.pid << " comm=" << evt.comm << ")"
                 << " matches blacklist '" << deny_rule->path_pattern << "'";
            v.description = desc.str();
            report.violations.push_back(std::move(v));
            report.total_violations++;
        } else if (!has_allow && !rules_.empty()) {
            Violation v;
            v.event = evt;
            v.matched_rule = {-1, AUDIT_DENY, "(default-deny)"};
            std::ostringstream desc;
            desc << "DENY: " << evt.event_name()
                 << " on '" << evt.path << "'"
                 << " (pid=" << evt.pid << " comm=" << evt.comm << ")"
                 << " -- no matching allow rule";
            v.description = desc.str();
            report.violations.push_back(std::move(v));
            report.total_violations++;
        }
    }

    return report;
}

} // namespace ghostbpf_observ
