/* SPDX-License-Identifier: MIT */
/*
 * socket_server.cpp – Unix socket JSON-line server for ShadowObserve daemon.
 */
#include "ghostbpf-observ/socket_server.h"
#include "observ_common.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

namespace ghostbpf_observ {

/* ===================================================================== */
/*  Minimal JSON helpers (no external deps)                              */
/* ===================================================================== */

static std::string json_escape_str(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        default:   out += c;
        }
    }
    return out;
}

static std::string json_ok(const std::string &extra = "") {
    if (extra.empty())
        return "{\"status\":\"ok\"}\n";
    return "{\"status\":\"ok\"," + extra + "}\n";
}

static std::string json_error(const std::string &msg) {
    return "{\"status\":\"error\",\"message\":\"" + json_escape_str(msg) + "\"}\n";
}

/* Simple JSON string value extractor (handles optional spaces after colon) */
static std::string json_get_string(const std::string &json, const std::string &key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    /* Skip optional whitespace and colon */
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) pos++;
    /* Skip optional whitespace after colon */
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (pos >= json.size() || json[pos] != '"') return "";
    pos++;
    auto end = json.find('"', pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

/* Simple JSON number value extractor (handles optional spaces) */
static uint64_t json_get_uint64(const std::string &json, const std::string &key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    /* Skip optional whitespace and colon */
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) pos++;
    /* Skip optional whitespace after colon */
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (pos >= json.size()) return 0;
    try { return std::stoull(json.substr(pos)); } catch (...) { return 0; }
}

static int json_get_int(const std::string &json, const std::string &key, int def = 0) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return def;
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) pos++;
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (pos >= json.size()) return def;
    try { return std::stoi(json.substr(pos)); } catch (...) { return def; }
}

/* Extract a JSON array substring (including brackets, handles spaces) */
static std::string json_get_array(const std::string &json, const std::string &key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "[]";
    pos += needle.size();
    /* Skip whitespace and colon */
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) pos++;
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (pos >= json.size() || json[pos] != '[') return "[]";

    int depth = 0;
    size_t start = pos;
    for (size_t i = pos; i < json.size(); i++) {
        if (json[i] == '[') depth++;
        else if (json[i] == ']') {
            depth--;
            if (depth == 0) return json.substr(start, i - start + 1);
        }
    }
    return "[]";
}

/* Parse a simple array of objects: [{...}, {...}] → vector of JSON strings */
static std::vector<std::string> json_parse_array_objects(const std::string &arr) {
    std::vector<std::string> result;
    int depth = 0;
    size_t obj_start = 0;
    for (size_t i = 0; i < arr.size(); i++) {
        if (arr[i] == '{') {
            if (depth == 0) obj_start = i;
            depth++;
        } else if (arr[i] == '}') {
            depth--;
            if (depth == 0) {
                result.push_back(arr.substr(obj_start, i - obj_start + 1));
            }
        }
    }
    return result;
}

/* ===================================================================== */
/*  ObserveDaemon implementation                                         */
/* ===================================================================== */

ObserveDaemon::ObserveDaemon() {
    try {
        enforcer_ = std::make_unique<Enforcer>();
    } catch (const std::exception &e) {
        fprintf(stderr, "[ObserveDaemon] Warning: Enforcer init failed: %s\n", e.what());
        fprintf(stderr, "[ObserveDaemon] Whitelist enforcement will be unavailable.\n");
        enforcer_ = nullptr;
    }
}

ObserveDaemon::~ObserveDaemon() {
    stop();
}

void ObserveDaemon::serve(const std::string &sock_path) {
    /* Remove stale socket */
    unlink(sock_path.c_str());

    listen_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        fprintf(stderr, "[ObserveDaemon] socket() failed: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(listen_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[ObserveDaemon] bind() failed: %s\n", strerror(errno));
        close(listen_fd_);
        return;
    }

    /* Make socket world-accessible */
    chmod(sock_path.c_str(), 0777);

    if (listen(listen_fd_, 16) < 0) {
        fprintf(stderr, "[ObserveDaemon] listen() failed: %s\n", strerror(errno));
        close(listen_fd_);
        return;
    }

    running_ = true;
    fprintf(stderr, "[ObserveDaemon] Listening on %s\n", sock_path.c_str());

    /* Start poll thread for active observers */
    poll_thread_ = std::make_unique<std::thread>(&ObserveDaemon::poll_loop, this);

    /* Accept loop */
    while (running_) {
        struct pollfd pfd = {listen_fd_, POLLIN, 0};
        int ret = poll(&pfd, 1, 500); /* 500ms timeout */
        if (ret <= 0) continue;

        int client_fd = accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) continue;

        /* Handle in a new thread */
        std::thread([this, client_fd]() {
            handle_connection(client_fd);
        }).detach();
    }

    close(listen_fd_);
    unlink(sock_path.c_str());

    if (poll_thread_ && poll_thread_->joinable())
        poll_thread_->join();
}

void ObserveDaemon::stop() {
    running_ = false;
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
    }
}

void ObserveDaemon::poll_loop() {
    while (running_) {
        {
            std::lock_guard<std::mutex> lock(sessions_mu_);
            for (auto &[cg, session] : sessions_) {
                if (session.observer && session.observer->is_running()) {
                    session.observer->poll(0); /* non-blocking */
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void ObserveDaemon::handle_connection(int client_fd) {
    FILE *fp = fdopen(dup(client_fd), "r");
    if (!fp) { close(client_fd); return; }

    char buf[8192];
    while (fgets(buf, sizeof(buf), fp)) {
        std::string line(buf);
        /* Trim trailing newline */
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        if (line.empty()) continue;

        std::string response = handle_request(line);
        ssize_t n = write(client_fd, response.c_str(), response.size());
        (void)n; /* ignore write errors on client disconnect */
    }

    fclose(fp);
    close(client_fd);
}

std::string ObserveDaemon::handle_request(const std::string &json_line) {
    std::string action = json_get_string(json_line, "action");

    if (action == "start_observe") {
        uint64_t cgroup_id = json_get_uint64(json_line, "cgroup_id");
        std::string log_path = json_get_string(json_line, "log_path");
        if (cgroup_id == 0) return json_error("cgroup_id required");
        if (log_path.empty()) return json_error("log_path required");
        return handle_start_observe(cgroup_id, log_path);
    }
    else if (action == "stop_observe") {
        uint64_t cgroup_id = json_get_uint64(json_line, "cgroup_id");
        if (cgroup_id == 0) return json_error("cgroup_id required");
        return handle_stop_observe(cgroup_id);
    }
    else if (action == "audit") {
        std::string log_path = json_get_string(json_line, "log_path");
        std::string rules = json_get_array(json_line, "rules");
        if (log_path.empty()) return json_error("log_path required");
        return handle_audit(log_path, rules);
    }
    else if (action == "get_events") {
        std::string log_path = json_get_string(json_line, "log_path");
        int limit = json_get_int(json_line, "limit", 100);
        if (log_path.empty()) return json_error("log_path required");
        return handle_get_events(log_path, limit);
    }
    else if (action == "install_whitelist") {
        uint64_t cgroup_id = json_get_uint64(json_line, "cgroup_id");
        std::string ops = json_get_array(json_line, "allowed_ops");
        if (cgroup_id == 0) return json_error("cgroup_id required");
        return handle_install_whitelist(cgroup_id, ops);
    }
    else if (action == "remove_whitelist") {
        uint64_t cgroup_id = json_get_uint64(json_line, "cgroup_id");
        if (cgroup_id == 0) return json_error("cgroup_id required");
        return handle_remove_whitelist(cgroup_id);
    }
    else {
        return json_error("unknown action: " + action);
    }
}

std::string ObserveDaemon::handle_start_observe(uint64_t cgroup_id, const std::string &log_path) {
    std::lock_guard<std::mutex> lock(sessions_mu_);

    /* Stop existing session if any */
    auto it = sessions_.find(cgroup_id);
    if (it != sessions_.end()) {
        it->second.observer->stop();
        sessions_.erase(it);
    }

    ObserveSession session;
    session.cgroup_id = cgroup_id;
    session.log_path = log_path;
    session.observer = std::make_unique<Observer>();

    if (!session.observer->start(cgroup_id, log_path)) {
        return json_error("failed to start observer for cgroup");
    }

    sessions_[cgroup_id] = std::move(session);
    fprintf(stderr, "[ObserveDaemon] Started observing cgroup %lu → %s\n",
            cgroup_id, log_path.c_str());
    return json_ok("\"log_path\":\"" + json_escape_str(log_path) + "\"");
}

std::string ObserveDaemon::handle_stop_observe(uint64_t cgroup_id) {
    std::lock_guard<std::mutex> lock(sessions_mu_);

    auto it = sessions_.find(cgroup_id);
    if (it == sessions_.end()) {
        return json_error("no active observation for this cgroup");
    }

    std::string log_path = it->second.log_path;
    IntegrityReport rep = it->second.observer->stop();
    sessions_.erase(it);

    fprintf(stderr, "[ObserveDaemon] Stopped observing cgroup %lu (complete=%d "
            "dropped=%lu write_err=%d drain_err=%d)\n",
            cgroup_id, rep.complete, (unsigned long)rep.dropped_events,
            rep.write_error, rep.drain_error);

    /* Surface the log-integrity status so the orchestrator can fail the epoch
     * closed when the recorded log is known to be incomplete. */
    std::ostringstream extra;
    extra << "\"log_path\":\"" << json_escape_str(log_path) << "\""
          << ",\"complete\":"       << (rep.complete ? "true" : "false")
          << ",\"dropped_events\":" << rep.dropped_events
          << ",\"write_error\":"    << (rep.write_error ? "true" : "false")
          << ",\"drain_error\":"    << (rep.drain_error ? "true" : "false");
    if (!rep.complete)
        extra << ",\"reason\":\"" << json_escape_str(rep.reason) << "\"";
    return json_ok(extra.str());
}

std::string ObserveDaemon::handle_audit(const std::string &log_path, const std::string &rules_json) {
    AuditEngine engine;

    /* Parse rules from JSON array */
    auto rule_objects = json_parse_array_objects(rules_json);
    for (const auto &obj : rule_objects) {
        int event_type = json_get_int(obj, "event_type", -1);
        std::string action_str = json_get_string(obj, "action");
        std::string path_pattern = json_get_string(obj, "path_pattern");

        if (action_str == "allow" || action_str == "ALLOW") {
            engine.add_allow_rule(event_type, path_pattern);
        } else if (action_str == "deny" || action_str == "DENY") {
            engine.add_deny_rule(event_type, path_pattern);
        }
    }

    /* Run audit */
    AuditReport report = engine.audit(log_path);

    /* Build response */
    std::ostringstream extra;
    extra << "\"total_events\":" << report.total_events
          << ",\"total_violations\":" << report.total_violations
          << ",\"parse_errors\":" << report.parse_errors
          << ",\"complete\":" << (report.complete ? "true" : "false");
    if (!report.complete)
        extra << ",\"integrity_reason\":\""
              << json_escape_str(report.integrity_reason) << "\"";
    extra << ",\"violations\":[";

    for (size_t i = 0; i < report.violations.size(); i++) {
        if (i > 0) extra << ",";
        auto &v = report.violations[i];
        extra << "{\"event\":\"" << v.event.event_name() << "\""
              << ",\"path\":\"" << json_escape_str(v.event.path) << "\""
              << ",\"pid\":" << v.event.pid
              << ",\"description\":\"" << json_escape_str(v.description) << "\"}";
    }
    extra << "]";

    return json_ok(extra.str());
}

std::string ObserveDaemon::handle_get_events(const std::string &log_path, int limit) {
    std::ifstream file(log_path);
    if (!file) return json_error("cannot open log file: " + log_path);

    std::ostringstream extra;
    extra << "\"events\":[";

    std::string line;
    int count = 0;
    while (std::getline(file, line) && count < limit) {
        if (line.empty()) continue;
        if (count > 0) extra << ",";
        extra << line;  /* Already JSON */
        count++;
    }
    extra << "],\"count\":" << count;

    return json_ok(extra.str());
}

std::string ObserveDaemon::handle_install_whitelist(uint64_t cgroup_id, const std::string &ops_json) {
    if (!enforcer_) {
        return json_error("enforcer not available (BPF LSM may not be supported)");
    }

    /* Enable enforcement for this cgroup */
    if (!enforcer_->enable(cgroup_id)) {
        return json_error("failed to enable enforcement for cgroup");
    }

    /* Parse allowed_ops and add rules */
    auto ops = json_parse_array_objects(ops_json);
    size_t added = 0;
    for (const auto &op : ops) {
        WhitelistRule rule;
        rule.cgroup_id = cgroup_id;
        rule.event_type = static_cast<uint16_t>(json_get_int(op, "event_type", 0xFFFF));
        rule.path_prefix = json_get_string(op, "path_prefix");
        if (enforcer_->add_rule(rule)) added++;
    }

    fprintf(stderr, "[ObserveDaemon] Installed whitelist for cgroup %lu: %zu rules\n",
            cgroup_id, added);

    std::ostringstream extra;
    extra << "\"rules_added\":" << added;
    return json_ok(extra.str());
}

std::string ObserveDaemon::handle_remove_whitelist(uint64_t cgroup_id) {
    if (!enforcer_) {
        return json_error("enforcer not available");
    }

    enforcer_->disable(cgroup_id);
    fprintf(stderr, "[ObserveDaemon] Removed whitelist for cgroup %lu\n", cgroup_id);
    return json_ok();
}

} // namespace ghostbpf_observ
