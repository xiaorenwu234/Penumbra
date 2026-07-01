/* SPDX-License-Identifier: MIT */
/*
 * socket_server.h – Unix socket JSON-line server for ShadowObserve daemon.
 */
#ifndef GHOSTBPF_OBSERV_SOCKET_SERVER_H
#define GHOSTBPF_OBSERV_SOCKET_SERVER_H

#include "ghostbpf-observ/observer.h"
#include "ghostbpf-observ/audit_engine.h"
#include "ghostbpf-observ/enforcer.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <mutex>

namespace ghostbpf_observ {

/**
 * ObserveDaemon – manages multiple Observer instances and provides
 * a Unix socket API for external coordination.
 *
 * Supported actions (JSON-line protocol):
 *   start_observe  – {action, cgroup_id, log_path}
 *   stop_observe   – {action, cgroup_id}
 *   audit          – {action, log_path, rules: [{event_type, action, path_pattern}]}
 *   get_events     – {action, log_path, [limit]}
 *   install_whitelist – {action, cgroup_id, allowed_ops: [{event_type, path_prefix}]}
 *   remove_whitelist  – {action, cgroup_id}
 */
class ObserveDaemon {
public:
    ObserveDaemon();
    ~ObserveDaemon();

    /**
     * Start the daemon, listening on the given Unix socket path.
     * This call blocks until stop() is called.
     */
    void serve(const std::string &sock_path);

    /**
     * Stop the daemon and close the listening socket.
     */
    void stop();

    /**
     * Check if the daemon is running.
     */
    bool is_running() const { return running_.load(); }

private:
    struct ObserveSession {
        std::unique_ptr<Observer> observer;
        std::string log_path;
        uint64_t cgroup_id;
    };

    std::atomic<bool> running_{false};
    int listen_fd_ = -1;

    /* Active observation sessions: cgroup_id → session */
    std::unordered_map<uint64_t, ObserveSession> sessions_;
    std::mutex sessions_mu_;

    /* Enforcer for whitelist */
    std::unique_ptr<Enforcer> enforcer_;

    /* Polling thread for active observers */
    std::unique_ptr<std::thread> poll_thread_;

    /* Internal handlers */
    std::string handle_request(const std::string &json_line);
    std::string handle_start_observe(uint64_t cgroup_id, const std::string &log_path);
    std::string handle_stop_observe(uint64_t cgroup_id);
    std::string handle_audit(const std::string &log_path, const std::string &rules_json);
    std::string handle_get_events(const std::string &log_path, int limit);
    std::string handle_install_whitelist(uint64_t cgroup_id, const std::string &ops_json);
    std::string handle_remove_whitelist(uint64_t cgroup_id);

    void poll_loop();
    void handle_connection(int client_fd);
};

} // namespace ghostbpf_observ

#endif // GHOSTBPF_OBSERV_SOCKET_SERVER_H
