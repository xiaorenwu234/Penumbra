/* SPDX-License-Identifier: MIT */
/*
 * demo.cpp – demonstration of ghostbpf-observ.
 *
 * Usage:
 *   sudo ./observ_demo <cgroup_id> [duration_sec]
 *
 * Example:
 *   # Find cgroup id:
 *   ls -li /sys/fs/cgroup/system.slice/sshd.service
 *   # 12345 is the inode number
 *   sudo ./observ_demo 12345 10
 *
 * The demo:
 *   1. Starts recording for the given cgroup.
 *   2. Waits for the specified duration.
 *   3. Stops recording.
 *   4. Loads a sample rule set and audits the log.
 *   5. Prints the audit report.
 */
#include "ghostbpf-observ/observer.h"
#include "ghostbpf-observ/audit_engine.h"
#include "observ_common.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

static void print_usage(const char *prog) {
    std::cerr << "Usage: " << prog << " <cgroup_id> [duration_sec]\n"
              << "  cgroup_id     – inode number from ls -li /sys/fs/cgroup/<path>\n"
              << "  duration_sec  – how long to record (default: 10)\n";
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    uint64_t cgroup_id = std::stoull(argv[1]);
    int duration_sec   = (argc >= 3) ? std::stoi(argv[2]) : 10;

    std::cout << "=== ghostbpf-observ demo ===\n"
              << "cgroup_id = " << cgroup_id << "\n"
              << "duration  = " << duration_sec << " sec\n\n";

    /* ---------- Phase 1: record --------------------------------------- */
    std::cout << "[1] Starting Observer...\n";

    ghostbpf_observ::Observer obs;

    if (!obs.start(cgroup_id, "events.jsonl")) {
        std::cerr << "Failed to start observer.\n";
        return 1;
    }

    std::cout << "[1] Recording to events.jsonl ...\n";

    /* poll the ring buffer for the duration */
    std::cout << "[1] Waiting " << duration_sec << " seconds"
              << " (run activity in the target cgroup now)...\n";
    auto deadline = std::chrono::steady_clock::now()
                    + std::chrono::seconds(duration_sec);
    while (std::chrono::steady_clock::now() < deadline) {
        obs.poll(100);
    }

    obs.stop();
    std::cout << "[1] Recording stopped.\n\n";

    /* ---------- Phase 2: audit ---------------------------------------- */
    std::cout << "[2] Loading audit rules...\n";
    ghostbpf_observ::AuditEngine engine;

    /* FS rules */
    engine.add_allow_rule(-1, "/tmp/");
    engine.add_allow_rule(-1, "/home/");
    engine.add_deny_rule(FS_EVENT_DELETE, "/etc/");
    engine.add_deny_rule(FS_EVENT_OPEN,   "/etc/shadow");

    /* Proc rules */
    engine.add_allow_rule(-1, "/usr/bin/");
    engine.add_allow_rule(-1, "/usr/sbin/");
    engine.add_allow_rule(-1, "/bin/");
    engine.add_allow_rule(-1, "/sbin/");
    engine.add_allow_rule(PROC_EVENT_EXEC, "/tmp/");
    engine.add_deny_rule(PROC_EVENT_PTRACE, "");  /* deny all ptrace */

    std::cout << "[2] Auditing events.jsonl ...\n";
    auto report = engine.audit("events.jsonl");

    /* ---------- Phase 3: report --------------------------------------- */
    std::cout << "\n========== AUDIT REPORT ==========\n"
              << "Total events:     " << report.total_events << "\n"
              << "Total violations: " << report.total_violations << "\n";

    if (report.total_violations == 0) {
        std::cout << "\n" << "No violations detected.\n";
    } else {
        std::cout << "\n--- Violations ---\n";
        for (size_t i = 0; i < report.violations.size(); i++) {
            const auto &v = report.violations[i];
            std::cout << "[" << (i + 1) << "] " << v.description << "\n";
        }
    }
    std::cout << "=================================\n";

    return 0;
}
