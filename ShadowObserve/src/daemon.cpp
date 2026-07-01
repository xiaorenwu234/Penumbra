/* SPDX-License-Identifier: MIT */
/*
 * daemon.cpp – ShadowObserve daemon entry point.
 *
 * Runs as a background service providing observation, audit, and
 * whitelist enforcement capabilities via Unix socket API.
 *
 * Usage:
 *   observ_daemon --sock /tmp/shadowobserve.sock
 */
#include "ghostbpf-observ/socket_server.h"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>

static ghostbpf_observ::ObserveDaemon *g_daemon = nullptr;

static void signal_handler(int /*sig*/) {
    if (g_daemon) g_daemon->stop();
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --sock <path>\n"
        "\n"
        "Options:\n"
        "  --sock <path>    Unix socket path for API (required)\n"
        "  --help           Show this help\n"
        "\n"
        "ShadowObserve daemon provides:\n"
        "  - Multi-cgroup eBPF event observation (FS + process events)\n"
        "  - Rule-based audit engine\n"
        "  - Whitelist eBPF LSM enforcement\n"
        "\n"
        "Protocol: JSON-line over Unix socket\n"
        "Actions: start_observe, stop_observe, audit, get_events,\n"
        "         install_whitelist, remove_whitelist\n",
        prog);
}

int main(int argc, char *argv[]) {
    std::string sock_path;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sock") == 0 && i + 1 < argc) {
            sock_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (sock_path.empty()) {
        fprintf(stderr, "Error: --sock is required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    fprintf(stderr, "╔══════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║       ShadowObserve - Observation & Enforcement Daemon  ║\n");
    fprintf(stderr, "╠══════════════════════════════════════════════════════════╣\n");
    fprintf(stderr, "║  Socket: %-47s║\n", sock_path.c_str());
    fprintf(stderr, "╚══════════════════════════════════════════════════════════╝\n");
    fprintf(stderr, "\n");

    ghostbpf_observ::ObserveDaemon daemon;
    g_daemon = &daemon;

    /* Install signal handlers for graceful shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    daemon.serve(sock_path);

    fprintf(stderr, "[ObserveDaemon] Stopped.\n");
    return 0;
}
