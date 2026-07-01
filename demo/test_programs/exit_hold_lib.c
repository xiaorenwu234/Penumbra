/*
 * exit_hold_lib.c - LD_PRELOAD library for exit-hold mechanism.
 *
 * When loaded via LD_PRELOAD, this library installs a destructor that runs
 * just before process exit. The destructor:
 *   1. Notifies the parent (cgroup_exec_hold) via eventfd that work is done
 *   2. Sleeps 200ms (ensures any temporary BPF allow has expired)
 *   3. Connects to a sentinel address (192.0.2.255:65535) which ShadowProc's
 *      BPF recognizes and intercepts as EVENT_EXIT_HOLD
 *
 * From the caller's perspective, the process appears to have exited normally
 * (parent exits when it receives the eventfd notification). But the actual
 * process is held alive by BPF for potential rollback or commit.
 *
 * Environment variables:
 *   __SHADOW_HOLD_FD  - fd number of eventfd to notify parent (set by cgroup_exec_hold)
 *
 * Compile: gcc -shared -fPIC -o libexithold.so exit_hold_lib.c
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

/* Sentinel address recognized by ShadowProc BPF as EXIT_HOLD signal */
#define EXIT_HOLD_IP   "192.0.2.255"
#define EXIT_HOLD_PORT 65535

/*
 * Destructor: runs automatically during normal process exit
 * (return from main, exit(), but NOT _exit() or SIGKILL)
 */
__attribute__((destructor))
static void __shadow_exit_hold(void) {
    /*
     * Step 1: Notify parent that we've completed execution.
     * The parent (cgroup_exec_hold) will exit upon receiving this,
     * making the caller's wait() return immediately.
     * eventfd write is NOT intercepted by BPF (not a pipe/socket).
     */
    const char *fd_str = getenv("__SHADOW_HOLD_FD");
    if (fd_str) {
        int hold_fd = atoi(fd_str);
        if (hold_fd > 0) {
            uint64_t val = 1;
            write(hold_fd, &val, sizeof(val));
            close(hold_fd);
        }
    }

    /*
     * Step 2: Sleep 200ms to ensure any temporary BPF allow
     * (from resume_pid's 100ms window) has expired.
     */
    usleep(200000);

    /*
     * Step 3: Connect to sentinel address → BPF intercepts → SIGSTOP.
     * Process is now frozen until orchestrator commits or rolls back.
     */
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0)
        return;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(EXIT_HOLD_PORT);
    inet_pton(AF_INET, EXIT_HOLD_IP, &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    /* Reached here after orchestrator resumed us - clean up and let exit proceed */
    close(sock);
}
