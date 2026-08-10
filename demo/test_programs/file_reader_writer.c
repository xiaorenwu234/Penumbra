/*
 * file_reader_writer.c - Reads a file and writes a new one (for cascade demo).
 *
 * Usage: ./file_reader_writer <mount_dir> <read_file> <write_file> <prefix>
 *
 * Flow:
 *   1. Read <mount_dir>/<read_file> (ShadowFS records read dependency)
 *   2. Write <mount_dir>/<write_file> with content derived from read_file
 *   3. Exit normally (no IPC trigger)
 *
 * This establishes a dependency: this agent depends on the agent that
 * wrote <read_file>. When that upstream agent is rolled back, this
 * agent will also be rolled back via cascade.
 *
 * After writing, it triggers IPC (connect) so ShadowProc can freeze it,
 * enabling the cascade to also kill this process when rolled back.
 *
 * Exit codes:
 *   0 - connect succeeded (should not happen if ShadowProc is active)
 *   1 - usage error
 *   2 - read failed
 *   3 - write failed
 *   4 - connect failed / was intercepted (expected)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE 4096

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <mount_dir> <read_file> <write_file> <prefix>\n", argv[0]);
        return 1;
    }

    char read_path[512], write_path[512];
    snprintf(read_path, sizeof(read_path), "%s/%s", argv[1], argv[2]);
    snprintf(write_path, sizeof(write_path), "%s/%s", argv[1], argv[3]);

    /* ---- Phase 1: Read source file (ShadowFS records read dependency) ---- */
    int rfd = open(read_path, O_RDONLY);
    if (rfd < 0) {
        perror("open(read)");
        return 2;
    }
    char buf[BUF_SIZE];
    ssize_t n = read(rfd, buf, sizeof(buf) - 1);
    close(rfd);
    if (n < 0) {
        perror("read");
        return 2;
    }
    buf[n] = '\0';

    /* ---- Phase 2: Write derived file (ShadowFS records write) ---- */
    int wfd = open(write_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (wfd < 0) {
        perror("open(write)");
        return 3;
    }

    /* Write: prefix + original content */
    size_t prefix_len = strlen(argv[4]);
    write(wfd, argv[4], prefix_len);
    write(wfd, buf, n);
    close(wfd);

    /* ---- Phase 3: Trigger IPC (ShadowProc intercepts this) ---- */
    /* Short delay to let the bash script report status */
    usleep(200000);  /* 200ms */

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        perror("socket");
        return 4;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    inet_pton(AF_INET, "192.0.2.1", &addr.sin_addr);  /* TEST-NET, non-routable */

    /* This connect() triggers ShadowProc's LSM socket_connect hook.
     * The eBPF program returns -ERESTARTSYS and sends SIGSTOP.
     * The process is now frozen until the orchestrator acts on it. */
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    /* If we reach here, the process was resumed (or killed) by the orchestrator */
    close(sock);

    return (ret == 0) ? 0 : 4;
}
