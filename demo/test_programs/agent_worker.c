/*
 * agent_worker.c - Simulates an agent that writes files then triggers IPC.
 *
 * Usage: ./agent_worker <mount_dir> <filename> <content>
 *
 * Flow:
 *   1. Write <content> to <mount_dir>/<filename> (recorded by ShadowFS)
 *   2. Attempt TCP connect to 192.0.2.1:12345 (intercepted by ShadowProc)
 *   3. Process is frozen by eBPF until orchestrator resumes/kills it
 *
 * Exit codes:
 *   0 - connect succeeded (should not happen if ShadowProc is active)
 *   1 - usage error
 *   2 - file write failed
 *   3 - connect failed / was intercepted (expected)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <mount_dir> <filename> <content>\n", argv[0]);
        return 1;
    }

    /* ---- Phase 1: Write file (ShadowFS records this) ---- */
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", argv[1], argv[2]);

    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 2;
    }
    size_t len = strlen(argv[3]);
    if (write(fd, argv[3], len) != (ssize_t)len) {
        perror("write");
        close(fd);
        return 2;
    }
    close(fd);
    /* File written successfully — ShadowFS has recorded the agent */

    /* ---- Phase 2: Trigger IPC (ShadowProc intercepts this) ---- */
    /* Short delay to let the bash script report status */
    usleep(200000);  /* 200ms */

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        perror("socket");
        return 3;
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
    /* If we reach here, the process was resumed by the orchestrator */
    close(sock);

    return (ret == 0) ? 0 : 3;
}
