/*
 * file_mutator.c - Mutates an EXISTING file (delete or rename), then triggers IPC.
 *
 * Usage: ./file_mutator <mount_dir> <op> <target> [newname]
 *   op = "delete"  -> unlink(<mount_dir>/<target>)
 *   op = "rename"  -> rename(<mount_dir>/<target>, <mount_dir>/<newname>)
 *
 * Flow:
 *   1. Perform the destructive metadata operation on a pre-existing (committed)
 *      file. ShadowFS records this as an undoable overlay entry (whiteout for
 *      delete, rename undo-log for rename).
 *   2. Attempt TCP connect to 192.0.2.1:12345 (intercepted by ShadowProc) so the
 *      process is frozen and the orchestrator can commit or roll the op back.
 *
 * Exit codes:
 *   0 - connect succeeded (process was resumed by orchestrator)
 *   1 - usage error
 *   2 - filesystem operation failed
 *   3 - connect failed / was intercepted (expected while frozen)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <mount_dir> <delete|rename> <target> [newname]\n", argv[0]);
        return 1;
    }

    const char *mount_dir = argv[1];
    const char *op = argv[2];
    const char *target = argv[3];

    char target_path[512];
    snprintf(target_path, sizeof(target_path), "%s/%s", mount_dir, target);

    /* ---- Phase 1: Destructive op on an existing file (ShadowFS records it) ---- */
    if (strcmp(op, "delete") == 0) {
        if (unlink(target_path) != 0) {
            perror("unlink");
            return 2;
        }
    } else if (strcmp(op, "rename") == 0) {
        if (argc < 5) {
            fprintf(stderr, "rename requires <newname>\n");
            return 1;
        }
        char new_path[512];
        snprintf(new_path, sizeof(new_path), "%s/%s", mount_dir, argv[4]);
        if (rename(target_path, new_path) != 0) {
            perror("rename");
            return 2;
        }
    } else {
        fprintf(stderr, "unknown op: %s (expected delete|rename)\n", op);
        return 1;
    }

    /* ---- Phase 2: Trigger IPC (ShadowProc intercepts this) ---- */
    usleep(200000);  /* 200ms, let the driver script observe state */

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

    /* This connect() triggers ShadowProc's LSM socket_connect hook → SIGSTOP. */
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);

    return (ret == 0) ? 0 : 3;
}
