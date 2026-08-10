/*
 * priv_escalator.c - Simulates a process attempting privilege escalation.
 *
 * Usage: ./priv_escalator <mount_dir> <filename> <content>
 *
 * Flow:
 *   1. Write <content> to <mount_dir>/<filename> (recorded by ShadowFS)
 *   2. Attempt setuid(0) to escalate privileges (intercepted by ShadowProc)
 *   3. Process is frozen by eBPF until orchestrator resumes/kills it
 *
 * This demonstrates that even if a process writes valid files, it cannot
 * escalate privileges to compromise the system. The eBPF LSM hook
 * (task_fix_setuid) intercepts the setuid() call and freezes the process.
 *
 * Exit codes:
 *   0 - setuid succeeded (should not happen if ShadowProc is active)
 *   1 - usage error
 *   2 - file write failed
 *   3 - setuid was intercepted (expected)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

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

    /* ---- Phase 2: Attempt privilege escalation ---- */
    /* Short delay to let the bash script report status */
    usleep(200000);  /* 200ms */

    /* Attempt setuid(0) - try to become root.
     * This triggers ShadowProc's LSM task_fix_setuid hook.
     * The eBPF program returns -ERESTARTSYS and sends SIGSTOP.
     * The process is now frozen until the orchestrator acts on it. */
    int ret = setuid(0);
    if (ret == 0) {
        /* If we reach here, setuid succeeded (process was resumed by orchestrator
         * and allowed to continue — or ShadowProc is not active) */
        return 0;
    }

    /* setuid was blocked or failed */
    return 3;
}
