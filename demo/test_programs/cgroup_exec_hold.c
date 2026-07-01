/*
 * cgroup_exec_hold.c - Launch agent in cgroup with transparent exit-hold.
 *
 * From the caller's perspective, this program exits normally when the agent
 * completes its work. But the actual agent process remains alive (held by
 * ShadowProc's exit-hold mechanism) for potential rollback or commit.
 *
 * Architecture:
 *   1. Move into cgroup
 *   2. Create eventfd for completion notification
 *   3. Fork:
 *      - Child: set LD_PRELOAD + __SHADOW_HOLD_FD env, exec the target
 *      - Parent: wait for either eventfd signal (agent done) or child death
 *   4. When eventfd fires: parent exits 0 → caller's wait() returns "success"
 *      The child is still alive, held by ShadowProc, awaiting commit/rollback.
 *   5. If child dies (killed by orchestrator rollback): parent exits with
 *      the child's exit status.
 *
 * Usage: cgroup_exec_hold <cgroup_procs_path> <libexithold_path> <command> [args...]
 *
 * The caller sees normal process semantics:
 *   cgroup_exec_hold ... && echo "agent completed successfully"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/wait.h>

/* fd number used to pass eventfd to child (high number to avoid conflicts) */
#define HOLD_FD 100

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <cgroup_procs_path> <libexithold_path> <command> [args...]\n",
            argv[0]);
        return 1;
    }

    const char *cgroup_procs_path = argv[1];
    const char *libexithold_path = argv[2];
    /* argv[3..] is the command + args */

    /* Step 1: Move into cgroup (before fork, so child inherits) */
    int cg_fd = open(cgroup_procs_path, O_WRONLY);
    if (cg_fd < 0) {
        fprintf(stderr, "open(%s): %s\n", cgroup_procs_path, strerror(errno));
        return 1;
    }
    char pid_buf[32];
    int len = snprintf(pid_buf, sizeof(pid_buf), "%d\n", getpid());
    if (write(cg_fd, pid_buf, len) < 0) {
        fprintf(stderr, "write cgroup.procs: %s\n", strerror(errno));
        close(cg_fd);
        return 1;
    }
    close(cg_fd);

    /* Step 2: Create eventfd for child → parent notification */
    int efd = eventfd(0, 0);
    if (efd < 0) {
        fprintf(stderr, "eventfd: %s\n", strerror(errno));
        return 1;
    }

    /* Step 3: Fork */
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return 1;
    }

    if (child == 0) {
        /* ─── Child process ─── */

        /* Put eventfd on HOLD_FD so the LD_PRELOAD library can find it */
        if (efd != HOLD_FD) {
            dup2(efd, HOLD_FD);
            close(efd);
        }

        /* Set environment for libexithold.so */
        char fd_str[16];
        snprintf(fd_str, sizeof(fd_str), "%d", HOLD_FD);
        setenv("__SHADOW_HOLD_FD", fd_str, 1);
        setenv("LD_PRELOAD", libexithold_path, 1);

        /* Close stdout/stderr to avoid BPF interception on this process
         * before exec. Reopen them as /dev/null so the exec'd program
         * still has valid fds 1 and 2. */
        /* Actually, DON'T close stdout/stderr - the agent needs them.
         * Just don't WRITE to them from this code path. */

        /* Exec the target command */
        execvp(argv[3], &argv[3]);

        /* exec failed - write error to fd 2 directly */
        const char *msg = "cgroup_exec_hold: exec failed\n";
        write(2, msg, strlen(msg));
        _exit(127);
    }

    /* ─── Parent process ─── */
    /* Parent keeps efd open for reading.
     * Child dup2'd efd to HOLD_FD, so child has its own reference.
     * Parent reads from efd to detect when child's destructor signals. */

    /* Step 4: Wait for completion or child death */
    struct pollfd pfd = { .fd = efd, .events = POLLIN };

    while (1) {
        int ret = poll(&pfd, 1, 200); /* 200ms timeout */

        if (ret > 0 && (pfd.revents & POLLIN)) {
            /* eventfd readable → child's destructor signaled completion */
            /* Agent has finished all work, about to enter exit-hold */
            return 0;
        }

        /* Check if child died (killed by orchestrator, or crashed) */
        int status;
        pid_t w = waitpid(child, &status, WNOHANG);
        if (w > 0) {
            /* Child is dead */
            if (WIFEXITED(status))
                return WEXITSTATUS(status);
            if (WIFSIGNALED(status))
                return 128 + WTERMSIG(status);
            return 1;
        }
    }
}
