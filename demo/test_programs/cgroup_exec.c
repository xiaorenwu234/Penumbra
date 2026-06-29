/*
 * cgroup_exec.c - Minimal wrapper to move a process into a cgroup and exec.
 *
 * Unlike bash, this program does NOT write anything to stdout/stderr
 * internally, so ShadowProc's BPF hook won't intercept it before exec.
 *
 * Usage: cgroup_exec <cgroup_procs_path> <command> [args...]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        /* Write usage to stderr — we're NOT in the cgroup yet */
        fprintf(stderr, "Usage: %s <cgroup_procs_path> <command> [args...]\n",
                argv[0]);
        return 1;
    }

    const char *cgroup_procs_path = argv[1];

    /* Open cgroup.procs file */
    int fd = open(cgroup_procs_path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", cgroup_procs_path, strerror(errno));
        return 1;
    }

    /* Write our own PID to move into the cgroup */
    char pid_buf[32];
    int len = snprintf(pid_buf, sizeof(pid_buf), "%d\n", getpid());
    if (write(fd, pid_buf, len) < 0) {
        fprintf(stderr, "write cgroup.procs: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    close(fd);

    /* Now we're in the cgroup. exec the command.
     * This program wrote NOTHING to stdout/stderr while in the cgroup,
     * so ShadowProc's BPF hook never intercepted us.
     * After exec, the new program inherits fds 0/1/2 from the parent. */
    execvp(argv[2], &argv[2]);

    /* If exec fails, we're still in the cgroup — avoid fprintf to stdout.
     * Write error directly to stderr fd. */
    const char *msg = "exec failed\n";
    write(2, msg, strlen(msg));
    return 1;
}
