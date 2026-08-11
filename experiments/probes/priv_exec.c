/* priv_exec.c - PRIVILEGE/EXEC probe: execve a target binary.
 * Tests whether BPF intercepts execve of privileged binaries.
 */
#include "common.h"
#include <sys/wait.h>

int main(int argc, char **argv)
{
    /* Target to exec: use /bin/true as a safe default */
    const char *target = (argc > 1) ? argv[1] : "/bin/true";
    WAIT_GO();

    pid_t child = fork();
    if (child < 0) {
        REPORT(child);
    }
    if (child == 0) {
        /* Child: attempt execve */
        char *args[] = {(char *)target, NULL};
        char *envp[] = {NULL};
        execve(target, args, envp);
        /* If execve returns, it failed */
        _exit(errno);
    }
    int status;
    waitpid(child, &status, 0);
    /* Report success if child exited 0 (execve succeeded) */
    int ret = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    int err = (ret == 0) ? 0 : EACCES;
    REPORT_ERRNO(ret, err);
}
