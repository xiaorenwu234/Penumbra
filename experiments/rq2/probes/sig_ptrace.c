/* sig_ptrace.c - SIGNAL/PTRACE probe: ptrace(PTRACE_TRACEME) on self. */
#include "common.h"
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Fork a child that does PTRACE_TRACEME, parent waits then detaches */
    pid_t child = fork();
    if (child == 0) {
        long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        int err = errno;
        printf("ret=%ld errno=%d\n", ret, err);
        fflush(stdout);
        _exit(ret == 0 ? 0 : (err ? err : 1));
    }
    int status;
    waitpid(child, &status, 0);
    /* Report child's result */
    if (WIFEXITED(status)) {
        printf("ret=%d errno=%d\n", WEXITSTATUS(status) == 0 ? 0 : -1,
               WEXITSTATUS(status));
    } else {
        printf("ret=-1 errno=%d\n", ECHILD);
    }
    fflush(stdout);
    _exit(0);
}
