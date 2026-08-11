/* ipc_pipe.c - IPC/PIPE_WRITE probe: write to a pipe. */
#include "common.h"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    int fds[2];
    if (pipe(fds) < 0) {
        REPORT(-1);
    }
    ssize_t ret = write(fds[1], "PIPE_DATA", 9);
    int err = errno;
    close(fds[0]);
    close(fds[1]);
    REPORT_ERRNO(ret, err);
}
