/* ipc_unix.c - IPC/UNIX_WRITE probe: send data over a Unix domain socket. */
#include "common.h"
#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char **argv)
{
    const char *sock_path = probe_target_path(argc, argv, "/tmp/shadow-probe-unix.sock");
    WAIT_GO();

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        REPORT(-1);
    }
    ssize_t ret = send(fds[0], "UNIX_DATA", 9, 0);
    int err = errno;
    close(fds[0]);
    close(fds[1]);
    REPORT_ERRNO(ret, err);
}
