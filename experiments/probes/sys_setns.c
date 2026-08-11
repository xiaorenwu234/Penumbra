/* sys_setns.c - SYSTEM/NAMESPACE probe: attempt setns() on own namespace. */
#include "common.h"
#include <sched.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Open own mount namespace and try to re-enter it (no-op but exercises hook) */
    int fd = open("/proc/self/ns/mnt", O_RDONLY);
    if (fd < 0) {
        REPORT(fd);
    }
    int ret = setns(fd, CLONE_NEWNS);
    int err = errno;
    close(fd);
    REPORT_ERRNO(ret, err);
}
