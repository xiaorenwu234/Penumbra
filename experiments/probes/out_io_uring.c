/* out_io_uring.c - OUTPUT/IO_URING probe: submit an I/O via io_uring.
 *
 * io_uring is an unsafe mechanism that bypasses traditional syscall hooks.
 * The system should REJECT this by design. This probe tests that rejection.
 */
#include "common.h"
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <string.h>

/* io_uring_setup syscall number (x86_64) */
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    struct io_uring_params params;
    memset(&params, 0, sizeof(params));

    /* Attempt to create an io_uring instance - should be rejected */
    int fd = syscall(__NR_io_uring_setup, 4, &params);
    int err = errno;
    if (fd >= 0)
        close(fd);
    REPORT_ERRNO(fd, err);
}
