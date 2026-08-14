/* sys_process_vm.c - SYSTEM/PROCESS_VM probe: process_vm_readv on self. */
#include "common.h"
#include <sys/uio.h>
#include <sys/syscall.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Read from own process memory via process_vm_readv */
    volatile int target_val = 42;
    char buf[16];

    struct iovec local = { .iov_base = buf, .iov_len = sizeof(int) };
    struct iovec remote = { .iov_base = (void *)&target_val, .iov_len = sizeof(int) };

    ssize_t ret = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    int err = errno;
    REPORT_ERRNO(ret, err);
}
