/* sys_process_vm_writev.c - SYSTEM/PROCESS_VM probe: process_vm_writev syscall.
 * Writes to own address space via process_vm_writev (self-write).
 * Single-process design avoids fork interfering with BPF fence.
 */
#include "common.h"
#include <sys/uio.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Self-write: write to our own address space via process_vm_writev.
     * This exercises the same BPF hook without fork complications. */
    char src_buf[64] = "SHADOW_VM_WRITE";
    char dst_buf[64] = {0};

    struct iovec local[1] = {
        { .iov_base = src_buf, .iov_len = sizeof(src_buf) }
    };
    struct iovec remote[1] = {
        { .iov_base = dst_buf, .iov_len = sizeof(dst_buf) }
    };

    /* Write to our own process (pid = self) */
    ssize_t ret = process_vm_writev(getpid(), local, 1, remote, 1, 0);
    int err = errno;
    REPORT_ERRNO(ret, err);
}
