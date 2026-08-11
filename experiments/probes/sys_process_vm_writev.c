/* sys_process_vm_writev.c - SYSTEM/PROCESS_VM probe: process_vm_writev syscall.
 * Writes data to another process's address space.
 * Tests whether BPF intercepts cross-process memory access.
 */
#include "common.h"
#include <sys/uio.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Fork a child to be the target */
    pid_t child = fork();
    if (child < 0) {
        REPORT(child);
    }

    if (child == 0) {
        /* Child: allocate a buffer and wait to be written to */
        volatile char buf[64] = {0};
        /* Signal parent we're ready by writing to a pipe would be complex;
         * just sleep and let parent write */
        usleep(100000);  /* 100ms */
        _exit(0);
    }

    /* Parent: wait a bit for child to start, then write to its memory */
    usleep(10000);  /* 10ms */

    /* We need a valid address in the child. Since we just forked,
     * the child has the same address space layout. Use a stack address
     * that we know exists in both processes. */
    char local_buf[64] = "SHADOW_VM_WRITE";
    char target_buf[64];  /* Same offset in child's stack */

    struct iovec local[1] = {
        { .iov_base = local_buf, .iov_len = sizeof(local_buf) }
    };
    struct iovec remote[1] = {
        { .iov_base = target_buf, .iov_len = sizeof(target_buf) }
    };

    ssize_t ret = process_vm_writev(child, local, 1, remote, 1, 0);
    int err = errno;

    /* Clean up child */
    int status;
    waitpid(child, &status, 0);

    REPORT_ERRNO(ret, err);
}
