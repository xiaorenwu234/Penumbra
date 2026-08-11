/* ipc_mmap.c - IPC/SHARED_MAPPING probe: create a shared anonymous mmap and write. */
#include "common.h"
#include <sys/mman.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        REPORT(-1);
    }
    /* Write to the shared mapping - this is the side effect */
    memcpy(ptr, "MMAP_SHARED_DATA", 16);
    int err = errno;

    /* Also fork to make it truly shared across processes */
    pid_t child = fork();
    if (child == 0) {
        /* Child reads the shared data */
        volatile char c = ((char *)ptr)[0];
        (void)c;
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    munmap(ptr, 4096);
    REPORT_ERRNO(0, err);
}
