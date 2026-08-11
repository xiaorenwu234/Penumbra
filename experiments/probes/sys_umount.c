/* sys_umount.c - SYSTEM/UMOUNT probe: attempt umount2 syscall.
 * Expected to fail with EPERM/EINVAL in most contexts, but tests
 * whether BPF intercepts the syscall.
 */
#include "common.h"
#include <sys/mount.h>

int main(int argc, char **argv)
{
    /* Target path to unmount (use a nonexistent path for safety) */
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-nonexistent-mount");
    WAIT_GO();

    /* MNT_DETACH to avoid blocking; will fail with EINVAL/EINVAL but
     * the syscall entry is what we're testing */
    int ret = umount2(path, MNT_DETACH);
    int err = errno;
    REPORT_ERRNO(ret, err);
}
