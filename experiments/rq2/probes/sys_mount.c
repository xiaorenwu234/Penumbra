/* sys_mount.c - SYSTEM/MOUNT probe: attempt a bind mount. */
#include "common.h"
#include <sys/mount.h>

int main(int argc, char **argv)
{
    const char *src = probe_target_path(argc, argv, "/tmp");
    const char *dst = probe_target_path2(argc, argv, "/tmp/shadow-probe-mnt");
    WAIT_GO();

    /* Create target dir if needed */
    mkdir(dst, 0755);
    int ret = mount(src, dst, NULL, MS_BIND, NULL);
    int err = errno;
    if (ret == 0)
        umount2(dst, MNT_DETACH);
    REPORT_ERRNO(ret, err);
}
