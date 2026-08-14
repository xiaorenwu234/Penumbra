/* fs_mknod.c - FILESYSTEM/MKNOD probe: create a special file node. */
#include "common.h"
#include <sys/stat.h>

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-mknod");
    WAIT_GO();

    /* Create a regular file node (mode 0644, no dev needed for regular) */
    int ret = mknod(path, S_IFREG | 0644, 0);
    int err = errno;
    REPORT_ERRNO(ret, err);
}
