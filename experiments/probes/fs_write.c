/* fs_write.c - FILESYSTEM/WRITE probe: writes data to an existing file. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-write.txt");
    WAIT_GO();

    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        REPORT(fd);
    }
    ssize_t ret = write(fd, "SHADOW_EFFECT_DATA", 18);
    int err = errno;
    close(fd);
    REPORT_ERRNO(ret, err);
}
