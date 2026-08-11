/* fs_create.c - FILESYSTEM/CREATE probe: creates a new file. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-create.txt");
    WAIT_GO();

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    int err = errno;
    if (fd >= 0)
        close(fd);
    REPORT_ERRNO(fd, err);
}
