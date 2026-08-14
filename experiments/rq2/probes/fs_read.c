/* fs_read.c - FILESYSTEM/READ probe: open + read a file. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-read.txt");
    WAIT_GO();

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        REPORT(fd);
    }
    char buf[256];
    ssize_t ret = read(fd, buf, sizeof(buf));
    int err = errno;
    close(fd);
    REPORT_ERRNO(ret, err);
}
