/* fs_truncate.c - FILESYSTEM/TRUNCATE probe: truncates a file to 0 bytes. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-truncate.txt");
    WAIT_GO();

    int ret = truncate(path, 0);
    REPORT(ret);
}
