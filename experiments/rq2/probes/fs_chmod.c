/* fs_chmod.c - FILESYSTEM/CHMOD probe: changes file permissions. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-chmod.txt");
    WAIT_GO();

    int ret = chmod(path, 0755);
    REPORT(ret);
}
