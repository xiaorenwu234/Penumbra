/* fs_rmdir.c - FILESYSTEM/RMDIR probe: removes a directory. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-rmdir");
    WAIT_GO();

    int ret = rmdir(path);
    REPORT(ret);
}
