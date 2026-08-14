/* fs_symlink.c - FILESYSTEM/SYMLINK probe: creates a symbolic link. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *target = probe_target_path(argc, argv, "/tmp/shadow-probe-symlink-target");
    const char *linkpath = probe_target_path2(argc, argv, "/tmp/shadow-probe-symlink-link");
    WAIT_GO();

    int ret = symlink(target, linkpath);
    REPORT(ret);
}
