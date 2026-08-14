/* fs_rename.c - FILESYSTEM/RENAME probe: renames a file. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *src = probe_target_path(argc, argv, "/tmp/shadow-probe-rename-src.txt");
    const char *dst = probe_target_path2(argc, argv, "/tmp/shadow-probe-rename-dst.txt");
    WAIT_GO();

    int ret = rename(src, dst);
    REPORT(ret);
}
