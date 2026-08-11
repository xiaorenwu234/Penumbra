/* fs_link.c - FILESYSTEM/LINK probe: creates a hard link. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *src = probe_target_path(argc, argv, "/tmp/shadow-probe-link-src.txt");
    const char *dst = probe_target_path2(argc, argv, "/tmp/shadow-probe-link-dst.txt");
    WAIT_GO();

    int ret = link(src, dst);
    REPORT(ret);
}
