/* fs_delete.c - FILESYSTEM/DELETE probe: unlinks a file. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-delete.txt");
    WAIT_GO();

    int ret = unlink(path);
    REPORT(ret);
}
