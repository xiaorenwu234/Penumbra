/* fs_mkdir.c - FILESYSTEM/MKDIR probe: creates a directory. */
#include "common.h"
#include <sys/stat.h>

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-mkdir");
    WAIT_GO();

    int ret = mkdir(path, 0755);
    REPORT(ret);
}
