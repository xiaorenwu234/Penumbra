/* fs_chown.c - FILESYSTEM/CHOWN probe: changes file ownership. */
#include "common.h"

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-chown.txt");
    WAIT_GO();

    /* Attempt to change owner to uid=1000, gid=1000 */
    int ret = chown(path, 1000, 1000);
    REPORT(ret);
}
