/* priv_setgroups.c - PRIVILEGE/SETGROUPS probe: attempt setgroups(). */
#include "common.h"
#include <grp.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    gid_t groups[] = {0};
    int ret = setgroups(1, groups);
    REPORT(ret);
}
