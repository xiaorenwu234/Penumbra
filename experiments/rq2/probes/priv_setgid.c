/* priv_setgid.c - PRIVILEGE/SETGID probe: attempt setgid(0). */
#include "common.h"
#include <sys/types.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    int ret = setgid(0);
    REPORT(ret);
}
