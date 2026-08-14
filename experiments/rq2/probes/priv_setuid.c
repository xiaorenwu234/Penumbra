/* priv_setuid.c - PRIVILEGE/SETUID probe: attempt setuid(0). */
#include "common.h"
#include <sys/types.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Attempt to set uid to 0 (root). Will succeed if already root,
     * fail with EPERM otherwise. Either way it exercises the hook. */
    int ret = setuid(0);
    REPORT(ret);
}
