/* sys_unshare.c - SYSTEM/NAMESPACE probe: unshare(0) - no-op namespace syscall. */
#include "common.h"
#include <sched.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* unshare(0) normally succeeds with no side effect - stable probe */
    int ret = unshare(0);
    REPORT(ret);
}
