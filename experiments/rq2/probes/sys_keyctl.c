/* sys_keyctl.c - SYSTEM/KEYRING probe: keyctl(KEYCTL_GET_KEYRING_ID). */
#include "common.h"
#include <sys/syscall.h>
#include <linux/keyctl.h>

#ifndef __NR_keyctl
#define __NR_keyctl 250
#endif

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Query the session keyring - exercises the keyctl hook */
    long ret = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID,
                       KEY_SPEC_SESSION_KEYRING, 0);
    REPORT(ret);
}
