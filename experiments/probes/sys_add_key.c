/* sys_add_key.c - SYSTEM/KEYRING probe: add_key syscall.
 * Tests whether BPF intercepts kernel keyring operations.
 */
#include "common.h"
#include <keyutils.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Add a key to the session keyring */
    const char *type = "user";
    const char *desc = "shadow-probe-test-key";
    const char *payload = "SHADOW_EFFECT_DATA";

    long ret = add_key(type, desc, payload, strlen(payload),
                       KEY_SPEC_SESSION_KEYRING);
    int err = errno;

    /* If successful, try to clean up (revoke the key) */
    if (ret >= 0) {
        keyctl(KEYCTL_REVOKE, ret);
    }

    REPORT_ERRNO(ret, err);
}
