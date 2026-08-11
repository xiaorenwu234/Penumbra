/* sys_request_key.c - SYSTEM/KEYRING probe: request_key syscall.
 * Tests whether BPF intercepts kernel key request operations.
 */
#include "common.h"
#include <keyutils.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Request a key from the session keyring.
     * This will likely fail (no matching key) but the syscall entry
     * is what we're testing for BPF interception. */
    long ret = request_key("user", "shadow-probe-nonexistent-key",
                           NULL, KEY_SPEC_SESSION_KEYRING);
    int err = errno;
    REPORT_ERRNO(ret, err);
}
