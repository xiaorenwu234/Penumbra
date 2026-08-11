/* priv_capset.c - PRIVILEGE/CAPSET probe: attempt capset() to modify capabilities. */
#include "common.h"
#include <sys/syscall.h>
#include <stdint.h>

/* Capability structures (from linux/capability.h, self-contained) */
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#define CAP_NET_RAW 13

struct __user_cap_header_struct {
    uint32_t version;
    int pid;
};

struct __user_cap_data_struct {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}};
    /* Try to set CAP_NET_RAW in effective set */
    data[0].effective = (1 << CAP_NET_RAW);
    data[0].permitted = (1 << CAP_NET_RAW);

    int ret = syscall(SYS_capset, &hdr, data);
    REPORT(ret);
}
