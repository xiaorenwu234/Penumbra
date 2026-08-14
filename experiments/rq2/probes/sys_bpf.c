/* sys_bpf.c - SYSTEM/BPF probe: attempt bpf(BPF_PROG_GET_NEXT_ID). */
#include "common.h"
#include <sys/syscall.h>
#include <linux/bpf.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* BPF_PROG_GET_NEXT_ID - read-only query that exercises the bpf hook */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    int ret = syscall(__NR_bpf, BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
    REPORT(ret);
}
