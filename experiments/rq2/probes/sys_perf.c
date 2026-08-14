/* sys_perf.c - SYSTEM/PERF probe: attempt perf_event_open(). */
#include "common.h"
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <string.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.disabled = 1;

    int fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    int err = errno;
    if (fd >= 0)
        close(fd);
    REPORT_ERRNO(fd, err);
}
