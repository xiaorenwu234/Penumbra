/* SPDX-License-Identifier: MIT */
/*
 * common.h - Shared infrastructure for RQ2 effect probe programs.
 *
 * Each probe:
 *   1. Reads SHADOW_GO_FD from the environment (a pipe fd).
 *   2. Blocks in read() on that fd until the test harness writes a byte.
 *   3. Executes exactly ONE side-effecting syscall.
 *   4. Prints "ret=<N> errno=<M>" to stdout and exits.
 *
 * The test harness places the probe into a monitored cgroup BEFORE writing
 * the go byte, so the BPF hooks see the syscall under attribution.
 */

#ifndef SHADOW_PROBE_COMMON_H
#define SHADOW_PROBE_COMMON_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

/*
 * WAIT_GO - Block until the harness signals execution.
 * Reads one byte from the fd named by SHADOW_GO_FD.
 * If the environment variable is missing, proceeds immediately (standalone mode).
 */
#define WAIT_GO() do { \
    const char *_go_fd_str = getenv("SHADOW_GO_FD"); \
    if (_go_fd_str) { \
        int _go_fd = atoi(_go_fd_str); \
        char _buf[1]; \
        if (read(_go_fd, _buf, 1) < 0) { \
            fprintf(stderr, "probe: go-fd read failed: %s\n", strerror(errno)); \
        } \
        close(_go_fd); \
    } \
} while (0)

/*
 * REPORT - Print the syscall result in the canonical format and exit.
 * The harness parses "ret=<N> errno=<M>" from stdout.
 */
#define REPORT(ret_val) do { \
    int _saved_errno = errno; \
    long _rv = (long)(ret_val); \
    printf("ret=%ld errno=%d\n", _rv, _saved_errno); \
    fflush(stdout); \
    _exit(_rv == 0 ? 0 : (_saved_errno ? _saved_errno : 1)); \
} while (0)

/*
 * REPORT_ERRNO - Like REPORT but explicitly captures errno before the macro.
 * Use when the syscall return and errno must be captured atomically.
 */
#define REPORT_ERRNO(ret_val, err) do { \
    printf("ret=%ld errno=%d\n", (long)(ret_val), (err)); \
    fflush(stdout); \
    _exit((ret_val) == 0 ? 0 : (err ? err : 1)); \
} while (0)

/*
 * GET_TARGET_PATH - Get the target file/directory path from argv[1] or
 * fall back to a default in /tmp.
 */
static inline const char *probe_target_path(int argc, char **argv,
                                            const char *default_path)
{
    if (argc > 1 && argv[1][0] == '/')
        return argv[1];
    return default_path;
}

/*
 * GET_TARGET_PATH2 - Get a second path from argv[2] (for rename, link, etc.)
 */
static inline const char *probe_target_path2(int argc, char **argv,
                                             const char *default_path)
{
    if (argc > 2 && argv[2][0] == '/')
        return argv[2];
    return default_path;
}

#endif /* SHADOW_PROBE_COMMON_H */
