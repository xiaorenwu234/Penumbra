/* SPDX-License-Identifier: MIT */
/*
 * common.h - Shared infrastructure for RQ2 effect probe programs.
 *
 * Each probe:
 *   1. Performs its setup (open/pipe/create). Setup must not be the effect
 *      under test.
 *   2. Announces "setup done" by writing one byte to SHADOW_READY_FD.
 *   3. Blocks in read() on SHADOW_GO_FD until the test harness writes a byte.
 *   4. Executes exactly ONE side-effecting syscall.
 *   5. Prints "ret=<N> errno=<M>" to stdout and exits.
 *
 * The harness waits for the step-2 announcement BEFORE placing the probe into
 * the monitored cgroup, and only then writes the go byte. So the BPF hooks see
 * the syscall under test -- and only that syscall -- under attribution.
 * Both environment variables are optional; with neither set the probe runs
 * standalone.
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
 * WAIT_GO - Announce that setup is complete, then block until the harness
 * signals execution.
 *
 * Two-step handshake:
 *   1. write one byte to SHADOW_READY_FD -> "every setup syscall has returned"
 *   2. read one byte from SHADOW_GO_FD   -> "you are under test now, proceed"
 *
 * Why step 1 is needed: the harness used to Popen() the probe and write
 * cgroup.procs only afterwards, so whether a *setup* syscall ran inside or
 * outside the enforced cgroup was decided by a race. out_splice fills its pipe
 * with write(2) into a FIFO, which the BPF write hook classifies as
 * IPC/PIPE_WRITE; under an allow-OUTPUT/SPLICE policy that key is absent, so
 * the write was default-denied, the pipe stayed empty, and splice() legitimately
 * returned 0 with a residual EPERM in errno -- reported as "denied despite allow
 * policy" on 9 of 10 repeats, while repeat 0 passed because a cold interpreter
 * let the probe win the race.
 *
 * The announcing write happens before the cgroup is joined, so it is never
 * itself subject to the policy under test.
 */
#define WAIT_GO() do { \
    const char *_go_fd_str = getenv("SHADOW_GO_FD"); \
    const char *_rdy_fd_str = getenv("SHADOW_READY_FD"); \
    if (_rdy_fd_str) { \
        int _rdy_fd = atoi(_rdy_fd_str); \
        char _rdy = 'R'; \
        ssize_t _rdy_wr = write(_rdy_fd, &_rdy, 1); \
        (void)_rdy_wr;  /* harness may have stopped waiting - not fatal */ \
        close(_rdy_fd); \
    } \
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
