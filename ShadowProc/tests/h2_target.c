// h2_target.c - Boundary target for ShadowProc syscall-restart verification.
//
// Verifies that BOTH sides of a speculative epoch correctly RESTART the
// interrupted boundary syscall when resumed:
//   - the speculative CANDIDATE (fresh clone, re-enters via ret_from_fork), and
//   - the pristine BASELINE (resumed from a job-control stop on REJECT).
//
// The program loops reading lines from stdin. Each read() is a potential epoch
// boundary. Every line it manages to read is echoed with the READER's pid, so
// the driver can attribute output to the candidate or the baseline:
//
//   H2_RESULT pid=<pid> status=OK   read_ret=<n> data=[<line>]   <- restart worked
//   H2_RESULT pid=<pid> status=FAIL read_ret=-...                <- restart broken
//                                                                   (ERESTARTSYS -512
//                                                                    leaked to userspace)
//
// Build: gcc -o tests/h2_target tests/h2_target.c -Wall

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(void)
{
    char buf[256];

    dprintf(2, "[h2_target] pid=%d ready; looping in read(stdin) at boundary\n",
            getpid());

    for (;;) {
        /* ===================== EPOCH BOUNDARY ===================== */
        ssize_t n = read(0, buf, sizeof(buf) - 1);
        int e = errno;
        /* ========================================================== */

        if (n < 0) {
            dprintf(1, "H2_RESULT pid=%d status=FAIL read_ret=%zd errno=%d (%s)\n",
                    getpid(), n, e, strerror(e));
            return 1;
        }
        if (n == 0) {              /* writer closed: EOF */
            dprintf(1, "H2_RESULT pid=%d status=EOF\n", getpid());
            return 0;
        }

        buf[n] = '\0';
        if (buf[n - 1] == '\n')
            buf[n - 1] = '\0';

        dprintf(1, "H2_RESULT pid=%d status=OK read_ret=%zd data=[%s]\n",
                getpid(), n, buf);

        if (strcmp(buf, "quit") == 0)
            return 0;
    }
}
