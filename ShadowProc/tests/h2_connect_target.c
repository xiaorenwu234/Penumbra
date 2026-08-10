// h2_connect_target.c - LSM-boundary target for ShadowProc reject verification.
//
// Complements h2_target.c (a read() boundary) by exercising an LSM-intercepted
// boundary: connect(). ShadowProc's socket_connect LSM hook holds every
// connect() with -ERESTARTSYS + SIGSTOP, so each connect() is a clean epoch
// boundary.
//
// This target is used to verify that a pristine BASELINE frozen at an
// LSM-intercepted connect() boundary is restored COHERENTLY on REJECT: after
// the candidate is discarded and the baseline resumed, the baseline must
// re-execute connect() and observe ECONNREFUSED (111) from the dead loopback
// port, WITHOUT crashing and WITHOUT leaking ERESTARTSYS (errno 512) to
// userspace.
//
//   H2C pid=<pid> status=OK connect_ret=<r> errno=<e>   <- connect restarted OK
//   H2C pid=<pid> status=FAIL ...                       <- setup failure
//
// Build: gcc -o tests/h2_connect_target tests/h2_connect_target.c -Wall

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void)
{
    // Gate on one stdin line so the driver can place us in the monitored cgroup
    // BEFORE our first connect() (otherwise we would race the cgroup add and the
    // first connect() might slip through un-monitored). read() is not an
    // intercepted syscall, so this blocks harmlessly until the driver writes.
    char gate[64];
    if (read(0, gate, sizeof(gate)) <= 0)
        return 0;

    dprintf(2, "[h2_connect_target] pid=%d ready; looping connect() at boundary\n",
            getpid());

    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            dprintf(1, "H2C pid=%d status=FAIL socket errno=%d (%s)\n",
                    getpid(), errno, strerror(errno));
            return 1;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(9999);                 /* nothing listens here */
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        /* ===================== EPOCH BOUNDARY ===================== */
        int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        int e = errno;
        /* ========================================================== */

        /* Reached only after the LSM hook lets the restarted connect() through.
         * connect_ret is -1 with errno ECONNREFUSED (111) for the dead port; a
         * botched restart would instead crash us or surface errno 512
         * (ERESTARTSYS leaked to userspace). */
        dprintf(1, "H2C pid=%d status=OK connect_ret=%d errno=%d\n",
                getpid(), r, e);

        close(fd);
        usleep(200000);   /* pace the loop so the next boundary is distinct */
    }
}
