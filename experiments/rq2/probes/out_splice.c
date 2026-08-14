/* out_splice.c - OUTPUT/SPLICE probe: use splice() to move data through a pipe. */
#include "common.h"
#include <fcntl.h>

#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 1
#endif

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    /* Setup pipe with data BEFORE the go signal, so only splice is the effect */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        REPORT(-1);
    }
    write(pipefd[1], "SPLICE_DATA", 11);
    close(pipefd[1]);

    int devnull = open("/dev/null", O_WRONLY);
    if (devnull < 0) {
        close(pipefd[0]);
        REPORT(-1);
    }

    WAIT_GO();

    /* splice from pipe to /dev/null - this is the output effect */
    ssize_t ret = splice(pipefd[0], NULL, devnull, NULL, 11, SPLICE_F_MOVE);
    int err = errno;
    close(devnull);
    close(pipefd[0]);
    REPORT_ERRNO(ret, err);
}
