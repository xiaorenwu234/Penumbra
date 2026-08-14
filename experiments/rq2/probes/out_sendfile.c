/* out_sendfile.c - OUTPUT/SENDFILE probe: use sendfile() to transfer data. */
#include "common.h"
#include <sys/sendfile.h>

int main(int argc, char **argv)
{
    const char *path = probe_target_path(argc, argv, "/tmp/shadow-probe-sendfile.txt");

    /* Create source file with data BEFORE go signal */
    int src = open(path, O_RDWR | O_CREAT, 0644);
    if (src < 0) {
        REPORT(src);
    }
    if (lseek(src, 0, SEEK_END) == 0) {
        write(src, "SENDFILE_DATA", 13);
    }
    lseek(src, 0, SEEK_SET);

    int pipefd[2];
    pipe(pipefd);

    WAIT_GO();

    /* sendfile is the output effect */
    off_t offset = 0;
    ssize_t ret = sendfile(pipefd[1], src, &offset, 13);
    int err = errno;
    close(pipefd[0]);
    close(pipefd[1]);
    close(src);
    REPORT_ERRNO(ret, err);
}
