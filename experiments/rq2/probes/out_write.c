/* out_write.c - OUTPUT/WRITE_OUT probe: write to stdout (fd 1). */
#include "common.h"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Write a marker to stdout - this IS the output effect */
    const char *msg = "SHADOW_OUTPUT_EFFECT\n";
    ssize_t ret = write(STDOUT_FILENO, msg, strlen(msg));
    int err = errno;
    /* Also print the canonical result line to stderr so the harness can parse it */
    fprintf(stderr, "ret=%zd errno=%d\n", ret, err);
    fflush(stderr);
    _exit(ret > 0 ? 0 : (err ? err : 1));
}
