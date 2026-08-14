/* sys_tty_ioctl.c - SYSTEM/TTY_IOCTL probe: ioctl on /dev/null (safe TIOCSTI test). */
#include "common.h"
#include <sys/ioctl.h>
#include <termios.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Open /dev/null and try TCGETS - will fail with ENOTTY but exercises hook */
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0) {
        REPORT(fd);
    }
    struct termios tio;
    int ret = ioctl(fd, TCGETS, &tio);
    int err = errno;
    close(fd);
    REPORT_ERRNO(ret, err);
}
