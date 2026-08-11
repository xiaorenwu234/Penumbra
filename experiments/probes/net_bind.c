/* net_bind.c - NETWORK/BIND probe: bind + listen on a TCP port. */
#include "common.h"
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 9998;
    WAIT_GO();

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        REPORT(fd);
    }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    if (ret == 0) {
        ret = listen(fd, 1);
        err = errno;
    }
    close(fd);
    REPORT_ERRNO(ret, err);
}
