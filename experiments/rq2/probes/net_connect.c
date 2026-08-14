/* net_connect.c - NETWORK/CONNECT probe: TCP connect to 127.0.0.1:port. */
#include "common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 9999;
    WAIT_GO();

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        REPORT(fd);
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };
    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    close(fd);
    REPORT_ERRNO(ret, err);
}
