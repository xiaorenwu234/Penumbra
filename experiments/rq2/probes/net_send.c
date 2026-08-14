/* net_send.c - NETWORK/SEND probe: send a UDP datagram via sendto().
 * Does NOT use connect() because that triggers the socket_connect BPF hook.
 * Note: BPF reads skc_daddr/dport which are 0 for unconnected UDP,
 * so endpoint policy must use wildcard (addr=0, port=0).
 */
#include "common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 9997;
    WAIT_GO();

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        REPORT(fd);
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };
    const char *msg = "SHADOW_UDP_PROBE";
    ssize_t ret = sendto(fd, msg, strlen(msg), 0,
                         (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    close(fd);
    REPORT_ERRNO(ret, err);
}
