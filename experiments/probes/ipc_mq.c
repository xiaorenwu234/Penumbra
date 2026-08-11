/* ipc_mq.c - IPC/POSIX_MQ probe: create a POSIX message queue and send a message. */
#include "common.h"
#include <mqueue.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MQ_NAME "/shadow-probe-mq"

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    struct mq_attr attr = {
        .mq_maxmsg = 10,
        .mq_msgsize = 64,
    };
    mqd_t mq = mq_open(MQ_NAME, O_CREAT | O_WRONLY, 0644, &attr);
    if (mq == (mqd_t)-1) {
        REPORT(-1);
    }
    int ret = mq_send(mq, "MQ_DATA", 7, 0);
    int err = errno;
    mq_close(mq);
    mq_unlink(MQ_NAME);
    REPORT_ERRNO(ret, err);
}
