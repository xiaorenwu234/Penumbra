/* ipc_msg.c - IPC/SYSV_MSG probe: create a SysV message queue and send a message. */
#include "common.h"
#include <sys/ipc.h>
#include <sys/msg.h>

struct msg_buf {
    long mtype;
    char mtext[32];
};

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msqid < 0) {
        REPORT(msqid);
    }
    struct msg_buf msg = { .mtype = 1 };
    strcpy(msg.mtext, "MSG_DATA");
    int ret = msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
    int err = errno;
    msgctl(msqid, IPC_RMID, NULL);
    REPORT_ERRNO(ret, err);
}
