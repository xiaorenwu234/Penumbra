/* ipc_sem.c - IPC/SYSV_SEM probe: create a SysV semaphore and perform semop. */
#include "common.h"
#include <sys/ipc.h>
#include <sys/sem.h>

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (semid < 0) {
        REPORT(semid);
    }
    union semun arg = { .val = 1 };
    semctl(semid, 0, SETVAL, arg);

    struct sembuf op = { .sem_num = 0, .sem_op = -1, .sem_flg = IPC_NOWAIT };
    int ret = semop(semid, &op, 1);
    int err = errno;
    semctl(semid, 0, IPC_RMID);
    REPORT_ERRNO(ret, err);
}
