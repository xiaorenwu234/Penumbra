/* ipc_shm.c - IPC/SYSV_SHM probe: create and attach a SysV shared memory segment. */
#include "common.h"
#include <sys/ipc.h>
#include <sys/shm.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid < 0) {
        REPORT(shmid);
    }
    void *ptr = shmat(shmid, NULL, 0);
    int err = errno;
    if (ptr != (void *)-1) {
        memcpy(ptr, "SHM_DATA", 8);
        shmdt(ptr);
    }
    shmctl(shmid, IPC_RMID, NULL);
    REPORT_ERRNO(shmid, err);
}
