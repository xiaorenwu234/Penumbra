/* ipc_shm.c - IPC/SYSV_SHM probe: shmget only (single syscall).
 * Avoids shmat/shmctl multi-syscall interaction issues.
 */
#include "common.h"
#include <sys/ipc.h>
#include <sys/shm.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    WAIT_GO();

    /* Single syscall: shmget creates the segment */
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    int err = errno;
    /* Clean up if successful */
    if (shmid >= 0) {
        shmctl(shmid, IPC_RMID, NULL);
    }
    REPORT_ERRNO(shmid, err);
}
