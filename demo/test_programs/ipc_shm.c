/*
 * ipc_shm.c - Attempts to open a SysV shared-memory IPC channel (shmat).
 *
 * Usage: ./ipc_shm
 *
 * A speculative agent that tries to establish a shared-memory segment — a
 * classic covert / side channel. ShadowProc's lsm/shm_shmat hook intercepts the
 * shmat() call (EVENT_IPC) and freezes the process BEFORE the channel is usable,
 * so a reviewer can decide to reject (kill) it.
 *
 * Flow:
 *   1. shmget(IPC_PRIVATE, ...) to create a segment (allowed — no channel yet).
 *   2. shmat(...) to attach it → intercepted by ShadowProc → process frozen.
 *   3. If ever resumed, detach + remove the segment and exit.
 *
 * Exit codes:
 *   0 - attached (process was resumed by orchestrator)
 *   2 - shmget failed
 *   3 - shmat failed / was intercepted (expected while frozen)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main(void) {
    /* Create a private shared-memory segment (this alone is not a channel). */
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (shmid < 0) {
        perror("shmget");
        return 2;
    }

    usleep(200000);  /* 200ms, let the driver script observe state */

    /* Attaching is what turns it into a usable IPC channel — ShadowProc's
     * lsm/shm_shmat hook intercepts this and SIGSTOPs us here. */
    void *addr = shmat(shmid, NULL, 0);
    if (addr == (void *)-1) {
        perror("shmat");
        shmctl(shmid, IPC_RMID, NULL);
        return 3;
    }

    /* Only reached if resumed: clean up and exit. */
    shmdt(addr);
    shmctl(shmid, IPC_RMID, NULL);
    return 0;
}
