/* W10: Session-resident memory payload for the overlayfs+CRIU baseline.
 *
 * Replaces `sleep infinity` as the checkpointed session process: allocate
 * `bytes` of anonymous memory, touch every page (forces RSS = payload),
 * then park forever. CRIU dump must write every byte to image files and
 * restore must read them back — the CRIU-unfriendly scenario Penumbra's
 * COW fork sidesteps (fork shares the pages; nothing is copied while they
 * stay clean).
 *
 * The Penumbra side parks the same payload in its session bash instead
 * (see harness.session_mem_setup_command); both engines snapshot a process
 * carrying ~N bytes of dirty anonymous memory, so only the snapshot
 * mechanism differs.
 *
 * Usage: w10_memhold <bytes>
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bytes>\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    unsigned long long bytes = strtoull(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || bytes == 0) {
        fprintf(stderr, "bad size: %s\n", argv[1]);
        return 2;
    }
    volatile char *mem = malloc((size_t)bytes);
    if (!mem) {
        perror("malloc");
        return 1;
    }
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0)
        page = 4096;
    /* Pre-fault every page: RSS (what CRIU dumps) must equal the payload. */
    for (unsigned long long i = 0; i < bytes; i += (unsigned long long)page)
        mem[i] = 0x41;
    /* Park until the engine SIGKILLs us (CRIU freezes us via ptrace). */
    for (;;)
        pause();
    return 0;
}
