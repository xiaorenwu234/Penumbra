/*
 * mem_modifier.c - Test program for COW memory rollback demo.
 *
 * Usage: ./mem_modifier <marker_file>
 *
 * Flow:
 *   Phase 1: Write a marker file with the address of global variables
 *            (for external verification), then trigger stdout write
 *            to get frozen by ShadowProc (allows orchestrator to call
 *            begin_speculative before the program modifies memory).
 *
 *   Phase 2: After being resumed, modify global variables in memory.
 *
 *   Phase 3: Trigger IPC (connect) to get frozen again by ShadowProc.
 *            At this point, external tools can verify the modified state,
 *            then commit_pid (accept) or reject_pid (discard) the change.
 *
 *   Phase 4: After being resumed (continue_pid), run to completion and
 *            append a completion record (completed=1, final_counter,
 *            final_message) to the marker file, proving the process
 *            continued past the freeze and finished the rest of its run.
 *
 * The global variables serve as verifiable targets:
 *   - g_counter: integer, initial=42, modified=9999
 *   - g_message: string, initial="ORIGINAL", modified="MODIFIED_BY_SPECULATIVE"
 *
 * External verification reads /proc/<pid>/mem at the recorded addresses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---- Global state: COW rollback targets ---- */
volatile int g_counter = 42;
volatile char g_message[64] = "ORIGINAL";

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <marker_file>\n", argv[0]);
        return 1;
    }

    /* ---- Phase 1: Write marker file with variable addresses ---- */
    /* This file lets external tools know WHERE to look in /proc/pid/mem */
    int mfd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (mfd < 0) {
        perror("open marker");
        return 1;
    }

    char info[512];
    int len = snprintf(info, sizeof(info),
        "pid=%d\n"
        "counter_addr=0x%lx\n"
        "counter_size=4\n"
        "counter_initial=42\n"
        "message_addr=0x%lx\n"
        "message_size=64\n"
        "message_initial=ORIGINAL\n",
        getpid(),
        (unsigned long)&g_counter,
        (unsigned long)g_message);
    write(mfd, info, len);
    close(mfd);

    /* ---- Trigger first freeze: connect() to a non-local address ---- */
    /* ShadowProc no longer intercepts write() to stdout/stderr; the
     * process is frozen at network IPC instead. The orchestrator should
     * call begin_speculative at this point, then resume us with resume_pid. */
    {
        int sock0 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sock0 >= 0) {
            struct sockaddr_in addr0;
            memset(&addr0, 0, sizeof(addr0));
            addr0.sin_family = AF_INET;
            addr0.sin_port = htons(12345);
            inet_pton(AF_INET, "192.0.2.2", &addr0.sin_addr);
            connect(sock0, (struct sockaddr *)&addr0, sizeof(addr0));
            close(sock0);
        }
    }

    /* If we reach here, the orchestrator has resumed us */

    /* ---- Phase 2: Modify memory (speculative execution) ---- */
    g_counter = 9999;
    strcpy((char *)g_message, "MODIFIED_BY_SPECULATIVE");

    /* Update marker file with modified values (for reference) */
    mfd = open(argv[1], O_WRONLY | O_APPEND);
    if (mfd >= 0) {
        len = snprintf(info, sizeof(info),
            "counter_modified=9999\n"
            "message_modified=MODIFIED_BY_SPECULATIVE\n");
        write(mfd, info, len);
        close(mfd);
    }

    /* ---- Phase 3: Trigger IPC (get frozen again) ---- */
    usleep(200000); /* 200ms delay */

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        perror("socket");
        return 3;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    inet_pton(AF_INET, "192.0.2.1", &addr.sin_addr);

    /* This connect() triggers ShadowProc's LSM socket_connect hook.
     * Process is frozen again. External tools can now:
     *   1. Read /proc/pid/mem to verify g_counter==9999
     *   2. Decide: commit_pid (accept) or reject_pid (discard speculative)
     *   3. Resume us (continue_pid) to run the rest to completion
     */
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);

    /* ---- Phase 4: Post-resume completion ---- */
    /* Reaching here means ShadowProc released the second freeze (after a
     * commit/continue) and we CONTINUED running past it. Append a completion
     * record so external tools can confirm the process finished the rest of
     * its run AND that the committed memory values are visible to this
     * continued execution (final_counter should be the committed 9999). */
    mfd = open(argv[1], O_WRONLY | O_APPEND);
    if (mfd >= 0) {
        len = snprintf(info, sizeof(info),
            "completed=1\n"
            "final_counter=%d\n"
            "final_message=%s\n",
            g_counter, (char *)g_message);
        write(mfd, info, len);
        close(mfd);
    }

    return 0;
}
