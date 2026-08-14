/* W9: Process memory modification benchmark (long-running worker).
 * A persistent worker that allocates memory and modifies pages on command.
 * Usage: w9_mem_worker <working_set_mib>
 *   working_set_mib: total memory to allocate in MiB (64, 256, 1024)
 *
 * Protocol (stdin commands, one per line):
 *   modify <dirty_percent>   - modify dirty_percent% of pages, print checksum
 *   status                   - print current RSS info from /proc/self/statm
 *   quit                     - exit
 *
 * The worker pre-faults all pages at startup (touch every page), then
 * waits for commands. On "modify P", it writes to P% of pages (spread
 * uniformly) and returns a checksum.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void print_mem_info(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    if (f) {
        long size, resident, shared, text, lib, data, dt;
        if (fscanf(f, "%ld %ld %ld %ld %ld %ld %ld",
                   &size, &resident, &shared, &text, &lib, &data, &dt) == 7) {
            long page_size = sysconf(_SC_PAGESIZE);
            printf("rss_bytes=%ld private_bytes=%ld\n",
                   resident * page_size, data * page_size);
        }
        fclose(f);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <working_set_mib>\n", argv[0]);
        return 1;
    }
    uint64_t ws_mib = (uint64_t)atoll(argv[1]);
    uint64_t ws_bytes = ws_mib * 1024 * 1024;
    uint64_t page_size = (uint64_t)sysconf(_SC_PAGESIZE);
    uint64_t n_pages = ws_bytes / page_size;

    /* Allocate and pre-fault all pages */
    volatile uint8_t *mem = (volatile uint8_t *)malloc(ws_bytes);
    if (!mem) {
        perror("malloc");
        return 1;
    }
    /* Touch every page to ensure physical allocation */
    for (uint64_t i = 0; i < ws_bytes; i += page_size)
        mem[i] = (uint8_t)(i & 0xFF);

    printf("ready ws_mib=%lu n_pages=%lu\n", 
           (unsigned long)ws_mib, (unsigned long)n_pages);
    fflush(stdout);

    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        /* Strip newline */
        line[strcspn(line, "\n")] = '\0';

        if (strncmp(line, "modify ", 7) == 0) {
            int dirty_pct = atoi(line + 7);
            if (dirty_pct < 0) dirty_pct = 0;
            if (dirty_pct > 100) dirty_pct = 100;

            uint64_t dirty_pages = (n_pages * (uint64_t)dirty_pct) / 100;
            /* Spread modifications uniformly across the address space */
            uint64_t step = (dirty_pages > 0) ? (n_pages / dirty_pages) : n_pages;
            if (step == 0) step = 1;

            volatile uint64_t checksum = 0;
            uint64_t modified = 0;
            uint64_t t0 = get_time_ns();

            for (uint64_t p = 0; p < n_pages && modified < dirty_pages;
                 p += step) {
                uint64_t idx = p * page_size;
                /* Write a pattern to the first 8 bytes of the page */
                *(volatile uint64_t *)(mem + idx) =
                    (uint64_t)(modified * 2654435761ULL + 1);
                checksum += *(volatile uint64_t *)(mem + idx);
                modified++;
            }

            uint64_t elapsed = get_time_ns() - t0;
            printf("modified_pages=%lu dirty_pct=%d elapsed_ns=%lu checksum=%lu\n",
                   (unsigned long)modified, dirty_pct,
                   (unsigned long)elapsed, (unsigned long)checksum);
            fflush(stdout);

        } else if (strncmp(line, "status", 6) == 0) {
            print_mem_info();
            fflush(stdout);

        } else if (strncmp(line, "quit", 4) == 0) {
            break;
        }
    }

    free((void *)mem);
    return 0;
}
