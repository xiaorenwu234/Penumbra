/* W2: CPU-only computation benchmark.
 * Performs LCG iterations for a target duration.
 * Usage: w2_cpu <target_ms>
 *   target_ms: target computation time in milliseconds (10, 100, 1000)
 *
 * The program calibrates on first run to determine iterations/ms,
 * then runs the target duration. No file I/O, no large output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_ms>\n", argv[0]);
        return 1;
    }
    uint64_t target_ms = (uint64_t)atoll(argv[1]);
    uint64_t target_ns = target_ms * 1000000ULL;

    volatile uint64_t value = 12345;
    uint64_t start = get_time_ns();

    /* Run LCG iterations until target duration is reached.
     * Check time every 1024 iterations to reduce clock_gettime overhead. */
    uint64_t iterations = 0;
    while (1) {
        for (int i = 0; i < 1024; i++) {
            value = value * 1664525ULL + 1013904223ULL;
            iterations++;
        }
        uint64_t now = get_time_ns();
        if (now - start >= target_ns)
            break;
    }

    /* Print minimal output to prevent dead-code elimination */
    printf("iterations=%lu checksum=%lu\n",
           (unsigned long)iterations, (unsigned long)value);
    return 0;
}
