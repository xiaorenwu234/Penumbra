/* W9: Tool output generation benchmark.
 * Writes a fixed amount of data to stdout.
 * Usage: w10_output <total_bytes> [chunk_size]
 *   total_bytes: total bytes to write to stdout
 *   chunk_size: size of each write() call (default: total_bytes)
 *
 * W9-a: single large output (chunk_size = total_bytes)
 * W9-b: multiple small outputs (chunk_size < total_bytes)
 *
 * (The binary keeps its historical "w10_output" name — the workload was
 * renumbered W10 → W9 when the session-resident-memory workload took the
 * W10 slot; renaming the file would break benchmark-path continuity with
 * previously collected results.)
 *
 * Measures optimistic result transcript tagging, delivery, and
 * canonicalization/removal cost.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define MAX_BUF (1024 * 1024)

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <total_bytes> [chunk_size]\n", argv[0]);
        return 1;
    }
    uint64_t total = (uint64_t)atoll(argv[1]);
    uint64_t chunk = (argc >= 3) ? (uint64_t)atoll(argv[2]) : total;
    if (chunk == 0) chunk = total;
    if (chunk > MAX_BUF) chunk = MAX_BUF;

    uint8_t *buf = malloc(chunk);
    if (!buf) {
        perror("malloc");
        return 1;
    }
    /* Fill with printable-ish pattern */
    for (uint64_t i = 0; i < chunk; i++)
        buf[i] = (uint8_t)('A' + (i % 26));

    uint64_t written = 0;
    int writes = 0;
    while (written < total) {
        uint64_t n = total - written;
        if (n > chunk) n = chunk;
        ssize_t w = write(STDOUT_FILENO, buf, n);
        if (w < 0) {
            perror("write");
            free(buf);
            return 1;
        }
        written += (uint64_t)w;
        writes++;
    }

    /* Print metadata to stderr (doesn't count as "output") */
    fprintf(stderr, "total=%lu writes=%d\n", (unsigned long)written, writes);
    free(buf);
    return 0;
}
