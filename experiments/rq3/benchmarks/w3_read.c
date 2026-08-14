/* W3: Sequential file read benchmark.
 * Reads a file completely and computes a checksum.
 * Usage: w3_read <file_path> [repeat_count]
 *   file_path: path to the input file
 *   repeat_count: number of times to read the file (default: 1)
 *
 * Measures ShadowFS read path and dependency recording cost.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define BUF_SIZE (1024 * 1024)  /* 1 MiB read buffer */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_path> [repeat_count]\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    int repeat = (argc >= 3) ? atoi(argv[2]) : 1;
    if (repeat < 1) repeat = 1;

    uint8_t *buf = malloc(BUF_SIZE);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    volatile uint64_t checksum = 0;
    uint64_t total_bytes = 0;

    for (int r = 0; r < repeat; r++) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            perror("open");
            free(buf);
            return 1;
        }
        ssize_t n;
        while ((n = read(fd, buf, BUF_SIZE)) > 0) {
            /* Simple checksum: sum of first 8 bytes of each chunk */
            for (ssize_t i = 0; i + 8 <= n; i += 64) {
                checksum += *(uint64_t *)(buf + i);
            }
            total_bytes += (uint64_t)n;
        }
        close(fd);
    }

    printf("bytes=%lu checksum=%lu repeats=%d\n",
           (unsigned long)total_bytes, (unsigned long)checksum, repeat);
    free(buf);
    return 0;
}
