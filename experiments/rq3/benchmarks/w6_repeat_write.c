/* W6: Repeated writes to the same file benchmark.
 * Writes N times to the same file at different offsets.
 * Usage: w6_repeat_write <file_path> <count> [write_size]
 *   file_path: path to an existing file (should be large enough)
 *   count: number of 4-KiB writes to perform
 *   write_size: size of each write in bytes (default: 4096)
 *
 * Verifies that repeated writes reuse the epoch-owned head:
 * first write does copy-up, subsequent writes should be cheaper.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <file_path> <count> [write_size]\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    int count = atoi(argv[2]);
    uint64_t write_size = (argc >= 4) ? (uint64_t)atoll(argv[3]) : 4096;

    /* Get file size for offset wrapping */
    struct stat st;
    if (stat(path, &st) < 0) {
        perror("stat");
        return 1;
    }
    uint64_t file_size = (uint64_t)st.st_size;
    if (file_size == 0) {
        fprintf(stderr, "file is empty\n");
        return 1;
    }

    uint8_t *buf = malloc(write_size);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("open");
        free(buf);
        return 1;
    }

    uint64_t total_written = 0;
    for (int i = 0; i < count; i++) {
        /* Fill buffer with iteration-dependent pattern to avoid caching */
        for (uint64_t j = 0; j < write_size; j++)
            buf[j] = (uint8_t)(i * 3 + j * 7 + 1);

        /* Use different offsets, wrapping around the file */
        uint64_t offset = ((uint64_t)i * write_size) % file_size;
        /* Align to write_size boundary */
        offset = (offset / write_size) * write_size;
        if (offset + write_size > file_size)
            offset = 0;

        ssize_t n = pwrite(fd, buf, write_size, offset);
        if (n < 0) {
            perror("pwrite");
            close(fd);
            free(buf);
            return 1;
        }
        total_written += (uint64_t)n;
    }

    close(fd);
    printf("writes=%d total_bytes=%lu\n", count, (unsigned long)total_written);
    free(buf);
    return 0;
}
