/* W4: New file creation and write benchmark.
 * Creates a new file and writes a specified amount of data.
 * Usage: w4_write_new <file_path> <size_bytes>
 *   file_path: path for the new file (must not exist)
 *   size_bytes: total bytes to write
 *
 * Measures ShadowFS staging write, new-version metadata, and
 * commit/rollback cost for new files (no copy-up).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define BUF_SIZE (1024 * 1024)  /* 1 MiB write buffer */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <file_path> <size_bytes>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    uint64_t total = (uint64_t)atoll(argv[2]);

    uint8_t *buf = malloc(BUF_SIZE);
    if (!buf) {
        perror("malloc");
        return 1;
    }
    /* Fill with a pattern (not all zeros, to avoid compression effects) */
    for (int i = 0; i < BUF_SIZE; i++)
        buf[i] = (uint8_t)(i * 7 + 13);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        free(buf);
        return 1;
    }

    uint64_t written = 0;
    while (written < total) {
        uint64_t chunk = total - written;
        if (chunk > BUF_SIZE) chunk = BUF_SIZE;
        ssize_t n = write(fd, buf, chunk);
        if (n < 0) {
            perror("write");
            close(fd);
            free(buf);
            return 1;
        }
        written += (uint64_t)n;
    }

    close(fd);
    printf("written=%lu\n", (unsigned long)written);
    free(buf);
    return 0;
}
