/* W7: Multi-file creation benchmark.
 * Creates N new files, each with a fixed write size (4 KiB).
 * Usage: w7_multifile <dir_path> <count> [write_size]
 *   dir_path: directory to create files in
 *   count: number of files to create
 *   write_size: bytes per file (default: 4096)
 *
 * Files are named file-0000.bin, file-0001.bin, ...
 * Measures finalization scaling with dirty object count.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dir_path> <count> [write_size]\n", argv[0]);
        return 1;
    }
    const char *dir = argv[1];
    int count = atoi(argv[2]);
    uint64_t write_size = (argc >= 4) ? (uint64_t)atoll(argv[3]) : 4096;

    uint8_t *buf = malloc(write_size);
    if (!buf) {
        perror("malloc");
        return 1;
    }
    for (uint64_t i = 0; i < write_size; i++)
        buf[i] = (uint8_t)(i * 5 + 3);

    char path[4096];
    int created = 0;

    for (int i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/file-%04d.bin", dir, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            perror("open");
            free(buf);
            return 1;
        }
        uint64_t written = 0;
        while (written < write_size) {
            ssize_t n = write(fd, buf + written, write_size - written);
            if (n < 0) {
                perror("write");
                close(fd);
                free(buf);
                return 1;
            }
            written += (uint64_t)n;
        }
        close(fd);
        created++;
    }

    printf("created=%d write_size=%lu\n", created, (unsigned long)write_size);
    free(buf);
    return 0;
}
