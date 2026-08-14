/* W5: Overwrite existing file benchmark (copy-up cost).
 * Overwrites a fixed region of an existing file.
 * Usage: w5_overwrite <file_path> <offset> <size>
 *   file_path: path to an existing file
 *   offset: byte offset to start writing
 *   size: number of bytes to write (typically 4096)
 *
 * The actual write size is fixed (4 KiB by default); only the original
 * file size varies. This answers: does first-write cost grow with the
 * modification size or with the copy-up object size?
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <file_path> <offset> <size>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    uint64_t offset = (uint64_t)atoll(argv[2]);
    uint64_t size = (uint64_t)atoll(argv[3]);

    uint8_t *buf = malloc(size);
    if (!buf) {
        perror("malloc");
        return 1;
    }
    /* Fill with a distinct pattern */
    for (uint64_t i = 0; i < size; i++)
        buf[i] = (uint8_t)(i * 11 + 37);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("open");
        free(buf);
        return 1;
    }

    ssize_t n = pwrite(fd, buf, size, offset);
    if (n < 0) {
        perror("pwrite");
        close(fd);
        free(buf);
        return 1;
    }

    close(fd);
    printf("written=%ld offset=%lu\n", (long)n, (unsigned long)offset);
    free(buf);
    return 0;
}
