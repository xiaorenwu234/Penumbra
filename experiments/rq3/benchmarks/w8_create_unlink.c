/* W8-a: Create/unlink operations benchmark.
 * Creates N files then unlinks them all.
 * Usage: w8_create_unlink <dir_path> <count>
 *   dir_path: directory to create files in
 *   count: number of files to create and unlink
 *
 * Tests whiteout creation and parent-directory handling.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dir_path> <count>\n", argv[0]);
        return 1;
    }
    const char *dir = argv[1];
    int count = atoi(argv[2]);

    char path[4096];
    uint8_t buf[64] = {0};

    /* Phase 1: Create files */
    for (int i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/tmp-%04d.bin", dir, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            perror("open");
            return 1;
        }
        if (write(fd, buf, sizeof(buf)) < 0) {
            perror("write");
            close(fd);
            return 1;
        }
        close(fd);
    }

    /* Phase 2: Unlink files */
    int unlinked = 0;
    for (int i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/tmp-%04d.bin", dir, i);
        if (unlink(path) < 0) {
            perror("unlink");
            return 1;
        }
        unlinked++;
    }

    printf("created=%d unlinked=%d\n", count, unlinked);
    return 0;
}
