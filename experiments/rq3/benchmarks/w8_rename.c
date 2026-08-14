/* W8: Rename operations benchmark.
 * Renames N files from old-i to new-i.
 * Usage: w8_rename <dir_path> <count>
 *   dir_path: directory containing files named old-0000.bin ... old-N.bin
 *   count: number of rename operations
 *
 * Each rename involves source and destination paths, testing
 * namespace versioning and parent-directory handling.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dir_path> <count>\n", argv[0]);
        return 1;
    }
    const char *dir = argv[1];
    int count = atoi(argv[2]);

    char old_path[4096], new_path[4096];
    int renamed = 0;

    for (int i = 0; i < count; i++) {
        snprintf(old_path, sizeof(old_path), "%s/old-%04d.bin", dir, i);
        snprintf(new_path, sizeof(new_path), "%s/new-%04d.bin", dir, i);
        if (rename(old_path, new_path) < 0) {
            perror("rename");
            return 1;
        }
        renamed++;
    }

    printf("renamed=%d\n", renamed);
    return 0;
}
