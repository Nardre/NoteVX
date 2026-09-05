#include "fakeSection.h"
#include "../debug/debug.h"

#include <elf.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

static int queue_push(struct queue *q, Elf64_Phdr *phdr, int i) {
    struct node *node = malloc(sizeof(struct node));
    if (node == NULL) {
        LOG_DEBUG("malloc failed.");
        return 1;
    }
    node->offset = phdr[i].p_offset;
    node->vaddr = phdr[i].p_vaddr;
    node->paddr = phdr[i].p_paddr;
    node->filesz = phdr[i].p_filesz;
    STAILQ_INSERT_TAIL(q, node, entries);
    return 0;
}

static void queue_free(struct queue *q) {
    struct node *c;

    while (!STAILQ_EMPTY(q)) {
        c = STAILQ_FIRST(q);
        STAILQ_REMOVE_HEAD(q, entries);
        free(c);
    }
}

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
    return 0;
}

static int get_segment(char *map, struct queue *text, size_t *text_size,
                                  struct queue *data, size_t *data_size) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(map + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        if (phdr[i].p_flags & PF_X) {
            queue_push(data, phdr, i);
            (*data_size)++;
        }
        else {
            queue_push(text, phdr, i);
            (*text_size)++;
        }

    }
    return 0;
}

static int create_section(char *map, struct queue *text, size_t text_size,
                              struct queue *data, size_t data_size) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

    if (ehdr->e_shoff == 0) {
        LOG_DEBUG("Section table not found.");
        return 1;
    }

    if (ehdr->e_shstrndx == SHN_UNDEF) {
        LOG_DEBUG("String table not found.");
        return 1;
    }


    if (ehdr->e_shnum < 3 + text_size + data_size) {
        LOG_DEBUG("Not enough sections");
        return 1;
    }

    Elf64_Shdr *shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
    Elf64_Off shstrtab_offset = shdr[ehdr->e_shstrndx].sh_offset;
    char *shstrtab = map + shstrtab_offset;
    char shstrtab_cpy[] = "\x00.init\x00.text\x00.fini\x00.data\x00.shstrtab\x00.NoteVX\x00";
    size_t shstrtab_size = sizeof(shstrtab_cpy);
    size_t i = 2;

    if (shdr[ehdr->e_shstrndx].sh_size < shstrtab_size) {
        LOG_DEBUG("String table not big enough");
        return 1;
    }

    // create_init
    for (int j = 0; j < ehdr->e_shnum; j++) {
        char *name = shstrtab + shdr[j].sh_name;
        if (strcmp(name, ".init") != 0)
            continue;
        memcpy((char *)&shdr[1], (char *)&shdr[j], sizeof(Elf64_Shdr));
        shdr[1].sh_name = 1; // .init
        shdr[1].sh_size = (ehdr->e_entry + 1) - shdr[1].sh_addr;
        LOG_DEBUG("create init: 0x%lx -> 0x%lx\n", shdr[1].sh_addr, shdr[1].sh_addr+ shdr[1].sh_size);
    }

    // create_data
    struct node *phdr;
    STAILQ_FOREACH(phdr, data, entries) {
        LOG_DEBUG("create data: 0x%lx -> 0x%lx", phdr->offset, phdr->offset + phdr->filesz);
        LOG_DEBUG("create data: 0x%lx -> 0x%lx\n", phdr->vaddr, phdr->vaddr + phdr->filesz);
        shdr[i].sh_name = 19; // .data
        shdr[i].sh_type = SHT_PROGBITS;
        shdr[i].sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr[i].sh_addr = phdr->vaddr;
        shdr[i].sh_offset = phdr->offset;
        shdr[i].sh_size = phdr->filesz;
        shdr[i].sh_link = 0;
        shdr[i].sh_info = 0;
        shdr[i].sh_addralign = 4;
        shdr[i].sh_entsize = 0;
        i++;
    }

    // create_text
    STAILQ_FOREACH(phdr, text, entries) {
        LOG_DEBUG("create text: 0x%lx -> 0x%lx", phdr->offset, phdr->offset + phdr->filesz);
        LOG_DEBUG("create text: 0x%lx -> 0x%lx\n", phdr->vaddr, phdr->vaddr+ phdr->filesz);
        shdr[i].sh_name = 7; // .text
        shdr[i].sh_type = SHT_PROGBITS;
        shdr[i].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr[i].sh_addr = phdr->vaddr;
        shdr[i].sh_offset = phdr->offset;
        shdr[i].sh_size = phdr->filesz;
        shdr[i].sh_link = 0;
        shdr[i].sh_info = 0;
        shdr[i].sh_addralign = 4;
        shdr[i].sh_entsize = 0;
        i++;
    }

    // create_shstrtab
    memset(shstrtab, 0, shdr[ehdr->e_shstrndx].sh_size);
    memcpy(shstrtab, shstrtab_cpy, shstrtab_size);
    ehdr->e_shstrndx = i;

    shdr[i].sh_name = 25;
    shdr[i].sh_type = SHT_STRTAB;
    shdr[i].sh_flags = 0;
    shdr[i].sh_addr = 0;
    shdr[i].sh_offset = shstrtab_offset;
    shdr[i].sh_size = shstrtab_size;
    shdr[i].sh_link = 0;
    shdr[i].sh_info = 0;
    shdr[i].sh_addralign = 4;
    shdr[i].sh_entsize = 0;

    ehdr->e_shnum = 3 + text_size + data_size; // NULL + shstrtab + init + text + data

    return 0;
}

static int poison_header(char *map) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    ehdr->e_version = 0x1444;
    unsigned char *ident = ehdr->e_ident;
    ident[EI_DATA] = ELFDATA2MSB;
    ident[EI_VERSION] = 0x38;
    return 0;
}

int fakeSection(char *filename) {
    int ret = 0;
    int fd = -1;
    char *map = NULL;
    struct stat *st = malloc(sizeof(struct stat));
    struct queue *text = malloc(sizeof(struct queue));;
    struct queue *data = malloc(sizeof(struct queue));;
    size_t text_size = 0;
    size_t data_size = 0;
    STAILQ_INIT(text);
    STAILQ_INIT(data);

    if (!st || !text || !data) {
        LOG_DEBUG("malloc failed.");
        ret = 1;
        goto Error;
    }

    LOG_DEBUG("open_and_map_elf: executing on %s.", filename);
    if (open_and_map(filename, &fd, st, &map) != 0) {
        LOG_DEBUG("open_and_map_elf failed.");
        ret = 1;
        goto Error;
    }

    LOG_DEBUG("get_segment: parsing PT_LOAD segments.");
    if (get_segment(map, text, &text_size, data, &data_size) != 0) {
        LOG_DEBUG("get_segment failed.");
        ret = 1;
        goto Error;
    }

    LOG_DEBUG("create_section: poisoning sections.");
    if (create_section(map, text, text_size, data, data_size)) {
        LOG_DEBUG("create_section failed.");
        ret = 1;
        goto Error;
    }

    LOG_DEBUG("poison_header: poisoning header.");
    if (poison_header(map)) {
        LOG_DEBUG("poison_header failed.");
        ret = 1;
        goto Error;
    }

    if (fsync(fd) == -1)
        LOG_PERROR("fsync warning (non-critical)");

Error:
    queue_free(text);
    queue_free(data);
    free(text);
    free(data);
    close(fd);
    if (map != MAP_FAILED && map != NULL)
        munmap(map, st->st_size);
    free(st);
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("usage: %s {elf}", argv[0]);
        return 1;
    }
    fakeSection(argv[1]);
    return 0;
}
