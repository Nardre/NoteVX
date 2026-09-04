#ifndef FAKESECTION_H
#define FAKESECTION_H

#include <elf.h>
#include <sys/queue.h>

struct node {
    Elf64_Off offset;
    Elf64_Addr vaddr;
    Elf64_Addr paddr;
    Elf64_Word filesz;
    STAILQ_ENTRY(node) entries;
};
STAILQ_HEAD(queue, node);

int fake_section(char *file);

#endif
