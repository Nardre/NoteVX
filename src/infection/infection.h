#ifndef INFECTION_H
#define INFECTION_H

#include <stdint.h>
#include <stddef.h>

int infect_ptnote(char *file, unsigned char payload[], size_t payload_size);

#endif
