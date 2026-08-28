#ifndef REPLICATION_H
#define REPLICATION_H

#include <stddef.h>

int replication(unsigned char **payload_bin, size_t *payload_size,
                unsigned char *stub_bin, size_t stub_bin_size);

#endif

