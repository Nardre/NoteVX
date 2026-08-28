#ifndef PROTECTION_H
#define PROTECTION_H

/* https://github.com/B-Con/crypto-algorithms/blob/master/sha256.h */
#include <stddef.h>

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;

int protection(void);

#endif
