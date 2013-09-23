#ifndef SIPHASH_H
#define SIPHASH_H 1
#include <stdint.h>

int siphash( unsigned char out[8], const unsigned char *in, unsigned long long inlen, const unsigned char k[16] );
uint64_t siphash_x(const unsigned char *in, unsigned long long inlen, uint64_t key1, uint64_t key2);

#endif
