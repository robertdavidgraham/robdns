#ifndef MURMURHASH3_H_
#define MURMURHASH3_H_
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

uint64_t murmurhash3(const void *key, size_t len, uint64_t seed);

#ifdef __cplusplus
}
#endif
#endif
