#ifndef UTIL_REALLOC2_H
#define UTIL_REALLOC2_H
#include <stdlib.h>

void *
REALLOC2(void *buf, size_t size, size_t count);

char *
STRDUP2(const char *str);

#define MALLOC2(size) REALLOC2(0, 1, (size))

#endif