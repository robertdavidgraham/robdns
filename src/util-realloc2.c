#include "util-realloc2.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HALF    (1UL << (sizeof(size_t) * 4))

void *
REALLOC2(void *buf, size_t size, size_t count)
{
    void *buf2;

    if (size == 0 || count == 0) {
        free(buf);
        return NULL;
    }

    /* Check for overflow. First, check if both integers are small, which is 
     * cheap on CPUs. Second, if a potential overflow exists, the check
     * using integer-division, which is expensive on CPUs. The expensive operation
     * will happen for allocations larger than 64k on 32bit processors,
     * and allocations larger than 4-gigabytes on 64bit processors */
    if (size >= HALF || count >= HALF) {
        if (count > SIZE_MAX / size)
            exit(1);
    }

    if (buf == NULL)
        buf2 = malloc(size * count);
    else
        buf2 = realloc(buf, size * count);

    if (buf2 == NULL)
        exit(1);

    return buf2;
}


char *
STRDUP2(const char *str)
{
    char *result;
    size_t len = strlen(str) + 1;

    result = MALLOC2(len);
    memcpy(result, str, len);
    
    return result;
}
