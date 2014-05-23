#ifndef PIXIE_ATOMIC_H
#define PIXIE_ATOMIC_H

#if defined(_MSC_VER)
#include <intrin.h>
#define __sync_fetch_and_add(p,n) _InterlockedExchangeAdd(p, n)
#define __sync_fetch_and_sub(p,n) _InterlockedExchangeAdd(p, -(n))
#endif

#endif
