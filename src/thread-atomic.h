#ifndef THREAD_ATOMIC_H
#define THREAD_ATOMIC_H

#if defined(_MSC_VER)
#include <intrin.h>
#define thread_compare_and_swap(value, old_value, new_value) (_InterlockedCompareExchange((long*)(value), new_value, old_value) == old_value)

#elif defined(__GNUC__)
#define thread_compare_and_swap(value, old_value, new_value) (__sync_bool_compare_and_swap((value), old_value, new_value))
#endif

#endif
