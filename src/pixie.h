/* Copyright: (c) 2009-2010 by Robert David Graham
** License: This code is private to the author, and you do not 
** have a license to run it, or own a copy, unless given 
** a license personally by the author. This is 
** explained in the LICENSE file at the root of the project. 
**/
#ifndef PIXIE_H
#define PIXIE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#define bool int

#if WIN32
#include <direct.h>
#define getcwd _getcwd
#else
#include <unistd.h>
#endif


typedef void (*PIXIE_FUNCTION)(void);

void *pixie_opendir(const char *name);
int pixie_closedir(void *v_dir);
const char *pixie_readdir(void *dir);

uint64_t pixie_get_filesize(const char *filename);

/* WIN32: FormatMessage(GetLastError)
 * LINUX: strerror(errno)*/
void pixie_strerror(char *error_msg, size_t sizeof_error_msg);

/* WIN32: LoadLibrary()
 * LINUX: dlopen() */
void *pixie_load_library(const char *library_name);
void pixie_close_library(void *library_handle);

/* WIN32: GetProcAddress()
 * LINUX: dlsym() */
PIXIE_FUNCTION pixie_get_proc_symbol(void *library, const char *symbol);

void pixie_sleep(unsigned milliseconds);

#if 0
void pixie_close_thread(ptrdiff_t thread_handle);
void pixie_end_thread(void);

void *pixie_initialize_critical_section();
void pixie_delete_critical_section(void *cs);
void pixie_leave_critical_section(void *cs);
void pixie_enter_critical_section(void *cs);
void pixie_lower_thread_priority(void);
void pixie_raise_thread_priority(void);
uint64_t pixie_microseconds(void);

void pixie_cpu_set_affinity(unsigned processor);
#endif

/**
 * Get the number CPUs in the system. This does not get CPU geomtry,
 * so there is no way to discover the number of sockets, or hypterthreads.
 * A quad-core hyper-threaded Nehalem CPU will return a count of "8".
 */
unsigned pixie_cpu_get_count();

/**
 * Retrieve the 6-byte MAC address of the local computer. This is
 * complicated by the fact that there is no robust API on systems to
 * get this address. The reason there is no simple method is that
 * computers may not have a network card at all, and thus no MAC address.
 * For example, a computer that connects via Bluetooth or dialup will
 * not have a MAC address. Another complication is that a computer may have
 * more than one network card, such as an Ethernet card and a WiFi card.
 */
unsigned pixie_get_mac_address(unsigned char macaddr[6]);

/**
 * WIN32: GetComputerName()
 * LINUX: get_host_name()
 */
unsigned pixie_get_host_name(char *name, unsigned name_size);

//unsigned pixie_locked_xadd_u32(unsigned *lhs, unsigned rhs);

//void pixie_locked_add_u32(volatile unsigned *lhs, unsigned rhs);
//void pixie_locked_subtract_u32(unsigned *lhs, unsigned rhs); 
//bool pixie_locked_CAS32(volatile unsigned *dst, unsigned src, unsigned expected);
//bool pixie_locked_CAS64(volatile uint64_t *dst, uint64_t src, uint64_t expected);
//bool pixie_locked_CAS128(volatile void *dst, unsigned src, unsigned expected);

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__)
    static __inline__ unsigned long long __rdtsc(void)
    {
        unsigned long hi = 0, lo = 0;
        __asm__ __volatile__ ("lfence\n\trdtsc" : "=a"(lo), "=d"(hi));
        return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
    }
#endif

void
pixie_get_memory_size(uint64_t *available, uint64_t *total_physical);


/**
 * Configure the thread to ignore all signals sent to it. This assumes
 * that the main thread is handling signals, or that you've started a 
 * special signals-only thread.
 */
//void pixie_thread_ignore_signals();


/**
 * Thread "barriers"
 */
/*#if defined(WIN32)
typedef struct pixie_barrier_t {
	int count;
	int total;
	void *cs;
	void *cv;
} pixie_barrier_t;
#define PIXIE_MUTEX_INITIALIZER {(void*)-1,-1,0,0,0,0}
#define PIXIE_BARRIER_INITIALIZER {0,0,PIXIE_MUTEX_INITIALIZER,{0}}
#define PIXIE_BARRIER_SERIAL_THREAD 1
#elif defined(__GNUC__)
#define pixie_barrier_t pthread_barrier_t
#endif
*/

#ifdef __cplusplus
}
#endif
#endif
