#define _CRT_SECURE_NO_WARNINGS
/* Copyright: (c) 2009-2010 by Robert David Graham
** License: This code is private to the author, and you do not 
** have a license to run it, or own a copy, unless given 
** a license personally by the author. This is 
** explained in the LICENSE file at the root of the project. 
**/
/*
    Portable APIs modeled after Linux/Windows APIs
*/
#if malloc==errmalloc
#undef malloc
#undef free
#endif
#if defined linux || defined __linux || defined __linux__
#define _GNU_SOURCE
#endif

#include "pixie.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>

#ifdef WIN32
#define _WIN32_WINNT 0x0500
#if defined(_MSC_VER)
#pragma warning(disable:4115)
#endif
#include <windows.h>
#include <WinBase.h>
#include <winerror.h>
#include <process.h>
#include <rpc.h>
#include <rpcdce.h>
#if defined(_MSC_VER)
#pragma comment(lib,"rpcrt4.lib")
#endif
#else
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/time.h>
#endif

#if defined linux || defined __linux || defined __linux__
#include <sched.h>	/* for getting CPU count and setting thread CPU affinity */
#include <sys/types.h>
#endif

#if defined __APPLE__ || defined __FreeBSD__
#include <sys/sysctl.h>
#endif


#ifndef UNUSEDPARM
#if defined(_MSC_VER)
#define UNUSEDPARM(x) x
#elif defined(__GNUC__)
#define UNUSEDPARM(x)
#endif
#endif

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

/*===========================================================================
 * IPHLPAPI.H (IP helper API)
 *  This include file is not included by default with Microsoft's compilers,
 *  but requires a seperate download of their SDK. In order to make
 *  compiling easier, we are going to copy the definitions from that file
 *  directly into this file, so that the header file isn't required.
 *===========================================================================*/
#if defined(WIN32) && !defined(__IPHLPAPI_H__)
/* __IPHLPAPI_H__ is the mutual-exclusion identifier used in the
 * original Microsoft file. We are going to use the same identifier here
 * so that if the programmer chooses, they can simply include the 
 * original file up above, and these definitions will automatically be
 * excluded. */
#define MAX_ADAPTER_DESCRIPTION_LENGTH  128
#define MAX_ADAPTER_NAME_LENGTH         256
#define MAX_ADAPTER_ADDRESS_LENGTH      8
#define DEFAULT_MINIMUM_ENTITIES        32
#define MAX_HOSTNAME_LEN                128
#define MAX_DOMAIN_NAME_LEN             128
#define MAX_SCOPE_ID_LEN                256
typedef struct {
    char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;
typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;
typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO* Next;
    DWORD ComboIndex;
    char AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
    char Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    UINT AddressLength;
    BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    PIP_ADDR_STRING CurrentIpAddress;
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    BOOL HaveWins;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    time_t LeaseObtained;
    time_t LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;


typedef DWORD (WINAPI *GETADAPTERSINFO)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
typedef DWORD (WINAPI *GETBESTINTERFACE)(DWORD ip_address, DWORD *r_interface_index);

DWORD WINAPI
GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen)
{
    static GETADAPTERSINFO xGetAdaptersInfo;

    if (xGetAdaptersInfo == 0) {
        void *h = pixie_load_library("iphlpapi.dll");
        if (h == NULL) {
            fprintf(stderr, "PIXIE: LoadLibrary(iphlpapi.dll) failed %u\n", (unsigned)GetLastError());
            return GetLastError(); 
        }
        xGetAdaptersInfo = (GETADAPTERSINFO)GetProcAddress(h, "GetAdaptersInfo");
        if (xGetAdaptersInfo == NULL) {
            fprintf(stderr, "PIXIE: GetProcAddress(iphlpapi.dll/%s) failed %u\n", "GetAdaptersInfo", (unsigned)GetLastError());
            return GetLastError();
        }
    }

    return xGetAdaptersInfo(pAdapterInfo, pOutBufLen);
}

DWORD WINAPI
GetBestInterface(DWORD  dwDestAddr, DWORD  *pdwBestIfIndex) 
{
    static GETBESTINTERFACE xGetBestInterface;
    if (xGetBestInterface == 0) {
        void *h = pixie_load_library("iphlpapi.dll");
        if (h == NULL) {
            fprintf(stderr, "PIXIE: LoadLibrary(iphlpapi.dll) failed %u\n", (unsigned)GetLastError());
            return GetLastError(); 
        }
        xGetBestInterface = (GETBESTINTERFACE)GetProcAddress(h, "GetBestInterface");
        if (xGetBestInterface == NULL) {
            fprintf(stderr, "PIXIE: GetProcAddress(iphlpapi.dll/%s) failed %u\n", "GetBestInterface", (unsigned)GetLastError());
            return GetLastError();
        }
    }

    return xGetBestInterface(dwDestAddr, pdwBestIfIndex);
}


#endif


/****************************************************************************
 ****************************************************************************/
void
pixie_strerror(char *error_msg, size_t sizeof_error_msg)
{
#ifdef WIN32
    DWORD err = GetLastError();
    CHAR *msg;

     if(FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |              // [15]
                        FORMAT_MESSAGE_FROM_SYSTEM |                  // [16]
                        0,                                        // [17]
                        0,                                 // [18]
                        err,                                          // [19]
                        0, // language ID
                        (CHAR*)&msg,                                 // [20]
                        0, // size ignored
                        NULL) // arglist
                              == 0)
    { /* not found */
            snprintf(error_msg, sizeof_error_msg, "unknown error");

     } else {
         snprintf(error_msg, sizeof_error_msg, "%s", msg);
         LocalFree(msg);
     }

#else
    snprintf(error_msg, sizeof_error_msg, "%s", strerror(errno));
#endif
}

/****************************************************************************
 * Load a dynamic link library. By loading this manually with code,
 * we can catch errors when the library doesn't exist on the system.
 * We can also go hunting for the library, or backoff and run without
 * that functionality. Otherwise, in the normal method, when the
 * operating system can't find the library, it simply refuses to run
 * our program
 ****************************************************************************/
void *
pixie_load_library(const char *library_name)
{
#ifdef WIN32
	void *h = LoadLibraryA(library_name);
	if (h == 0) {
		switch (GetLastError()) {
		case ERROR_BAD_EXE_FORMAT:
			printf("LoadLibrary(%s): bad DLL format (maybe 64-bit or 32-bit?)\n", library_name);
			break;
		case ERROR_MOD_NOT_FOUND:
			/* silently ignore this error */
			break;
		default:
			printf("LoadLibrary(%s): error# %u\n", library_name, (unsigned)GetLastError());
			break;
		}
	}
	return h;
#else
	void *h;

    h = dlopen(library_name,RTLD_LAZY);
	if (h == NULL) {
		; /*printf("dlopen(%s) err: %s\n", library_name, dlerror());*/
	}
	return h;
#endif
}

/****************************************************************************
 ****************************************************************************/
void
pixie_close_library(void *library_handle)
{
#ifdef WIN32
	BOOL x;
	x = FreeLibrary(library_handle);
	if (x == 0)
		fprintf(stderr, "FreeLibrary(): return error #%u\n", (unsigned)GetLastError());
#else
	int x;
	x = dlclose(library_handle);
	if (x != 0)
		fprintf(stderr, "dlclose(): returned error #%u (%s)\n", errno, dlerror());
#endif
}


/****************************************************************************
 * Retrieve a pointer to the named function. The 'library' is a handle for
 * a dynamic library (.dll or .so) that was loaded with 'pixie_load_library'
 ****************************************************************************/
PIXIE_FUNCTION
pixie_get_proc_symbol(void *library, const char *symbol)
{
#ifdef WIN32
    return (PIXIE_FUNCTION)GetProcAddress(library, symbol);
#else
    /* ISO C doesn't allow us to cast a data pointer to a function
     * pointer, therefore we have to cheat and use a union */
    union {
        void *data;
        PIXIE_FUNCTION func;
    } result;
    result.data = dlsym(library, symbol);
    return result.func;
#endif
}


/****************************************************************************
 * Retrieve the MAC address of the system
 ****************************************************************************/
unsigned
pixie_get_mac_address(unsigned char macaddr[6])
{
    memset(macaddr, 0, 6);
#ifdef WIN32
    {
        DWORD dwStatus;
        IP_ADAPTER_INFO *p;
        IP_ADAPTER_INFO AdapterInfo[16];
        DWORD dwBufLen = sizeof(AdapterInfo);
        DWORD interface_index = (DWORD)-1;

        GetBestInterface(0x01010101, &interface_index);
        
        dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
        if (dwStatus != ERROR_SUCCESS)
              return 1;

        for (p=AdapterInfo; p; p = p->Next) {

            if (p->Index == interface_index || interface_index == -1) {
                memcpy(macaddr, p->Address, 6);
                return 0;
            }
            /*(
            printf("[%02x:%02x:%02x:%02x:%02x:%02x]\n",
            mac_address[0], mac_address[1], mac_address[2], 
            mac_address[3], mac_address[4], mac_address[5]
            );
            printf("    %s\n", p->AdapterName);
            printf("    %s\n", p->Description);
            printf("    IP: ");
            for (a = &p->IpAddressList; a; a = a->Next) {
                printf("%s ", a->IpAddress.String);
            }
            printf("\n");
            */
        }
        return (unsigned)-1;
    }
#else
    return (unsigned)-1;
#endif
}


/****************************************************************************
 * Retrieve the name of the host computer.
 ****************************************************************************/
unsigned
pixie_get_host_name(char *name, unsigned name_size)
{
#ifdef WIN32
    {
        DWORD nSize = (DWORD)name_size;
        /*
        BOOL WINAPI GetComputerName(
          __out    LPTSTR lpBuffer,
        __inout  LPDWORD lpnSize
        );
        Return Value: If the function succeeds, the return value is a nonzero value.
        The variable 'lpnsize' must be set to the length of the number of
        bytes in the string, and it be set to the resulting length */
        if (GetComputerNameA(name, &nSize))
            return (unsigned)nSize;
        else
            return 0;
    }
#else
    /*
    int gethostname(char *name, size_t namelen)
    'namelen' is the size of the 'name' buffer.
    Returns 0 on success, -1 on failure
    */
    if (gethostname(name, name_size) == 0) {
        /* If the buffer is too small, it might not nul terminate the
         * string, so let's guarantee a nul-termination */
        name[name_size-1] = '\0';
        return name_size;
    } else
        return 0;
#endif
}



/****************************************************************************
 ****************************************************************************/
void
pixie_lower_thread_priority()
{
#if defined(WIN32)
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_BELOW_NORMAL);
    SetThreadPriorityBoost(GetCurrentThread(), 1);
#elif defined(__GNUC__)
	/* Todo */
#else
#error pixie_lower_thread_priority undefimed
#endif
}



/****************************************************************************
 ****************************************************************************/
void
pixie_raise_thread_priority()
{
#if defined(WIN32)
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_ABOVE_NORMAL);
    SetThreadPriorityBoost(GetCurrentThread(), 1);
#elif defined(__GNUC__)
	/* Todo */
#else
#error pixie_raise_thread_priority undefimed
#endif
}


/****************************************************************************
 ****************************************************************************/
void
pixie_enter_critical_section(void *cs)
{
    /* check for null, allows users to compile without Multithreading 
     * support */
    if (cs == NULL)
        return;

#if defined(WIN32)
    if (TryEnterCriticalSection((CRITICAL_SECTION*)cs))
        return;
    else {
        EnterCriticalSection((CRITICAL_SECTION*)cs);
    }
#elif defined(__GNUC__)
    pthread_mutex_lock(cs);
#else
#error pixie_enter_critical_section undefimed
#endif
}


/****************************************************************************
 ****************************************************************************/
void
pixie_leave_critical_section(void *cs)
{
    /* check for null, allows users to compile without Multithreading 
     * support */
    if (cs == NULL)
        return;

#if defined(WIN32)
    LeaveCriticalSection(cs);
#elif defined(__GNUC__)
	if (pthread_mutex_unlock(cs) != 0) printf("mutex: failed %d\n", errno);
#else
#error pixie_leave_critical_section undefimed
#endif
}


/****************************************************************************
 ****************************************************************************/
void *
pixie_initialize_critical_section(void)
{
#if defined(WIN32)
    CRITICAL_SECTION *cs = (CRITICAL_SECTION*)malloc(sizeof(*cs));
	if (cs == NULL) {
		fprintf(stderr, "%s: out of memory error\n", "pixie");
		exit(1);
	}
    memset(cs, 0, sizeof(*cs));
    InitializeCriticalSection(cs);
    return cs;
#elif defined(__GNUC__)
    pthread_mutex_t *mutex = (pthread_mutex_t*)malloc(sizeof(*mutex));
	if (mutex == NULL) {
		fprintf(stderr, "%s: out of memory error\n", "pixie");
		exit(1);
	}
    memset(mutex, 0, sizeof(*mutex));
    pthread_mutex_init(mutex, 0);
    return mutex;
#else
#error pixie_initialize_critical_section undefimed
#endif
}


/****************************************************************************
 ****************************************************************************/
void
pixie_close_thread(ptrdiff_t thread_handle)
{
#if defined(WIN32)
	CloseHandle((HANDLE)thread_handle);
#elif defined(__GNUC__)
	/* TODO: does anything go here */
#else
#error pixie_close_thread undefined
#endif
}



/****************************************************************************
 ****************************************************************************/
void 
pixie_delete_critical_section(void *cs)
{
#if defined(WIN32)
    if (cs) {
        DeleteCriticalSection(cs);
        free(cs);
    }
#elif defined(__GNUC__)
	if (cs) {
		pthread_mutex_destroy(cs);
		free(cs);
	}
#else
#error pixie_delete_critical_section undefined
#endif
}

/****************************************************************************
 ****************************************************************************/
void
pixie_sleep(unsigned milliseconds)
{
#ifdef WIN32
    Sleep(milliseconds);
#elif defined(_POSIX_C_SOURCE)
	struct timespec delay;
	delay.tv_sec = 0;
	delay.tv_nsec = milliseconds * 1000 * 1000;
	nanosleep(&delay, 0);
#else
    usleep(milliseconds*1000);
#endif
}


/****************************************************************************
 ****************************************************************************/
uint64_t
pixie_microseconds()
{
#ifdef WIN32
    {
        FILETIME ft;
        uint64_t result;

        GetSystemTimeAsFileTime(&ft);

        result = ((uint64_t)ft.dwHighDateTime) << 32;
        result |= ft.dwLowDateTime;

        return result/10;
    }
#else
    {
        struct timeval tv;
        gettimeofday(&tv,0);

        return ((uint64_t)tv.tv_sec)*1000000 + tv.tv_usec;
    }
#endif
}



/****************************************************************************
 ****************************************************************************/
unsigned 
pixie_locked_xadd_u32(unsigned *lhs, unsigned rhs)
{
#if defined(WIN32)
    return InterlockedExchangeAdd((long*)lhs, rhs);
#elif defined(__GNUC__) && __GNUC__ >= 4 
	return (unsigned)__sync_fetch_and_add(lhs, rhs);
#if 0 && defined(__i386__)
    unsigned ret;
    __asm__ (
        "lock\n\t"
        "xaddl %0,(%1)"
        :"=r" (ret)
        :"r" (lhs), "0" (rhs)
        :"memory" );
        return ret;
#endif
#else
#error pixie_locked_xadd_u32: undefined (unknown compiler or OS)
#endif
}

/****************************************************************************
 ****************************************************************************/
void
pixie_locked_add_u32(volatile unsigned *lhs, unsigned rhs)
{
#if defined(_MSC_VER)
#ifdef _M_X64
    InterlockedAdd((long*)lhs, rhs);
#else
    __asm {
            push eax
            push ebx
            push ecx
            mov ecx, lhs
            mov ebx, rhs

            lock add dword ptr[ecx], ebx

            pop ecx
            pop ebx
            pop eax
    }
#endif
#elif defined(__GNUC__) 
	__sync_add_and_fetch(lhs, rhs);
#if 0 && defined(__i386__)
	 __asm__ __volatile__ (
                      "   lock       ;\n"
                      "   addl %1,%0 ;\n"
                      : "=m"  (lhs)
                      : "ir"  (rhs), "m" (lhs)
                      :  "memory"                               /* no clobber-list */
                      );
#endif
#if 0
    unsigned ret;
    __asm__ (
        "lock\n\t"
        "add %0,(%1)"
        :"=r" (ret)
        :"r" (lhs), "0" (rhs)
        :"memory" );
        /*return ret;*/
#endif
#else
#error: pixie_locked_add_u32: undefined
#endif
}

/****************************************************************************
 ****************************************************************************/
void
pixie_locked_subtract_u32(unsigned *lhs, unsigned rhs)
{
#if defined(_MSC_VER)
#if _M_X64
	InterlockedAdd((long*)lhs, -(long)rhs);
#else
    __asm {
            push eax
            push ebx
            push ecx
            mov ecx, lhs
            mov ebx, rhs

            lock sub dword ptr[ecx], ebx

            pop ecx
            pop ebx
            pop eax
    }
#endif
#elif defined(__GNUC__)
	__sync_sub_and_fetch(lhs, rhs);
#if 0 && defined(__i386__)
    unsigned ret;
    __asm__ (
        "lock\n\t"
        "subl %0,(%1)"
        :"=r" (ret)
        :"r" (lhs), "0" (rhs)
        :"memory" );
        /*return ret;*/
#endif
#else
#error pixie_locked_subtract_u32: not implemented yet
#endif
}

/****************************************************************************
 ****************************************************************************/
bool 
pixie_locked_compare_and_swap(volatile unsigned *dst, unsigned src, unsigned expected)
{
#if defined(WIN32)
	return InterlockedCompareExchange((LONG*)dst, src, expected) == (LONG)expected;
#elif defined(__GNUC__)
	return __sync_bool_compare_and_swap(dst, src, expected);
#if 0 && defined(__i386__)
    unsigned ret;
    __asm__ (
        "lock\n\t"
        "subl %0,(%1)"
        :"=r" (ret)
        :"r" (lhs), "0" (rhs)
        :"memory" );
        /*return ret;*/
#endif
#else
#error pixie_locked_subtract_u32: not implemented yet
#endif
}


/****************************************************************************
 * Retrives the total amount of memory in the system, as well as the current
 * amount of free memory. The reason for this is that the program can
 * size its internal tables so that they fit within physical RAM, otherwise
 * it will cause a lot of swapping.
 ****************************************************************************/
void
pixie_get_memory_size(uint64_t *available, uint64_t *total_physical)
{
#if defined(WIN32)
	MEMORYSTATUSEX status;

	status.dwLength = sizeof(status);

	GlobalMemoryStatusEx(&status);

	*available = status.ullAvailPhys;
	*total_physical = status.ullTotalPhys;

#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
	/* Use 'sysctl' instead? */
	size_t page_count = sysconf(_SC_PHYS_PAGES);
	size_t page_size = sysconf(_SC_PAGESIZE);
	*total_physical = page_count * page_size;
	available = total_physical;
#elif defined(__APPLE__)

        size_t oldlen;
        uint64_t physmem_size;

        oldlen = sizeof(physmem_size);
        sysctlbyname("hw.memsize", &physmem_size, &oldlen, NULL, 0);

	*total_physical = physmem_size;
	available = total_physical;
#else
#error pixie_get_memory_size: not implemented yet
#endif
}



/****************************************************************************
 ****************************************************************************/
void 
pixie_thread_ignore_signals()
{
#ifndef WIN32
	sigset_t mask;
	sigfillset(&mask);
	pthread_sigmask(SIG_SETMASK, &mask, 0);
#endif
}




#ifdef WIN32
#include <Windows.h>
struct dirent {
	char	d_name[FILENAME_MAX];
};
typedef struct DIR {
	HANDLE			handle;
	WIN32_FIND_DATAA	info;
	struct dirent		result;
} DIR;

void *
pixie_opendir(const char *name)
{
	DIR	*dir = NULL;
	char	path[FILENAME_MAX];

	if (name == NULL || name[0] == '\0') {
		errno = EINVAL;
	} else if ((dir = (DIR *) malloc(sizeof(*dir))) == NULL) {
		errno = ENOMEM;
	} else {
		snprintf(path, sizeof(path), "%s/*", name);
		dir->handle = FindFirstFileA(path, &dir->info);

		if (dir->handle != INVALID_HANDLE_VALUE) {
			dir->result.d_name[0] = '\0';
		} else {
			free(dir);
			dir = NULL;
		}
	}

	return (dir);
}

int
pixie_closedir(void *v_dir)
{
    DIR *dir = (DIR*)v_dir;
	int result = -1;

	if (dir != NULL) {
		if (dir->handle != INVALID_HANDLE_VALUE)
			result = FindClose(dir->handle) ? 0 : -1;

		free(dir);
	}

	if (result == -1)
		errno = EBADF;

	return (result);
}

const char *
pixie_readdir(void *vdir)
{
    DIR *dir = (DIR*)vdir;
	struct dirent *result = 0;

	if (dir && dir->handle != INVALID_HANDLE_VALUE) {
		if(!dir->result.d_name ||
		    FindNextFileA(dir->handle, &dir->info)) {
			result = &dir->result;
			strcpy(result->d_name, dir->info.cFileName);
		}
	} else {
		errno = EBADF;
	}

    if (result == NULL)
        return NULL;
	return (result->d_name);
}
#else
#include <sys/types.h>
#include <dirent.h>
void *pixie_opendir(const char *name)
{
    return opendir(name);
}
int pixie_closedir(void *v_dir)
{
    return closedir(v_dir);
}
const char *
pixie_readdir(void *vdir)
{
    return readdir(vdir)->d_name;
}
#endif

uint64_t
pixie_get_filesize(const char *filename)
{
        
#if defined(_MSC_VER)
#define stat64 _stat64
#elif defined(__GNUC__)
#define stat64 stat
#endif
    struct stat64 s;
    int x;
      
    s.st_size = 1;
    x = stat64(filename, &s);
    if (x != 0) {
        fprintf(stderr, "couldn't stat(%s)\n", filename);
        perror(filename);
        return 1000;
    } else if (s.st_size == 0) {
        fprintf(stderr, "%s: file is empty\n", filename);
        return 1000;
    }
    return s.st_size;
}
