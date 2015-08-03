/*
    log messages to console, depending on verbose level

    Use -v (or -d) to get more verbose output. The more -v you add, the
    more verbose the output becomes.

    Details about the running of the program go to <stderr>.
    Details about scan results go to <stdout>, so that they can easily
    be redirected to a file.
*/
#include "logger.h"
#include "string_s.h"
#include <stdarg.h>
#include <stdio.h>

int verbosity = 0; /* yea! a global variable!! */


/***************************************************************************
 ***************************************************************************/
void
vLOG(enum LogLevel level, enum LogCategory cat, const char *fmt, va_list marker)
{
    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}


void LOG_CRIT(enum LogCategory cat, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(L_CRIT, cat, fmt, marker);
    va_end(marker);
}

void LOG_ERR(enum LogCategory cat, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(L_ERR, cat, fmt, marker);
    va_end(marker);
}

void LOG_WARN(enum LogCategory cat, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(L_WARN, cat, fmt, marker);
    va_end(marker);
}

void LOG_INFO(enum LogCategory cat, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(L_INFO, cat, fmt, marker);
    va_end(marker);
}

void LOG_DBG(enum LogCategory cat, int debug_level, const char *fmt, ...)
{
    va_list marker;

    if (debug_level >= verbosity)
        return;
    va_start(marker, fmt);
    vLOG(L_DBG0, cat, fmt, marker);
    va_end(marker);
}



