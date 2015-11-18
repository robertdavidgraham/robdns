/*
    Track timestamps of all the configuration files we read so that
    during SIGHUP, we can check if any of the configuration has
    changed. Normally, SIGHUP just informs us that zonefile information
    has changed, without a configuration change, so we'd like to skip
    the reconfiguration.
*/
#include "conf-trackfile.h"
#include "logger.h"
#include "util-realloc2.h"
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#if defined(_MSC_VER)
#define stat64 _stat64
#define strdup _strdup
#elif defined(__GNUC__)
#define stat64 stat
#endif

struct Conf_TrackFile
{
    struct {
        char *filename;
        int64_t timestamp;
        int64_t size;
    } *files;
    unsigned count;
    unsigned max;
};

/****************************************************************************
 ****************************************************************************/
unsigned
conf_trackfile_count(const struct Conf_TrackFile *tf)
{
    return tf->count;
}


/****************************************************************************
 ****************************************************************************/
const char *
conf_trackfile_filename(const struct Conf_TrackFile *tf, unsigned index)
{
    return tf->files[index].filename;
}


/****************************************************************************
 ****************************************************************************/
unsigned
conf_trackfile_has_changed2(
    const struct Conf_TrackFile *tfnew, 
    const struct Conf_TrackFile *tfold)
{
    unsigned i;

    /* On startup, when there are no old configuration files, this will
     * be the default case. */
    if (tfold == NULL) {
        if (tfnew == NULL)
            return 0;
        else
            return 1;
    }

    assert(tfnew->count <= tfold->count);

    /* Go through and make sure every file in the NEW matches exactly
     * the configuration file in the OLD */
    for (i=0; i<tfnew->count; i++) {

        /* filenames must be the same */
        if (strcmp(tfnew->files[i].filename, tfold->files[i].filename) != 0)
            return 1;

        /* timestamps must be same */
        if (tfnew->files[i].timestamp != tfold->files[i].timestamp)
            return 1;

        /* file sizes must be same */
        if (tfnew->files[i].size != tfold->files[i].size)
            return 1;
    }

    /* Now go through the remaining files in the OLD configuration
     * to see if they've changed */
    for ( ; i<tfold->count; i++) {
        const char *filename = tfold->files[i].filename;
        int64_t timestamp = tfold->files[i].timestamp;
        int64_t size = tfold->files[i].size;
        struct stat64 s;

        if (stat64(filename, &s) != 0) {
            if (timestamp != 0 || size != 0)
                return 1; /* file is now gone, but didn't used to be */
        } else {
            if (timestamp != s.st_mtime || size != s.st_size)
                return 1; /* file time or size has changed */
        }
    }

    /* If we reach this point without returning, then it means that none
     * of the files have changed. This is the expected condition, since 
     * most of the time we process SIGHUP events, we'll be reloading
     * zonefiles rather tha conf files. */
    return 0;
}

/****************************************************************************
 ****************************************************************************/
unsigned
conf_trackfile_has_changed(const struct Conf_TrackFile *tf)
{
    unsigned i;

    /* On startup, when there are no old configuration files, this will
     * be the default case. */
    if (tf == NULL || tf->count == 0) {
        return 1;
    }

    /* See if the timestamps or filesizes have changed */
    for (i=0; i<tf->count; i++) {
        const char *filename = tf->files[i].filename;
        int64_t timestamp = tf->files[i].timestamp;
        int64_t size = tf->files[i].size;
        struct stat64 s;

        if (stat64(filename, &s) != 0) {
            if (timestamp != 0 || size != 0)
                return 1; /* file is now gone, but didn't used to be */
        } else {
            if (timestamp != s.st_mtime || size != s.st_size)
                return 1; /* file time or size has changed */
        }
    }

    /* If we reach this point without returning, then it means that none
     * of the files have changed. This is the expected condition, since 
     * most of the time we process SIGHUP events, we'll be reloading
     * zonefiles rather tha conf files. */
    return 0;
}

/****************************************************************************
 ****************************************************************************/
void
conf_trackfile_add(struct Conf_TrackFile *tf, const char *filename)
{
    struct stat64 s;

    /* expand storage if there is not enough space */
    if (tf->count + 1 >= tf->max) {
        tf->max = tf->max * 2 + 1;
        tf->files = REALLOC2(tf->files, tf->max, sizeof(tf->files[0]));
    }

    /*
     * Grab the size/timestamp so that we can detect when it changes
     */
    tf->files[tf->count].filename = STRDUP2(filename);
    if (stat64(filename, &s) == 0) {
        tf->files[tf->count].timestamp = s.st_mtime; /* last modified time */
        tf->files[tf->count].size = s.st_size; /* size of the file */
    } else {
        //LOG_WARN(C_CONFIG, "%s: %s\n", filename, strerror(errno));

        /* remember the file if it doesn't exist now, in case it exists
         * in the future */
        tf->files[tf->count].timestamp = 0;
        tf->files[tf->count].size = 0;
    }

    tf->count++;
}

/****************************************************************************
 ****************************************************************************/
struct Conf_TrackFile *
conf_trackfile_create(void)
{
    struct Conf_TrackFile *result;

    result = MALLOC2(sizeof(*result));
    memset(result, 0, sizeof(*result));

    return result;
}

/****************************************************************************
 ****************************************************************************/
void
conf_trackfile_destroy(struct Conf_TrackFile *tf)
{
    size_t i;

    for (i=0; i<tf->count; i++) {
        if (tf->files[i].filename)
            free(tf->files[i].filename);
    }

    free(tf);
}

