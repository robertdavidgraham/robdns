#include "configuration.h"
#include "util-filename.h"
#include "pixie.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>


/****************************************************************************
 * Look for suffixes to strings, especially looking for file types like
 * ".conf" or ".zone" or ".pcap".
 * @return 1 if the string has that suffix, or 0 otherwise.
 ****************************************************************************/
static int
ends_with(const char *string, const char *suffix)
{
    size_t string_length = strlen(string);
    size_t suffix_length = strlen(suffix);

    if (suffix_length > string_length)
        return 0;

    return memcmp(string+string_length-suffix_length, suffix, suffix_length) == 0;
}


/****************************************************************************
 * Recursively descened a file directory tree and create a list of 
 * all filenames ending in ".zone".
 ****************************************************************************/
static void
directory_to_zonefile_list(struct Cfg_ZoneDir *zonedir, const char *in_dirname)
{
    void *x;
    size_t dirname_length = strlen(in_dirname);
    char *dirname;
    size_t total_files = 0;
    
    dirname = malloc(dirname_length + 1);
    memcpy(dirname, in_dirname, dirname_length + 1);

    /* strip trailing slashes, if there are any */
    while (dirname_length && (dirname[dirname_length-1] == '/' || dirname[dirname_length-1] == '\\')) {
        dirname_length--;
    }

    /*
     * Start directory enumeration
     */
    x = pixie_opendir(dirname);
    if (x == NULL) {
        perror(dirname);
        free(dirname);
        return; /* no content */
    }

    /*
     * 'for all zonefiles in this directory...'
     */
    for (;;) {
        const char *filename;
        char *fullname;
        struct _stat64 s;

        /* Get next filename */
        filename = pixie_readdir(x);
        if (filename == NULL)
            break;

        /* Skip the bad names */
        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
            continue;

        /* get the full name */
        fullname = filename_combine(dirname, filename);

        /* Get the file size/timestmap */
        if (_stat64(fullname, &s) != 0) {
            perror(fullname);
            free(fullname);
            continue;
        }

        /* if this is a directory, then recursively descend */
        if (s.st_mode & S_IFDIR) {
            directory_to_zonefile_list(zonedir, fullname);
            free(fullname);
            continue;
        }

        /* add the name to our list
         * TODO: this should insert in sort order */
        if (zonedir->file_count + 1 > zonedir->file_max) {
            zonedir->file_max = zonedir->file_max*2 + 1;
            if (zonedir->files == 0)
                zonedir->files = malloc(sizeof(zonedir->files[0]) * zonedir->file_max);
            else
                zonedir->files = realloc(zonedir->files, sizeof(zonedir->files[0]) * zonedir->file_max);
        }

        if (!ends_with(filename, ".zone")) {
            free(fullname);
            continue;
        }

        zonedir->files[zonedir->file_count].filename = fullname;
        zonedir->files[zonedir->file_count].size = s.st_size;
        zonedir->files[zonedir->file_count].timestamp = s.st_mtime;
        zonedir->file_count++;
    }
    pixie_closedir(x);

    free(dirname);
}
