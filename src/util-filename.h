/***************************************************************************
 ****************************************************************************/
#ifndef UTIL_FILENAME_H
#define UTIL_FILENAME_H

/* Combine directoryname with filename */
char *filename_combine(const char *dirname, const char *filename);

int filename_is_absolute(const char *filename);

char *filename_get_directory(const char *filename);

#endif
