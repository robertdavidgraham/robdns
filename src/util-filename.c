#include "util-filename.h"
#include "util-keyword.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef WIN32
#include <direct.h> /* getcwd */
#define getcwd _getcwd
#else
#include <unistd.h> /* getcwd */
#endif

/* use these macros, because functions like isspace() produce undefined
 * results for sign-extended characters */
#define my_isspace(c) isspace((c)&0xFF)
#define my_isalpha(c) isalpha((c)&0xFF)
#define my_isdigit(c) isdigit((c)&0xFF)

/***************************************************************************
 ****************************************************************************/
void
combine_elements(char *result, unsigned *result_offset, unsigned result_max,
				 unsigned prefix_length,
				 const char *filename, unsigned in_filename_offset, unsigned filename_max)
{
	unsigned filename_offset[1];
	static const struct Keyword slash = {"/", 1};

	*filename_offset = in_filename_offset;

	while (*filename_offset < filename_max) {
		struct Keyword element;

		/* skip duplicate //// characters */
		if (filename[*filename_offset] == '\\') {
			(*filename_offset)++;
			continue;
		}
		if (filename[*filename_offset] == '/') {
			(*filename_offset)++;
			continue;
		}
		
		/* Grab element from input filename */
		element = keyword_next_path_element(filename, filename_offset, filename_max);

		/* ignore "." */
		if (keyword_is_equal(&element, ".")) {
			continue;
		}

		/* traverse "..". Keep track of the path prefix (like "c:\") and don't go
		 * past the root even if there are too many ".." symbols */
		if (keyword_is_equal(&element, "..")) {

			/* go backwards until "/" */
			while (*result_offset > prefix_length && result[(*result_offset)-1] != '/' && result[(*result_offset)-1] != '\\')
				(*result_offset)--;

			/* go backwards past the "/" */ 
			while ((*result_offset) > prefix_length && (result[(*result_offset)-1] == '/' || result[(*result_offset)-1] == '\\'))
				(*result_offset)--;
			
			/* terminate string at this point */
			result[*result_offset] = '\0';
			continue;
		}

		/* else,
		 *	append the right-hand element onto the left-hand element
		 */
		if (*result_offset && result[(*result_offset) - 1] != '/')
			keyword_append(result, result_offset, result_max, slash);
		keyword_append(result, result_offset, result_max, element);
	}
}


/***************************************************************************
 ****************************************************************************/
char *
filename_combine(const char *dirname, const char *filename)
{
	char *result;
	unsigned dirname_length;
	unsigned filename_length;
	unsigned dirname_offset = 0;
	unsigned result_offset = 0;
	unsigned result_max;
	static const struct Keyword slash = {"/", 1};
	struct Keyword prefix;
	unsigned prefix_length;

	/* Deal with empty strings*/
	filename_length = (unsigned)strlen(filename);
	if (dirname == NULL || dirname[0] == '\0') {
		result = (char*)malloc(filename_length+1);
        if (result == NULL)
            exit(1);
		memcpy(result, filename, filename_length+1);
		return result;
	}
	dirname_length = (unsigned)strlen(dirname);


	/* Remove leading '/' on the filename */
	while (filename_length && (filename[0] == '/' || filename[0] == '\\')) {
		filename_length--;
		filename++;
	}

	/* Remove trailing '/' on directory name */
	while (dirname_length && (dirname[dirname_length-1] == '/' || filename[0] == '\\'))
		dirname_length--;

	/* Allocate space for the result */
	result_max = dirname_length + filename_length + 2;
	result = (char*)malloc(result_max + 1);
    if (result == NULL)
        exit(1);

	/*
	 * Get the prefix, which is something like "C:\" on Windows,
	 * or "\\" or "//" also on Windows, or "/" on Unix 
	 */
	prefix = keyword_get_file_prefix(dirname, &dirname_offset, dirname_length);
	keyword_append(result, &result_offset, result_max, prefix);
	if (result_offset && result[result_offset - 1] != '/' && result[result_offset - 1] != '\\')
		keyword_append(result, &result_offset, result_max, slash);
	prefix_length = result_offset;

	/* Combine elements */
	combine_elements(result, &result_offset, result_max, prefix_length, dirname, dirname_offset, dirname_length);
	combine_elements(result, &result_offset, result_max, prefix_length, filename, 0, filename_length);


	return result;
}

/***************************************************************************
 ****************************************************************************/
int
filename_is_absolute(const char *filename)
{
    if (filename == NULL || filename[0] == '\0')
        return 0;
    if (filename[0] == '/')
        return 1;
#if WIN32
    if (filename[0] == '\\')
        return 1;
    if (strlen(filename) >= 3) {
        if (my_isalpha(filename[0]) && filename[1] == ':') {
            if (filename[2] == '\\' || filename[2] == '/')
                return 1;
        }
    }
#endif
    return 0;
}


/***************************************************************************
 ****************************************************************************/
char *
filename_get_directory(const char *filename)
{
    char *filename2;
    size_t len = strlen(filename);
    char *result;

    while (len && filename[len] != '/' && filename[len] != '\\')
        len--;
    
    filename2 = malloc(len+1);
    if (filename2 == NULL)
        exit(1);
    memcpy(filename2, filename, len+1);
    filename2[len] = '\0';
    
    if (filename_is_absolute(filename2))
        result = filename_combine(filename2, "");
    else {
        char buf[512];
        if (getcwd(buf, sizeof(buf)) == NULL)
            exit(1);
        result = filename_combine(buf, filename2);
    }
    free(filename2);
    return result;
}
