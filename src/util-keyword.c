/***************************************************************************
 ****************************************************************************/
#include "util-keyword.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#define my_isdigit(c) isdigit((c)&0xFF)
#define my_isspace(c) isspace((c)&0xFF)
#define my_isalpha(c) isalpha((c)&0xFF)

/***************************************************************************
 ****************************************************************************/
struct Keyword
keyword_next(const char *line, unsigned *r_offset, unsigned max)
{
	unsigned starting;
	struct Keyword result;

	while (*r_offset < max && my_isspace(line[*r_offset]))
		(*r_offset)++;

	starting = *r_offset;

	while (*r_offset < max && !my_isspace(line[*r_offset]))
		(*r_offset)++;

	result.str = line + starting;
	result.length = (*r_offset) - starting;

	while (*r_offset < max && my_isspace(line[*r_offset]))
		(*r_offset)++;

	return result;
}

/***************************************************************************
 ****************************************************************************/
struct Keyword
keyword_next_to_comma(const char *line, unsigned *r_offset, unsigned max)
{
	unsigned starting;
	struct Keyword result;

	/* strip leading whitespace */
	while (*r_offset < max && my_isspace(line[*r_offset]))
		(*r_offset)++;

	starting = *r_offset;

	/* UP TO THE NEXT COMMA */
	while (*r_offset < max && line[*r_offset] != ',')
		(*r_offset)++;

	/* set the value and strip whitespace from the end of it */
	result.str = line + starting;
	result.length = (*r_offset) - starting;
	while (result.length && my_isspace(result.str[result.length-1]))
		result.length--;

	/* skip trailing comma */
	if (*r_offset < max && line[*r_offset] == ',')
		(*r_offset)++;

	/* skip trailing whitespace */
	while (*r_offset < max && my_isspace(line[*r_offset]))
		(*r_offset)++;

	return result;
}

/***************************************************************************
 ****************************************************************************/
struct Keyword
keyword_next_opt_name(const char *line, unsigned *r_offset, unsigned max)
{
	unsigned starting;
	struct Keyword result;

	/* strip leading whitespace */
	while (*r_offset < max && my_isspace(line[*r_offset]))
		(*r_offset)++;

	starting = *r_offset;

	/* UP TO THE NEXT COLON */
	while (*r_offset < max && line[*r_offset] != ':' && line[*r_offset] != ';')
		(*r_offset)++;

	/* set the value and strip whitespace from the end of it */
	result.str = line + starting;
	result.length = (*r_offset) - starting;

	while (result.length && my_isspace(result.str[result.length-1]))
		result.length--;

	if (*r_offset < max && line[*r_offset] == ':')
		(*r_offset)++;

	/* strip trailing whitespace */
	while (*r_offset < max && my_isspace(line[*r_offset]))
		(*r_offset)++;
	return result;
}

/***************************************************************************
 ****************************************************************************/
struct Keyword
keyword_next_opt_value(const char *line, unsigned *r_offset, unsigned max)
{
	unsigned starting;
	struct Keyword result;

	/* strip leading whitespace */
	while (*r_offset < max && my_isspace(line[*r_offset]))
		(*r_offset)++;

	starting = *r_offset;

	/* UP TO THE NEXT COMMA */
	while (*r_offset < max && line[*r_offset] != ';')
		(*r_offset)++;

	/* set the value and strip whitespace from the end of it */
	result.str = line + starting;
	result.length = (*r_offset) - starting;
	while (result.length && my_isspace(result.str[result.length-1]))
		result.length--;

	if (*r_offset < max && line[*r_offset] == ';')
		(*r_offset)++;

	/* strip trailing whitespace */
	while (*r_offset < max && my_isspace(line[*r_offset]))
		(*r_offset)++;
	return result;
}

/***************************************************************************
 ****************************************************************************/
int
keyword_is_equal(const struct Keyword *lhs, const char *rhs)
{
	size_t rhs_length = strlen(rhs);

	if (lhs->length != rhs_length)
		return 0;

	return memcmp(lhs->str, rhs, rhs_length) == 0;	
}


/***************************************************************************
 ****************************************************************************/
int
keyword_to_unsigned(struct Keyword *key, unsigned *r_result)
{
	unsigned i;

	*r_result = 0;

	if (key->length == 0)
		return 0;
	if (!my_isdigit(key->str[0]))
		return 0;

	for (i=0; i<key->length; i++) {
		if (!my_isdigit(key->str[i]))
			break;
		*r_result *= 10;
		*r_result += key->str[i] - '0';
	}

	return 1;
}


/***************************************************************************
 * Get's the 'prefix' from the filename. Filenames look like:
 *  D:\foo\bar\
 *  \\SERVER\foo\bar/
 *  /foo/bar/
 ****************************************************************************/
struct Keyword
keyword_get_file_prefix(const char *filename, unsigned *r_offset, unsigned length)
{
	struct Keyword result = {0,0};

#if WIN32
	/*
	 * if Windows style c:\
	 */
	if (my_isalpha(filename[*r_offset]) && (length-*r_offset)>1 && filename[1+*r_offset] == ':') {
		if (length-*r_offset > 2 && filename[2+*r_offset] == '/') {
			result.str = filename + *r_offset;
			result.length = 3;
		} else {
			result.str = filename + *r_offset;
			result.length = 2;
		}
		*r_offset += 2;
		while (*r_offset < length && filename[*r_offset] == '/')
			(*r_offset)++;
		return result;
	}
#endif

	/*
	 * if Windows style //
	 */
	if ((length-*r_offset) > 1 && memcmp(filename+*r_offset, "//", 2) == 0) {
		result.str = filename + *r_offset;
		result.length = 2;
		while (*r_offset < length && filename[*r_offset] == '/')
			(*r_offset)++;
		return result;
	}

	/*
	 * Unix style
	 */
	if ((length-*r_offset) > 0 && filename[*r_offset] == '/') {
		result.str = filename + *r_offset;
		result.length = 1;
		while (*r_offset < length && filename[*r_offset] == '/')
			(*r_offset)++;
		return result;
	}

	/*
	 * Windows backslash
	 */
	if ((length-*r_offset) > 0 && filename[*r_offset] == '\\') {
		result.str = "/";
		result.length = 1;
		while (*r_offset < length && (filename[*r_offset] == '/' || filename[*r_offset] == '\\'))
			(*r_offset)++;
		return result;
	}

	/*
	 * something else, probably an error
	 */
	{
		unsigned i;

		for (i=*r_offset; i<length && filename[i] != '/'; i++)
			;
		result.str = filename + *r_offset;
		result.length = i - *r_offset;
		*r_offset = i;
		while (*r_offset < length && filename[*r_offset] == '/')
			(*r_offset)++;
		return result;
	}
}

/***************************************************************************
 ****************************************************************************/
void
keyword_append(char *p, unsigned *r_offset, unsigned max, struct Keyword element)
{
	if (*r_offset + element.length < max) {
		memcpy(p+*r_offset, element.str, element.length);
		*r_offset += element.length;
		if (*r_offset < max)
			p[*r_offset] = '\0';
	} else
		fprintf(stderr, "keyword_append(): overflow\n");
}

/***************************************************************************
 ****************************************************************************/
struct Keyword
keyword_next_path_element(const char *filename, unsigned *r_offset, unsigned length)
{
	struct Keyword result;
	unsigned starting = *r_offset;

	while (*r_offset < length && filename[*r_offset] != '/' && filename[*r_offset] != '\\')
		(*r_offset)++;
	result.str = filename + starting;
	result.length = *r_offset - starting;

	while (*r_offset < length && (filename[*r_offset] == '/' || filename[*r_offset] == '\\'))
		(*r_offset)++;

	return result;
}

/***************************************************************************
 ****************************************************************************/
void
keyword_to_name_value(const struct Keyword *field, struct Keyword *name, struct Keyword *value)
{
	unsigned offset = 0;

	*name = keyword_next(field->str, &offset, field->length);
	*value = keyword_next(field->str, &offset, field->length);
}

