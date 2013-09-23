/***************************************************************************
 ****************************************************************************/
#ifndef KEYWORD_H
#define KEYWORD_H

struct Keyword
{
	const char *str;
	unsigned length;
};

struct Keyword keyword_next(const char *line, unsigned *r_offset, unsigned max);
struct Keyword keyword_next_to_comma(const char *line, unsigned *r_offset, unsigned max);
struct Keyword keyword_next_opt_name(const char *line, unsigned *r_offset, unsigned max);
struct Keyword keyword_next_opt_value(const char *line, unsigned *r_offset, unsigned max);
struct Keyword keyword_next_path_element(const char *line, unsigned *r_offset, unsigned max);

int keyword_is_equal(const struct Keyword *lhs, const char *rhs);
struct Keyword keyword_get_file_prefix(const char *filename, unsigned *r_offset, unsigned length);
void keyword_append(char *p, unsigned *r_offset, unsigned max, struct Keyword element);

void keyword_to_name_value(const struct Keyword *field, struct Keyword *name, struct Keyword *value);
int keyword_to_unsigned(struct Keyword *key, unsigned *r_result);


#endif
