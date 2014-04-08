#include "zonefile-parse.h"
#include "zonefile-fields.h"
#include "zonefile-rr.h"
#include <ctype.h> /* fixme: get rid of this include */
#include <string.h>
#include <stdarg.h>
#include "unusedparm.h"

/****************************************************************************
 ****************************************************************************/
static void
parse_err_v(struct ZoneFileParser *parser,  const char *fmt, va_list marker)
{
    parser->src.error_count++;
    fprintf(stderr, "%s:%u: ", parser->src.filename, parser->src.line_number);
    vfprintf(stderr, fmt, marker);
}
void
parse_err(struct ZoneFileParser *parser,  const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    parse_err_v(parser, fmt, marker);
    va_end(marker);
}

/****************************************************************************
 ****************************************************************************/
static unsigned
base64_to_value(const unsigned char c)
{
	if ('A' <= c && c <= 'Z')
		return c - 'A';
	else if ('a' <= c && c <= 'z')
		return c - 'a' + 26;
	else if ('0' <= c && c <= '9')
		return c - '0' + 52;
	else if (c == '+')
		return 62;
	else if (c == '/')
		return 63;
	else if (c == '=')
		return 64;
	else
		return 65;
}

/****************************************************************************
 ****************************************************************************/
static unsigned
base32hex_to_value(const unsigned char c)
{
	if ('A' <= c && c <= 'Z')
		return c - 'A' + 10;
	else if ('a' <= c && c <= 'z')
		return c - 'a' + 10;
	else if ('0' <= c && c <= '9')
		return c - '0';
	else if (c == '=')
		return 64;
	else
		return 65;
}

/****************************************************************************
 ****************************************************************************/
static unsigned
hex_to_value(const unsigned char c)
{
	if ('A' <= c && c <= 'F')
		return c - 'A' + 10;
	else if ('a' <= c && c <= 'f')
		return c - 'a' + 10;
	else if ('0' <= c && c <= '9')
		return c - '0';
	else
		return 16;
}


/****************************************************************************
 ****************************************************************************/
static unsigned
parse_default(struct ZoneFileParser *parser, unsigned *s, const unsigned char *buf, unsigned *offset, unsigned *length)
{
	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,
	};
	unsigned char c = buf[*offset];

    UNUSEDPARM(length);

	switch (*s) {
	case $START:
		switch (c) {
		case ' ':
		case '\t':
		case '\r':
			return 1;
		case '\n':
            parser->src.line_number++;
			if (parser->is_multiline)
				return 1;
			else {
				parse_err(parser, "unexpected character\n");
				*s = $PARSE_ERROR;
				return 1;
			}
		case '(':
			parser->is_multiline = 1;
			return 1;
		case ')':
			parser->is_multiline = 0;
			return 1;
		}
		return 0;
	}
	return 0;
}

/****************************************************************************
 ****************************************************************************/
void
x_parse_ipv6(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length, unsigned char *ipv6)
{
	unsigned i;
	unsigned s = parser->s2;
	unsigned intermediate = (unsigned)parser->rr_ipv6.val;
	unsigned count = parser->rr_ipv6.length&0xFF;
	unsigned n;
	
	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,

		$NUMBER,
		$COLON,
	};
	for (i=*offset; i<length; i++) {
	unsigned char c = buf[i];
	switch (s) {
	case $START:
		if (parse_default(parser, &s, buf, &i, &length))
			break;
		s = $NUMBER;
		intermediate = 0;
		count = 0;

	case $NUMBER:
	state_number:
		n = hex_to_value(c);
		if (n < 16) {
			intermediate *= 16;
			intermediate += n;
			continue;
		}

		if (count <= 14) {
			ipv6[count++] = (unsigned char)(intermediate>>8);
			ipv6[count++] = (unsigned char)(intermediate>>0);
			intermediate = 0;
		}



		switch (c) {
		case ':':
			/* nothing special at this time, as ANY non-hex char
			 * resets the progression.
			 * TODO: handle two of these in a row to 
			 * handle the :: compression
			 */
			s = $COLON;
			continue;

		case ' ':
		case '\t':
		case '\r':
			s = $END;
			continue;

		case '\n':
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else {
				goto end;
			}
		case '(':
			parser->is_multiline = 1;
			continue;
		case ')':
			parser->is_multiline = 0;
			continue;
		default:
			parse_err(parser, "ipv6: unexpected character\n");
			s = $PARSE_ERROR;
			continue;
		}

	case $COLON:
		if (c == ':') {
            if (parser->rr_ipv6.ellision < 16) {
			    parse_err(parser, "ipv6: not supported: IPv6 :: compression\n");
            } else
                parser->rr_ipv6.ellision = count;
            continue;
		}
		s = $NUMBER;
		goto state_number;

	case $COMMENT:
		while (i < length && buf[i] != '\n')
			i++;
		if (i < length) {
			if (parser->is_multiline) {
				s = $END;
				continue;
			}
			goto end;
		}

		break;

	case $END:
		if (c == ';') {
			s = $COMMENT;
			continue;
		} else if (c == ' ' || c == '\t' || c == '\r') {
			continue;
		} else if (c == '\n') {
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else
				goto end;
		} else if (c == ')' && parser->is_multiline) {
			parser->is_multiline = 0;
			continue;
		} else {
			goto end;
		}


	case $PARSE_ERROR:
		while (i<length && !(buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\r'))
			i++;
		break;
	}
	}
end:
	parser->rr_ipv6.val = intermediate;
	parser->rr_ipv6.length = count;
	parser->s2 = s;
	*offset = i;
}

/* Control characters:
 * 0x09 = tab
 * 0x0a = newline
 * 0x0d = carriage return
 * 0x20 = space
 * 0x22 = "
 * 0x28 = (
 * 0x29 = )
 * 0x3b = ; semicolon
 */
char CONTROLCHAR[257] = 
    /*0 1 2 3 4 5 6 7 8 9 a b c d e f    0 1 2 3 4 5 6 7 8 9 a b c d e f*/
    "\0\0\0\0\0\0\0\0\0\1\1\0\0\1\0\0" "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\1\0\1\0\0\0\0\0\1\1\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0\0\0\0\1\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    ;

/****************************************************************************
 ****************************************************************************/
unsigned
parse_default2( struct ZoneFileParser *parser, 
                const unsigned char *buf, unsigned *offset, unsigned *length,
                unsigned char *c)
{
again:
    *c = buf[*offset];

    /*
     * If we are currently in a comment, then process that until
     * end-of-input or end-of-line
     */
    if (parser->is_commenting) {
        while ((*offset) < (*length)  &&  buf[*offset] != '\n')
            (*offset)++;
        if ((*offset) >= (*length))
            return 1; /* caller should break out of loop */
        parser->is_commenting = 0;
        *c = ' ';
        return 0;
    }


    /*
     * Do special processing of certain characters
     */
	switch (buf[*offset]) {
    case ';':
        /* start of comment */
        parser->is_commenting = 1;
        (*offset)++;
        goto again;

	case '\n':
		if (parser->is_multiline) {
            parser->src.line_number++;
            (*offset)++;
            goto again;
        } else {
            /* bring in the outer length, causing the parser loop
                * to break after the current character. Presumably, 
                * the outer parser will treat '\n' as any other 
                * space character */
            *length = (*offset) + 1;
            return 0;
        }
        
	case '(':
        if (!parser->is_string) {
			parser->is_multiline = 1;
            (*offset)++;
            *c = ' ';
            return 0;
        } else
            return 0;

	case ')':
        if (!parser->is_string) {
			parser->is_multiline = 0;
            (*offset)++;
            *c = ' ';
            return 0;
        } else
            return 0;
	}

	return 0;
}

/****************************************************************************
 ****************************************************************************/
void
x_parse_ipv4(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length)
{
	unsigned i;
	unsigned s = parser->s2;
    uint64_t *ipv4 = &parser->rr_number;

	
	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,

		$NUMBER1, $NUMBER2, $NUMBER3, $NUMBER4,
	};
	for (i=*offset; i<length; i++) {
	unsigned char c = buf[i];
	switch (s) {
	case $START:
		if (parse_default(parser, &s, buf, &i, &length))
			break;
		s = $NUMBER1;
		parser->rr_ipv4.result = 0;
		parser->rr_ipv4.count = 0;

	case $NUMBER1:case $NUMBER2:case $NUMBER3:case $NUMBER4:
		if ('0' <= c && c <= '9') {
			parser->rr_ipv4.result *= 10;
			parser->rr_ipv4.result += (c - '0');
			continue;
		}
		*ipv4 <<= 8;
		*ipv4 |= (parser->rr_ipv4.result & 0xFF);
		parser->rr_ipv4.result = 0;



		switch (c) {
		case '.':
			s++;
			continue;

		case ' ':
		case '\t':
		case '\r':
			s = $END;
			continue;

		case '\n':
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else {
				goto end;
			}
		case '(':
			parser->is_multiline = 1;
			continue;
		case ')':
			parser->is_multiline = 0;
			continue;
		default:
			parse_err(parser, "ipv4: unexpected character\n");
			s = $PARSE_ERROR;
			continue;
		}


	case $COMMENT:
		while (i < length && buf[i] != '\n')
			i++;
		if (i < length) {
			if (parser->is_multiline) {
				s = $END;
				continue;
			}
			goto end;
		}

		break;

	case $END:
		if (c == ';') {
			s = $COMMENT;
			continue;
		} else if (c == ' ' || c == '\t' || c == '\r') {
			continue;
		} else if (c == '\n') {
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else
				goto end;
		} else if (c == ')' && parser->is_multiline) {
			parser->is_multiline = 0;
			continue;
		} else {
			goto end;
		}


	case $PARSE_ERROR:
		while (i<length && !(buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\r'))
			i++;
		break;
	}
	}
end:
	parser->s2 = s;
	*offset = i;
}

/****************************************************************************
 ****************************************************************************/
void
x_parse_txt(
        struct ZoneFileParser *parser,
        const unsigned char *buf,
        unsigned *offset,
        unsigned length)
{
    struct ParseBuffer *buffer = &parser->rr_buffer;
	unsigned i;
	unsigned s = parser->s2;
	const unsigned is_whitespace_allowed = 0;

	
	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,

		$TEXT, 
		$TEXT_ESC,
		$QUOTED,
		$QUOTED_ESC0,
		$QUOTED_ESC1,
		$QUOTED_ESC2,
	};
	for (i=*offset; i<length; i++) {
	unsigned char c = buf[i];
	switch (s) {
	case $START:
        /* TXT lines are prefixed by a 1-byte length field. We record the
         * location of that length field so that once we reach the end of the 
         * text field, we can go back and set the length prefix
         */
        buffer->line_offset = buffer->length++;
		if (parse_default(parser, &s, buf, &i, &length))
			break;
		if (c == '\"') {
			s = $QUOTED;
            continue;
        } else
			s = $TEXT;

	case $TEXT:
		switch (c) {
		case ' ':
		case '\t':
		case '\r':
			if (is_whitespace_allowed)
				continue;
			else {
				s = $END;
				continue;
			}
		case '\n':
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else {
				goto end;
			}
		case '(':
			parser->is_multiline = 1;
			continue;
		case ')':
			parser->is_multiline = 0;
			continue;
		default:
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = c;
		}
		continue;


	case $QUOTED:
		switch (c) {
        case '\"':
            s = $END;
            continue;
        case '\\':
            s = $QUOTED_ESC0;
            continue;
        case '\n':
            parser->src.line_number++;
            parse_err(parser, "TXT: unhandled condition\n");

		default:
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = c;
		}
		continue;

	case $COMMENT:
		while (i < length && buf[i] != '\n')
			i++;
		if (i < length) {
			if (parser->is_multiline) {
				s = $END;
				continue;
			}
			goto end;
		}

		break;
	case $QUOTED_ESC0:
		if ('0' <= c && c <= '9') {
			parser->substring_esc = c - '0';
			s = $QUOTED_ESC1;
			continue;
		} else {
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = '\\';
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = c;
			s = $QUOTED;
			continue;
		}
		break;
	case $QUOTED_ESC1:
		if ('0' <= c && c <= '9') {
			parser->substring_esc *= 10;
			parser->substring_esc = c - '0';
			s = $QUOTED_ESC2;
			continue;
		} else {
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = (unsigned char)parser->substring_esc;
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = c;
			s = $QUOTED;
			continue;
		}
		break;
	case $QUOTED_ESC2:
		if ('0' <= c && c <= '9') {
			parser->substring_esc *= 10;
			parser->substring_esc = c - '0';
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = (unsigned char)parser->substring_esc;
			s = $QUOTED;
			continue;
		} else {
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = (unsigned char)parser->substring_esc;
			if (buffer->length < (65536-12))
				buffer->data[buffer->length++] = c;
			s = $QUOTED;
			continue;
		}
		break;

	case $END:
        switch (c) {
        case ';':
			s = $COMMENT;
			continue;
        case ' ':
        case '\t':
        case '\r':
			continue;
        case '\n':
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else
				goto end;
        case ')':
		    if (parser->is_multiline) {
			    parser->is_multiline = 0;
			    continue;
		    } else {
			    goto end;
		    }
        case '(':
            if (parser->is_multiline) {
                goto end;
            } else {
                parser->is_multiline = 1;
                continue;
            }
        default:
            goto end;
        }


	case $PARSE_ERROR:
		while (i<length && !isspace(buf[i]))
			i++;
		break;
    default:
        parse_err(parser, "TXT errror\n");
        break;
	}
	}
end:
	parser->s2 = s;
	*offset = i;
}

/****************************************************************************
 ****************************************************************************/
void
x_parse_hex(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length, unsigned is_whitespace_allowed)
{
    struct ParseBuffer *buffer = &parser->rr_buffer;
	unsigned i;
	unsigned s = parser->s2;
	unsigned n;

	
	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,

		$NUMBER, 
		$EQUALS,
	};
	for (i=*offset; i<length; i++) {
	unsigned char c = buf[i];
	switch (s) {
	case $START:
		if (parse_default(parser, &s, buf, &i, &length))
			break;
		s = $NUMBER;
		buffer->length = 0;
		parser->rr_hex.count = 0;

	case $NUMBER:
		n = hex_to_value(c);
		if (n < 16) {
			parser->rr_hex.result <<= 4;
			parser->rr_hex.result |= n;
			parser->rr_hex.count++;
			if (parser->rr_hex.count == 2) {
				parser->rr_hex.count = 0;
				if (buffer->length + 2 < (65536-12)) {
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_hex.result>>0);
				}
			}
			continue;
		}
		
		switch (c) {
		case '-':
			if (buffer->length == 0 && parser->rr_hex.count == 0) {
				s = $END;
				continue;
			} else {
				parse_err(parser, "hex: unexpected character\n");
				s = $PARSE_ERROR;
				continue;
			}

		case ' ':
		case '\t':
		case '\r':
			if (is_whitespace_allowed)
				continue;
			else {
				s = $END;
				continue;
			}
		case '\n':
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else {
				goto end;
			}
		case '(':
			parser->is_multiline = 1;
			continue;
		case ')':
			parser->is_multiline = 0;
			continue;
		default:
			parse_err(parser, "unexpected character\n");
			s = $PARSE_ERROR;
			continue;
		}


	case $COMMENT:
		while (i < length && buf[i] != '\n')
			i++;
		if (i < length) {
			if (parser->is_multiline) {
				s = $END;
				continue;
			}
			goto end;
		}

		break;

	case $END:
		if (c == ';') {
			s = $COMMENT;
			continue;
		} else if (c == ' ' || c == '\t' || c == '\r') {
			continue;
		} else if (c == '\n') {
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else
				goto end;
		} else if (c == ')' && parser->is_multiline) {
			parser->is_multiline = 0;
			continue;
		} else {
			goto end;
		}


	case $PARSE_ERROR:
		while (i<length && !isspace(buf[i]))
			i++;
		break;
	}
	}
end:
	parser->s2 = s;
	*offset = i;
}

/****************************************************************************
 ****************************************************************************/
void
x_parse_ttl(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length)
{
    uint64_t *result = &parser->rr_number;
	unsigned i;
	unsigned s = parser->s2;
	
	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,

		$NUMBER, 
	};
	for (i=*offset; i<length; i++) {
	unsigned char c = buf[i];
	switch (s) {
	case $START:
		if (parse_default(parser, &s, buf, &i, &length))
			break;
		if ('0' <= c && c <= '9') {
			*result = 0;
			s = $NUMBER;
		} else {
			parse_err(parser, "unexpected character\n");
			s = $PARSE_ERROR;
			continue;
		}

	case $NUMBER:
		switch (c) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			*result = *result * 10 + (c - '0');
			break;
		case 'w': case 'W':
			*result *= 24*60*60*7;
			s = $END;
			break;
		case 'd': case 'D':
			*result *= 24*60*60;
			s = $END;
			break;
		case 'h': case 'H':
			*result *= 60*60;
			s = $END;
			break;
		case 'm': case 'M':
			*result *= 60;
			s = $END;
			break;
		case ' ':
		case '\t':
		case '\r':
			s = $END;
			break;
		case '\n':
			goto end;
		case ';':
			s = $COMMENT;
			break;
        case ')':
            s = $END;
            i--;
            continue;
		default:
			parse_err(parser, "unexpected numeric character\n");
			s = $PARSE_ERROR;
			break;
		}
		continue;

	case $COMMENT:
		while (i < length && buf[i] != '\n')
			i++;
		if (i < length) {
			if (parser->is_multiline) {
				s = $END;
				continue;
			}
			goto end;
		}

		break;

	case $END:
		if (c == ';') {
			s = $COMMENT;
			continue;
		} else if (c == ' ' || c == '\t' || c == '\r') {
			continue;
		} else if (c == '\n') {
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else
				goto end;
		} else if (c == ')' && parser->is_multiline) {
			parser->is_multiline = 0;
			continue;
		} else {
			goto end;
		}


	case $PARSE_ERROR:
		while (i<length && !isspace(buf[i]))
			i++;
		break;
	}
	}
end:
	parser->s2 = s;
	*offset = i;
}

/****************************************************************************
 ****************************************************************************/
void
x_parse_base64(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length)
{
    struct ParseBuffer *buffer = &parser->rr_buffer;
	unsigned i;
	unsigned s = parser->s2;
	unsigned n;

	
	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,

		$NUMBER, 
		$EQUALS,
	};
	for (i=*offset; i<length; i++) {
	unsigned char c = buf[i];
	switch (s) {
	case $START:
		s = $NUMBER;
		buffer->length = 0;
		parser->rr_base64.count = 0;

	case $NUMBER:
		n = base64_to_value(c);
		if (n < 64) {
			parser->rr_base64.result <<= 6;
			parser->rr_base64.result |= n;
			parser->rr_base64.count++;
			if (parser->rr_base64.count == 4) {
				parser->rr_base64.count = 0;
				if (buffer->length + 4 < (65536-12)) {
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base64.result>>16);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base64.result>>8);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base64.result>>0);
				}
			}
			continue;
		}
		
		switch (c) {
		case '=':
			s = $EQUALS;
			break;
		case ' ':
		case '\t':
		case '\r':
			continue;
		case '\n':
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else {
				goto end;
			}
		case '(':
			parser->is_multiline = 1;
			continue;
		case ')':
			parser->is_multiline = 0;
			continue;
        case ';':
            s = $END;
            goto end;
		default:
			parse_err(parser, "unexpected character\n");
			s = $PARSE_ERROR;
			continue;
		}



	case $EQUALS:
		if (c == '=') {
			parser->rr_base64.count++;
			if (parser->rr_base64.count == 4) {
				parser->rr_base64.count = 0;
				if (buffer->length + 4 < (65536-12)) {
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base64.result>>16);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base64.result>>8);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base64.result>>0);
				}
				s = $END;
				continue;
			}
			continue;
		} else {
			s = $END;
			goto case_end;
		}

	case $COMMENT:
		while (i < length && buf[i] != '\n')
			i++;
		if (i < length) {
			if (parser->is_multiline) {
				s = $END;
				continue;
			}
			goto end;
		}

		break;

	case $END:
	case_end:
		if (c == ';') {
			s = $COMMENT;
			continue;
		} else if (c == ' ' || c == '\t' || c == '\r') {
			continue;
		} else if (c == '\n') {
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else
				goto end;
		} else if (c == ')' && parser->is_multiline) {
			parser->is_multiline = 0;
			continue;
		} else {
			goto end;
		}


	case $PARSE_ERROR:
		while (i<length && !isspace(buf[i]))
			i++;
		break;
	}
	}
end:
	parser->s2 = s;
	*offset = i;
}

/****************************************************************************
 ****************************************************************************/
void
x_parse_base32hex(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length)
{
    struct ParseBuffer *buffer = &parser->rr_buffer;
	unsigned i;
	unsigned s = parser->s2;
	unsigned n;

	
	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,

		$NUMBER, 
		$EQUALS,
	};
	for (i=*offset; i<length; i++) {
	unsigned char c = buf[i];
	switch (s) {
	case $START:
		if (c == ' ' || c == '\t' || c == '\r')
			continue;
		s = $NUMBER;
		buffer->length = 0;
		parser->rr_base32hex.count = 0;

	case $NUMBER:
		n = base32hex_to_value(c);
		if (n < 64) {
			parser->rr_base32hex.result <<= 5;
			parser->rr_base32hex.result |= n;
			parser->rr_base32hex.count++;
			if (parser->rr_base32hex.count == 8) {
				parser->rr_base32hex.count = 0;
				if (buffer->length + 5 < (65536-12)) {
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>>32);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>>24);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>>16);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>> 8);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>> 0);
				}
			}
			continue;
		}
		
		switch (c) {
		case '=':
			s = $EQUALS;
			break;
		case ' ':
		case '\t':
		case '\r':
			s = $END;
			continue;
		case '\n':
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else {
				goto end;
			}
		case '(':
			parser->is_multiline = 1;
			continue;
		case ')':
			parser->is_multiline = 0;
			continue;
		default:
			parse_err(parser, "unexpected character\n");
			s = $PARSE_ERROR;
			continue;
		}



	case $EQUALS:
		if (c == '=') {
			parser->rr_base32hex.count++;
			if (parser->rr_base32hex.count == 8) {
				parser->rr_base32hex.count = 0;
				if (buffer->length + 5 < (65536-12)) {
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>>32);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>>24);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>>16);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>> 8);
					buffer->data[buffer->length++] = (unsigned char)(parser->rr_base32hex.result>> 0);
				}
				s = $END;
				continue;
			}
			continue;
		} else {
			s = $END;
			goto case_end;
		}

	case $COMMENT:
		while (i < length && buf[i] != '\n')
			i++;
		if (i < length) {
			if (parser->is_multiline) {
				s = $END;
				continue;
			}
			goto end;
		}

		break;

	case $END:
	case_end:
		if (c == ';') {
			s = $COMMENT;
			continue;
		} else if (c == ' ' || c == '\t' || c == '\r') {
			continue;
		} else if (c == '\n') {
			if (parser->is_multiline) {
                parser->src.line_number++;
				continue;
            } else
				goto end;
		} else if (c == ')' && parser->is_multiline) {
			parser->is_multiline = 0;
			continue;
		} else {
			goto end;
		}


	case $PARSE_ERROR:
		while (i<length && !isspace(buf[i]))
			i++;
		break;
	}
	}
end:
	parser->s2 = s;
	*offset = i;
}
