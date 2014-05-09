#include "zonefile-fields.h"
#include <ctype.h>


/****************************************************************************
 ****************************************************************************/
void 
mm_charstring_start(struct ZoneFileParser *parser)
{
    parser->rr_buffer.length = 0;
    parser->rr_buffer.line_offset = 0;
    parser->rr_buffer.data = &parser->block->buf[parser->block->offset];
    parser->s2 = 0;
}

/****************************************************************************
 ****************************************************************************/
void 
mm_charstring_end(struct ZoneFileParser *parser)
{
    unsigned length;
    unsigned start;

    /* Get offset to the first byte of the charstring, which will be
     * it's length field */
    start = parser->rr_buffer.line_offset;

    /* Find the length of the charstring */
    length = parser->rr_buffer.length - start - 1;

    /* Set the length field */
    parser->rr_buffer.data[start] = (unsigned char)length;
}

/****************************************************************************
 ****************************************************************************/
void
mm_charstring_parse(
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
	    unsigned char c;
        
        /* get next character */
        if (parse_default2(parser, buf, &i, &length, &c))
            break;

        
	    switch (s) {
	    case $START:
            /* TXT lines are prefixed by a 1-byte length field. We record the
             * location of that length field so that once we reach the end of the 
             * text field, we can go back and set the length prefix
             */
            buffer->line_offset = buffer->length++;
		    
            if (c == '\"') {
                parser->is_string = 1;
			    s = $QUOTED;
                continue;
            } else {
                parser->is_string = 0;
			    s = $TEXT;
            }

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
