#include "config.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

/******************************************************************************
 ******************************************************************************/
int
CONF_ERROR(struct ConfText *t, const char *fmt, ...)
{
    va_list marker;
    fprintf(stderr, "%s:%u: ", t->filename, t->line_number);
    va_start(marker, fmt);
    vfprintf(stderr, fmt, marker);
    va_end(marker);
    t->is_error = 1;
    return -1;
}

/******************************************************************************
 ******************************************************************************/
void
string_free(struct String *str)
{
    if (str && str->capacity)
        free(str->str);
    memset(str, 0, sizeof(*str));
}
bool
string_is_equal(struct String lhs, struct String rhs)
{
    if (lhs.length != rhs.length)
        return false;
    return memcmp(lhs.str, rhs.str, rhs.length) == 0;
}

bool
kw_is_equals(const struct Keyword lhs, const char *rhs)
{
    size_t rhs_length;
    if (rhs == NULL)
        rhs_length = 0;
    else 
        rhs_length = strlen(rhs);
    if (lhs.length != rhs_length)
        return false;
    return memcmp(lhs.str, rhs, rhs_length) == 0;
}

/******************************************************************************
 * skips both whitespace and comments
 ******************************************************************************/
int
c__skip_whitespace(struct ConfText *t)
{
    size_t i = t->offset;
    size_t length = t->length;
    const char *buf = t->buf;
    
    while (i < length) {
        
        /* skip whitespace */
        if (i < length && isspace(buf[i]&0xFF)) {
            if (buf[i] == '\n')
                t->line_number++;
            i++;
            continue;
        }
        
        /* skip # comments */
        if (i < length && buf[i] == '#') {
            while (i < length && buf[i] != '\n')
                i++;
            continue;
        }
        
        /* skip C++ // comments */
        if (i + 1 < length && memcmp(buf+i, "//", 2) == 0) {
            while (i < length && buf[i] != '\n')
                (i)++;
            continue;
        }
        
        /* skip C comments */
        if (i + 1 < length && memcmp(buf+i, "/*", 2) == 0) {
            unsigned tmp_line_number = t->line_number;
            i += 2;
            while (i + 1 < length && buf[i] != '*' && buf[i+1] != '/') {
                if (buf[i] == '\n')
                    t->line_number++;
                i++;
            }
            if (i + 1 < length && memcmp(buf+i, "*/", 2) == 0) {
                i += 2;
                continue;
            } else {
                fprintf(stderr, "%s:%u: end of comment not found\n", 
                        t->filename, tmp_line_number);
                t->offset = length;
                return -1;
            }
        }

        /* If we've reached this point, there are no comments or whitespace,
         * so just return */
        break;
    }
    
    t->offset = i;
    return 0;
}

/******************************************************************************
 ******************************************************************************/
bool
c__skip_brace(struct ConfText *t)
{
    c__skip_whitespace(t);
    
    if (t->is_error)
        return false;

    if (t->offset >= t->length || t->buf[t->offset] != '{') {
        return false;
    } else {
        t->offset++;
        c__skip_whitespace(t);
        return true;
    }
}


/******************************************************************************
 ******************************************************************************/
bool
c__skip_endbrace(struct ConfText *t)
{
    c__skip_whitespace(t);
    
    if (t->is_error)
        return false;

    if (t->offset >= t->length || t->buf[t->offset] != '}') {
        return false;
    } else {
        t->offset++;
        c__skip_whitespace(t);
        return true;
    }
}


/******************************************************************************
 ******************************************************************************/
bool
c__skip_semicolon(struct ConfText *t)
{
    c__skip_whitespace(t);
    
    if (t->is_error)
        return false;

    if (t->offset >= t->length || t->buf[t->offset] != ';') {
        return false;
    } else {
        t->offset++;
        c__skip_whitespace(t);
        return true;
    }
}

/******************************************************************************
 ******************************************************************************/
bool
c__skip_exclamation(struct ConfText *t)
{
    c__skip_whitespace(t);
    
    if (t->is_error)
        return false;

    if (t->offset >= t->length || t->buf[t->offset] != ';') {
        return false;
    } else {
        t->offset++;
        c__skip_whitespace(t);
        return true;
    }
}




/******************************************************************************
 ******************************************************************************/
bool
c__is_brace(const struct ConfText *t)
{
    if (t->offset < t->length && t->buf[t->offset] == '{')
        return true;
    else
        return false;
}
bool
c__is_endbrace(const struct ConfText *t)
{
    if (t->offset < t->length && t->buf[t->offset] == '}')
        return true;
    else
        return false;
}
bool
c__is_semicolon(const struct ConfText *t)
{
    if (t->offset < t->length && t->buf[t->offset] == ';')
        return true;
    else
        return false;
}
bool
c__is_exclamation(const struct ConfText *t)
{
    if (t->offset < t->length && t->buf[t->offset] == '!')
        return true;
    else
        return false;
}



/******************************************************************************
 ******************************************************************************/
void
string_append(struct String *s, const char *rhs, size_t rhs_length)
{
    
    /* expand capacity if needed */
    if (s->length + rhs_length >= s->capacity) {
        while (s->length + rhs_length >= s->capacity)
            s->capacity = s->capacity * 2 + 1;
        
        if (s->str == NULL) {
            s->str = malloc(s->capacity + 1);
        } else {
            s->str = realloc(s->str, s->capacity + 1);
        }
    }
    
    memcpy(s->str + s->length, rhs, rhs_length);
    s->length += rhs_length;
    s->str[s->length] = '\0';    
}

/******************************************************************************
 ******************************************************************************/
struct String
c__next_string(struct ConfText *t)
{
    struct String s;
    
    memset(&s, 0, sizeof(s));
    
    c__skip_whitespace(t);
    
    if (t->offset >= t->length || t->buf[t->offset++] != '\"') {
        CONF_ERROR(t, "expected \" to start string\n");
        return s;
    }
    
    while (t->offset < t->length && t->buf[t->offset] != '\"') {
        string_append(&s, t->buf + t->offset, 1);
        t->offset++;
    }
    
    if (t->offset < t->length && t->buf[t->offset] == '\"')
        t->offset++;
    
    c__skip_whitespace(t);
    
    return s;
}


/******************************************************************************
 ******************************************************************************/
struct Keyword
c__next_keyword(struct ConfText *t)
{
    struct Keyword kw;
    
    c__skip_whitespace(t);
    
    kw.str = t->buf + t->offset;
    for (kw.length = 0; t->offset + kw.length < t->length; kw.length++) {
        char c = t->buf[t->offset + kw.length];
        if (!isalnum(c&0xFF) && c != '-' && c != '_')
            break;
    }
    
    t->offset += kw.length;

    c__skip_whitespace(t);

    return kw;
}

bool
c__is_keyword(const struct ConfText *t, const char *keyword)
{
    struct Keyword kw;
    
    kw.str = t->buf + t->offset;
    for (kw.length = 0; t->offset + kw.length < t->length; kw.length++) {
        char c = t->buf[t->offset + kw.length];
        if (!isalnum(c&0xFF) && c != '-' && c != '_')
            break;
    }

    return kw_is_equals(kw, keyword);
}

/******************************************************************************
 ******************************************************************************/
bool
c__is_ipv4(const struct ConfText *t)
{
    unsigned x;
    const unsigned char *px = (const unsigned char*)t->buf + t->offset;
    size_t length = t->length - t->offset;
    size_t offset = 0;
    unsigned i;

    if (t->offset >= t->length)
        return false;
    
    /* Make sure there is at least one number [0..255] */
    for (i=0; i<4; i++) {
        if (!isdigit(px[offset]))
            return false;
        x = px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        if (x > 255)
            return false;
        if (i < 3) {
            if (px[offset] != '.')
                break;
            else
                offset++;
        }
    }

    if (offset < length && px[offset] == '/') {
        if (!isdigit(px[offset]))
            return false;
        x = px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        if (x > 32)
            return false;
    } else if (i != 4) {
        /* if not CIDR, then must have 4 numbers */
        return false;
    }

    if (offset >= length)
        return true;

    if (isspace(px[offset]) || ispunct(px[offset]))
        return true;
    else
        return false;
}

/******************************************************************************
 ******************************************************************************/
bool
c__next_ipv4(struct ConfText *t, unsigned *address, unsigned *prefix)
{
    unsigned x;
    const unsigned char *px = (const unsigned char *)t->buf + t->offset;
    size_t length = t->length - t->offset;
    size_t offset = 0;
    unsigned i;

    *address = 0;
    *prefix = 32;

    if (t->offset >= t->length)
        return false;
    
    /* Make sure there is at least one number [0..255] */
    for (i=0; i<4; i++) {
        if (!isdigit(px[offset]))
            return false;
        x = px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        *address <<= 8;
        *address |= x;
        if (x > 255)
            return false;
        if (i < 3) {
            if (px[offset] != '.')
                break;
            else
                offset++;
        }
    }

    if (offset < length && px[offset] == '/') {
        while (i < 4) {
            *address <<= 8;
            i++;
        }

        if (!isdigit(px[offset]))
            return false;
        x = px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        *prefix = x;
        if (x > 32)
            return false;
    } else if (i != 4) {
        /* if not CIDR, then must have 4 numbers */
        return false;
    }

    t->offset += offset;

    c__skip_whitespace(t);
    return true;
}

/******************************************************************************
 ******************************************************************************/
bool
c__next_ipv6(struct ConfText *t, unsigned *address, unsigned *prefix)
{
    unsigned x;
    const unsigned char *px = (const unsigned char *)t->buf + t->offset;
    size_t length = t->length - t->offset;
    size_t offset = 0;
    unsigned i;

    *address = 0;
    *prefix = 32;

    if (t->offset >= t->length)
        return false;
    
    /* Make sure there is at least one number [0..255] */
    for (i=0; i<4; i++) {
        if (!isdigit(px[offset]))
            return false;
        x = px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        *address <<= 8;
        *address |= x;
        if (x > 255)
            return false;
        if (i < 3) {
            if (px[offset] != '.')
                break;
            else
                offset++;
        }
    }

    if (offset < length && px[offset] == '/') {
        while (i < 4) {
            *address <<= 8;
            i++;
        }

        if (!isdigit(px[offset]))
            return false;
        x = px[offset++] - '0';
        if (offset < length && isdigit(px[offset]))
            x = x * 10 + px[offset++] - '0';
        *prefix = x;
        if (x > 32)
            return false;
    } else if (i != 4) {
        /* if not CIDR, then must have 4 numbers */
        return false;
    }

    t->offset += offset;

    c__skip_whitespace(t);
    return true;
}

/******************************************************************************
 ******************************************************************************/
bool
c__next_uint32(struct ConfText *t, unsigned *number)
{
    const unsigned char *px = (const unsigned char *)t->buf + t->offset;
    size_t length = t->length - t->offset;
    size_t offset = 0;

    *number = 0;

    if (t->offset >= t->length)
        return false;
    
    if (!isdigit(px[offset]))
        return false;
        
    while (offset < length && isdigit(px[offset])) {
        unsigned char c = px[offset];
        if (*number > 0xFFFFFFFF/10)
            return false;
        else if (*number * 10 < (0xFFFFFFFF + (c - '0')))
            return false;
        *number = (*number) * 10 + (c - '0');
        offset++;
    }

    t->offset += offset;

    c__skip_whitespace(t);
    return true;
}


/******************************************************************************
 ******************************************************************************/
bool
c__next_boolean(struct ConfText *t)
{
    struct Keyword kw;
    
    kw = c__next_keyword(t);
    if (t->is_error)
        return false;

    c__skip_whitespace(t);


    if (kw_is_equals(kw, "yes") 
        || kw_is_equals(kw, "true")
        || kw_is_equals(kw, "1"))
        return true;
    else if (kw_is_equals(kw, "no")
        || kw_is_equals(kw, "false")
        || kw_is_equals(kw, "0"))
        return false;
    else {
        CONF_ERROR(t, "invalid boolean value\n");
        return false;
    }
}