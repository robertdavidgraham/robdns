#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdarg.h>

/******************************************************************************
 ******************************************************************************/
struct Filenames {
    char **list;
    size_t count;
    size_t capacity;
};

struct ConfText {
    const char *buf;
    const char *filename;
    size_t offset;
    size_t length;
    unsigned line_number;
    unsigned is_error:1;
};

/******************************************************************************
 ******************************************************************************/
struct String
{
    char *str;
    size_t length;
    size_t capacity;
};
struct Keyword
{
    const char *str;
    size_t length;
};

enum Conf_ZoneType {Type_Master, Type_Slave};

/******************************************************************************
 ******************************************************************************/
struct Conf_Zone
{
    struct String name;
    struct String file;
    enum Conf_ZoneType type;
    bool is_notify;
};
struct Conf_ZoneList
{
    struct Conf_Zone *list;
    size_t count;
    size_t capacity;
};

/******************************************************************************
 ******************************************************************************/
struct Config
{
    struct Filenames filenames;
    struct Conf_ZoneList zones;
};


/******************************************************************************
 ******************************************************************************/
static int
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


/**
 * Add name to the list of files that need to be tracked in order to figure
 * out if a configuration file has changed
 */
void
conf_filename_add(struct Config *conf, const char *filename)
{
    struct Filenames *x = &conf->filenames;
    size_t i;
    
    /* don't add the same filename twice */
    for (i=0; i<x->count; i++) {
        if (strcmp(x->list[i], filename) == 0)
            return;
    }
    
    /* expand if necessary */
    if (x->count + 1 >= x->capacity) {
        x->capacity = x->capacity * 2 + 1;
        
        if (x->list) {
            x->list = realloc(x->list,
                              x->capacity * sizeof(x->list[0]));
        } else {
            x->list = malloc(x->capacity * sizeof(x->list[0]));
        }
    }
    
    x->list[x->count++] = strdup(filename);
}
struct Conf_Zone *
conf_zone_add(struct Conf_ZoneList *x, struct String s)
{
    
    /* expand if necessary */
    if (x->count + 1 >= x->capacity) {
        x->capacity = x->capacity * 2 + 1;
        if (x->list) {
            x->list = realloc(x->list,
                              x->capacity * sizeof(x->list[0]));
        } else {
            x->list = malloc(x->capacity * sizeof(x->list[0]));
        }
    }
    
    memset(&x->list[x->count], 0, sizeof(x->list[0]));
    x->list[x->count].name.str = malloc(s.length + 1);
    memcpy(x->list[x->count].name.str, s.str, s.length + 1);
    return &x->list[x->count++];
}
bool
str_is_equal(struct String lhs, struct String rhs)
{
    if (lhs.length != rhs.length)
        return false;
    return memcmp(lhs.str, rhs.str, rhs.length) == 0;
}
bool
kw_is_equal(const struct Keyword lhs, const struct Keyword rhs)
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

struct Conf_Zone *
conf_zone_lookup(struct Conf_ZoneList *x, struct String s)
{
    size_t i;
    for (i=0; i<x->count; i++) {
        if (str_is_equal(x->list[i].name, s))
            return &x->list[i];
    }
    return NULL;
}

/******************************************************************************
 * skips both whitespace and comments
 ******************************************************************************/
int
skip_whitespace(struct ConfText *t)
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
static struct Keyword
next_keyword(struct ConfText *t)
{
    struct Keyword kw;
    
    skip_whitespace(t);
    
    kw.str = t->buf + t->offset;
    for (kw.length = 0; t->offset + kw.length < t->length; kw.length++) {
        char c = t->buf[t->offset + kw.length];
        if (!isalnum(c&0xFF) && c != '-' && c != '_')
            break;
    }
    
    t->offset += kw.length;
    return kw;
}

void
str_append(struct String *s, const char *rhs, size_t rhs_length)
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
static struct String
parse_string(struct ConfText *t)
{
    struct String s;
    
    memset(&s, 0, sizeof(s));
    
    skip_whitespace(t);
    
    if (t->offset >= t->length || t->buf[t->offset++] != '\"') {
        fprintf(stderr, "%s:%u: expected \" to start string\n",
                t->filename, t->line_number);
        t->is_error = 1;
        return s;
    }
    
    while (t->offset < t->length && t->buf[t->length] != '\"') {
        str_append(&s, t->buf + t->length, 1);
        
        t->length++;
    }
    
    while (t->offset < t->length && t->buf[t->length] == '\"')
        t->length++;
    
    skip_whitespace(t);
    
    return s;
}

/******************************************************************************
 ******************************************************************************/
bool
parse_brace(struct ConfText *t)
{
    skip_whitespace(t);
    
    if (t->offset >= t->length || t->buf[t->offset] != '{') {
        fprintf(stderr, "%s:%u: expected brace {, found something else\n",
                t->filename, t->line_number);
        return false;
    }
    
    t->offset++;
    
    skip_whitespace(t);
    
    return true;
}

bool
parse_endbrace(struct ConfText *t)
{
    skip_whitespace(t);
    
    if (t->offset >= t->length || t->buf[t->offset] != '}') {
        fprintf(stderr, "%s:%u: expected end brace }, found something else\n",
                t->filename, t->line_number);
        return false;
    }
    
    t->offset++;
    
    skip_whitespace(t);
    
    return true;
}

bool
parse_semicolon(struct ConfText *t)
{
    skip_whitespace(t);
    
    if (t->offset >= t->length || t->buf[t->offset] != '}') {
        fprintf(stderr, "%s:%u: expected semicolon ; found something else\n",
                t->filename, t->line_number);
        return false;
    }
    
    t->offset++;
    
    skip_whitespace(t);
    
    return true;
}


/******************************************************************************
 ******************************************************************************/
static int
parse_zone(struct Config *conf, struct ConfText *t)
{
    struct String s;
    struct Conf_Zone *zone;
    
    s = parse_string(t);
    if (t->is_error)
        return -1;
    
    zone = conf_zone_lookup(&conf->zones, s);
    if (zone == NULL)
        zone = conf_zone_add(&conf->zones, s);
    
    if (!parse_brace(t))
        return -1;
    
    while (t->offset < t->length && t->buf[t->offset] != '}') {
        struct Keyword kw = next_keyword(t);
        
        if (kw_is_equals(kw, "type")) {
            kw = next_keyword(t);
            if (kw_is_equals(kw, "master"))
                zone->type = Type_Master;
            else if (kw_is_equals(kw, "slave"))
                zone->type = Type_Slave;
            else 
                return CONF_ERROR(t, "zone type unknown\n");
            
        } else if (kw_is_equals(kw, "file")) {
            zone->file = parse_string(t);
            if (t->is_error)
                return CONF_ERROR(t, "zone file corrupt\n");
        } else if (kw_is_equals(kw, "notify")) {
            kw = next_keyword(t);
            if (kw_is_equals(kw, "yes"))
                zone->is_notify = true;
            else if (kw_is_equals(kw, "no"))
                zone->is_notify = false;
            else
                return CONF_ERROR(t, "zone notify unknown\n");
        } else {
            return CONF_ERROR(t, "zone unknown statement\n");
        }
        
        skip_whitespace(t);
    }
    
    if (!parse_endbrace(t))
        return -1;
    return 0;
}

/******************************************************************************
 ******************************************************************************/
int
conf_parse(struct Config *conf, const char *filename, const char *buf, size_t length)
{
    struct ConfText t[1];
    
    memset(t, 0, sizeof(t[0]));
    
    t->offset = 0;
    t->length = length;
    t->buf = buf;
    t->filename = filename;
    
    
    while (t->offset < t->length && !t->is_error) {
        struct Keyword kw = next_keyword(t);
        
        if (kw_is_equals(kw, "zone"))
            parse_zone(conf, t);
        else {
            return CONF_ERROR(t, "zone unknown statement\n");
        }
        
    }
    
    if (t->is_error)
        return -1;
    else 
        return 0;
}


/******************************************************************************
 ******************************************************************************/
int
conf_read(struct Config *conf, const char *filename)
{
    char *buf;
    FILE *fp;
    struct stat s;
    size_t bytes_read;
    
    /* Remember this filename so that when we are told to reload the
     * the configuration that we can check on the status. Also, we
     * use this to prevent an infinite loop */
    conf_filename_add(conf, filename);
    
    /* open the next configuration file */
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror(filename);
        return -1;
    }
    
    /* fixme: lock the file */
    
    /* Find the size of the file */
    if (fstat(fileno(fp), &s) != 0) {
        perror(filename);
        fclose(fp);
        return -1;
    }
    if (s.st_size == 0) {
        fprintf(stderr, "%s: empty file\n", filename);
        fclose(fp);
        return -1;
    }
    
    /* allocate a buffer to hold the file */
    buf = malloc(s.st_size);
    if (buf == NULL) {
        fprintf(stderr, "%s: out of memory\n", filename);
        fclose(fp);
        return -1;
    }
    
    /* read the entire file into memory */
    bytes_read = fread(buf, 1, s.st_size, fp);
    if (bytes_read != s.st_size) {
        fprintf(stderr, "%s: error reading file\n", filename);
        if (bytes_read == 0)
            perror(filename);
        fclose(fp);
        return -1;
    }
    
    /* now that we've read in the entire file, we can safely close it*/
    fclose(fp);
    
    /* now we can parse the file */
   
    return 0;
}


/******************************************************************************
 ******************************************************************************/
static const char *test_cfg = 
"zone \"0.0.127.in-addr.arpa\" {\n"
"    type master;\n"
"    file \"localhost.rev\";\n"
"    notify no;\n"
"};\n"
"// We are the master server for example.com\n"
"zone \"example.com\" {\n"
"    type master;\n"
"    file \"example.com.db\";\n"
"    # IP addresses of slave servers allowed to\n"
"    /* transfer example.com\n"
"    */\n"
"    allow-transfer {\n"
"        192.168.4.14;\n"
"        192.168.5.53;\n"
"    };\n"
"};\n"
"// We are a slave server for eng.example.com\n"
"zone \"eng.example.com\" {\n"
"    type slave;\n"
"    file \"eng.example.com.bk\";\n"
"    // IP address of eng.example.com master server\n"
"    masters { 192.168.4.12; };\n"
"};\n"
;


/******************************************************************************
 ******************************************************************************/
int
conf_selftest(void)
{
    struct Config conf[1];
    memset(conf, 0, sizeof(conf[0]));
    conf_parse(conf, "<test>", test_cfg, sizeof(test_cfg));
    return 0;
}
