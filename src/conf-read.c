#include "config.h"
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#if defined(WIN32)
#define strdup _strdup
#define fileno _fileno
#endif




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
        struct Keyword kw = c__next_keyword(t);
        
        if (kw_is_equals(kw, "zone"))
            conf_zone_parse(conf, t);
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
    int x;
    
    /* Remember this filename so that when we are told to reload the
     * the configuration that we can check on the status. Also, we
     * use this to prevent an infinite loop */
    conf_filename_add(conf, filename);
    
    /* open the next configuration file */
    x = fopen_s(&fp, filename, "rb");
    if (x) {
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
    conf_parse(conf, "<test>", test_cfg, strlen(test_cfg));
    return 0;
}
