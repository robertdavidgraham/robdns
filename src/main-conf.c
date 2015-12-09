#include "main-conf.h"
#include "db.h"
#include "conf-trackfile.h"
#include "configuration.h"
#include "string_s.h"
#include "logger.h"
#include "util-ipaddr.h"
#include "zonefile-parse.h"
#include "zonefile-load.h"
#include "success-failure.h"
#include "pixie.h"
#include "pixie-nic.h"
#include "pixie-timer.h"
#include "pixie-threads.h"
#include "util-realloc2.h"
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>

/****************************************************************************
 * This function parses the zone-file. Since parsing can take a long time,
 * such as when reading the .com file, we print status indicating how long
 * things are taking.
 ****************************************************************************/
enum SuccessFailure
zonefile_benchmark(
        struct DomainPointer domain,
        struct DomainPointer origin,
	    unsigned type,
        unsigned ttl,
        unsigned rdlength,
        const unsigned char *rdata,
        uint64_t filesize,
	    void *userdata,
        const char *filename,
        unsigned line_number)
{
    return Success;
}

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
 ****************************************************************************/
static char *
combine_filename(const char *dirname, const char *filename)
{
    size_t dirname_len = strlen(dirname);
    size_t filename_len = strlen(filename);
    char *xfilename = REALLOC2(0, 1, dirname_len + filename_len + 2);

    memcpy(xfilename, dirname, dirname_len);

    while (dirname_len && (xfilename[dirname_len-1] == '/' || xfilename[dirname_len-1] == '\\'))
        dirname_len--;

    xfilename[dirname_len++] = '/';
    memcpy(xfilename + dirname_len, filename, filename_len);
    xfilename[dirname_len + filename_len] = '\0';

    return xfilename;
}





/****************************************************************************
 ****************************************************************************/
struct XParseThread {
    struct Catalog *db_load;
    size_t start_index;
    size_t end_index;
    enum SuccessFailure status;
    size_t thread_handle;
    uint64_t total_bytes;
    uint64_t total_files;
    struct Configuration *cfg;
};

/****************************************************************************
 ****************************************************************************/
static void
conf_zonefiles_parse_thread(void *v)
{
    struct XParseThread *p = (struct XParseThread *)v;
    struct Catalog *db = p->db_load;
    struct Configuration *cfg = p->cfg;
    struct ZoneFileParser *parser;
    static const struct DomainPointer root = {(const unsigned char*)"\0",1};
    size_t directory_index;
    size_t file_index;
    size_t current_index;

    fflush(stderr);
    fflush(stdout);


    /*
     * Start the parsing
     */
    parser = zonefile_begin(
                root, 
                60, 128,
                cfg->options.directory,
                zonefile_load, 
                db,
                cfg->insertion_threads
                );

    /*
     * Find the starting point. This converts the single
     * integer number into a [directory, file] index pair.
     */
    current_index = 0;
    for (directory_index = 0; directory_index < cfg->zonedirs_length; directory_index++) {
        struct Cfg_ZoneDir *zonedir = cfg->zonedirs[directory_index];
        current_index += zonedir->file_count;
        if (current_index >= p->start_index)
            break;
    }
    file_index = current_index - p->start_index;


    
    /*
     * 'for all zonefiles in this directory...'
     */
    if (directory_index < cfg->zonedirs_length)
    while (current_index < p->end_index) {
        const char *filename;
        FILE *fp;
        int err;
        uint64_t filesize;
        struct Cfg_ZoneDir *zonedir;
        
        /* If we've gone past the end of this directory,
         * then start parsing the next directory */
        zonedir = cfg->zonedirs[directory_index];
        if (file_index >= zonedir->file_count) {
            file_index = 0;
            directory_index++;
            if (directory_index >= cfg->zonedirs_length)
                break;
            zonedir = cfg->zonedirs[directory_index];
        }

        filename = zonedir->files[file_index].filename;
        filesize = zonedir->files[file_index].size;
        current_index++;
        file_index++;

        /*
         * Open the file
         */
        fflush(stdout);
        fflush(stderr);
        err = fopen_s(&fp, filename, "rb");
        if (err || fp == NULL) {
            perror(filename);
            p->status = Failure;
            return;
        }
        p->total_bytes += filesize;

        /*
         * Set parameters
         */
        zonefile_begin_again(
            parser,
            root,   /* . domain origin */
            60,     /* one minute ttl */
            filesize, 
            filename);

        /*
         * Continue parsing the file until end, reporting progress as we
         * go along
         */
        for (;;) {
            unsigned char buf[65536];
            size_t bytes_read;

            bytes_read = fread((char*)buf, 1, sizeof(buf), fp);
            if (bytes_read == 0)
                break;

            zonefile_parse(
                parser,
                buf,
                bytes_read
                );

        }
        fclose(fp);
    }

    /* We are done parsing the directories. Now let's parse
     * the individual zonefiles */
    while (current_index < p->end_index) {
        const char *filename;
        FILE *fp;
        int err;
        uint64_t filesize;
        struct Cfg_Zone *zone;
        
        if (file_index >= cfg->zones_length)
            break;
        zone = cfg->zones[file_index];

        filename = zone->file;
        filesize = zone->file_size;
        current_index++;
        file_index++;

        /*
         * Open the file
         */
        fflush(stdout);
        fflush(stderr);
        err = fopen_s(&fp, filename, "rb");
        if (err || fp == NULL) {
            perror(filename);
            p->status = Failure;
            return;
        }
        p->total_bytes += filesize;

        /*
         * Set parameters
         */
        zonefile_begin_again(
            parser,
            root,   /* . domain origin */
            60,     /* one minute ttl */
            filesize, 
            filename);

        /*
         * Continue parsing the file until end, reporting progress as we
         * go along
         */
        for (;;) {
            unsigned char buf[65536];
            size_t bytes_read;

            bytes_read = fread((char*)buf, 1, sizeof(buf), fp);
            if (bytes_read == 0)
                break;

            zonefile_parse(
                parser,
                buf,
                bytes_read
                );

        }
        fclose(fp);
    }

    if (zonefile_end(parser) == Success) {
        p->status = Success;
    } else {
        fprintf(stderr, "%s: failure\n", "");
        p->status = Failure;
    }
}

/****************************************************************************
 ****************************************************************************/
enum SuccessFailure
conf_zonefiles_parse(   struct Catalog *db_load,
                        struct Configuration *cfg,
                        uint64_t *out_total_files,
                        uint64_t *out_total_bytes)
{
    struct XParseThread p[16];
    size_t exit_code;
    size_t parse_thread_count = 4;
    size_t i;
    size_t start_index;
    enum SuccessFailure status = Success;
    size_t in_total_files;

    //LOG(2, "loading %llu zonefiles\n", conf->zonefiles.total_files);

    /*
     * Make sure we have some zonefiles to parse
     */
    in_total_files = cfg->zones_length + cfg->zonedirs_filecount;
    if (in_total_files == 0)
        return Failure; /* none found */

    /* The parser threads are heavy-weight, so therefore
     * we shouldn't have a lot of them unless we have
     * a lot of files to parse */
    if (in_total_files < 10)
        parse_thread_count = 1;
    else if (in_total_files < 5000)
        parse_thread_count = 2;
    else
        parse_thread_count = 4;
    

    /*
     * Divide the list of names into equal sized chunks,
     * and launch a parsing thread for each one. The primary 
     * optimization that's happening here is that that each
     * of the threads will stall waiting for file I/O, during
     * which time other threads can be active. Each individual
     * file can be parsed with only a single thread, of course,
     * because zonefiles are stateful. However, two unrelated
     * files can be parsed at the same time.
     */
    start_index = 0;
    for (i=0; i<parse_thread_count; i++) {
        size_t end_index;

        if (start_index >= in_total_files) {
            parse_thread_count = i;
            break;
        }

        /*
         * Figure out the index
         */
        end_index = start_index + in_total_files/parse_thread_count;

        p[i].db_load = db_load;
        p[i].start_index = start_index;
        p[i].end_index = end_index;
        p[i].cfg = cfg;
        p[i].total_bytes = 0;
        p[i].total_files = 0;

        if (parse_thread_count > 1) {
            p[i].thread_handle = pixie_begin_thread(conf_zonefiles_parse_thread, 0, &p[i]);
        } else {
            p[i].thread_handle = 0;
            conf_zonefiles_parse_thread(p);
        }

        start_index = end_index;
    }

    /*
     * Wait for them all to end, and collect statistics.
     */
    for (i=0; i<parse_thread_count; i++) {
        pixie_join(p[i].thread_handle, &exit_code);
        *out_total_bytes += p[i].total_bytes;
        *out_total_files = p[i].total_files;
        if (p[i].status != Success)
            status = Failure;
    }

    return status;
}


/***************************************************************************
 ***************************************************************************/
static void conf_usage(void)
{
    printf("usage:\n");
    printf("robdns <zone-file> <conf-file> <ip-address>\n");
    exit(1);
}


/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all setable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
void
conf_echo(struct Core *conf, FILE *fp)
{
#if 0
    unsigned i;
    fprintf(fp, "# ADAPTER SETTINGS\n");
    if (conf->nic_count == 0)
        conf_echo_nic(conf, fp, 0);
    else {
        for (i=0; i<conf->nic_count; i++)
            conf_echo_nic(conf, fp, i);
    }
#endif
}


/***************************************************************************
 ***************************************************************************/
static unsigned
hexval(char c)
{
    if ('0' <= c && c <= '9')
        return (unsigned)(c - '0');
    if ('a' <= c && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    if ('A' <= c && c <= 'F')
        return (unsigned)(c - 'A' + 10);
    return 0xFF;
}

/***************************************************************************
 ***************************************************************************/
int
parse_mac_address(const char *text, unsigned char *mac)
{
    unsigned i;

    for (i=0; i<6; i++) {
        unsigned x;
        char c;

        while (isspace(*text & 0xFF) && ispunct(*text & 0xFF))
            text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x = hexval(c)<<4;
        text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x |= hexval(c);
        text++;

        mac[i] = (unsigned char)x;

        if (ispunct(*text & 0xFF))
            text++;
    }

    return 0;
}

/***************************************************************************
 ***************************************************************************/
static uint64_t
parseInt(const char *str)
{
    uint64_t result = 0;

    while (*str && isdigit(*str & 0xFF)) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

/***************************************************************************
 * Parses the number of seconds (for rotating files mostly). We do a little
 * more than just parse an integer. We support strings like:
 *
 * hourly
 * daily
 * Week
 * 5days
 * 10-months
 * 3600
 ***************************************************************************/
uint64_t
parseTime(const char *value)
{
    uint64_t num = 0;
    unsigned is_negative = 0;

    while (*value == '-') {
        is_negative = 1;
        value++;
    }

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]&0xFF) || isspace(value[0]&0xFF))
        value++;

    if (isalpha(value[0]&0xFF) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0]&0xFF)) {
    case 's':
        num *= 1;
        break;
    case 'm':
        num *= 60;
        break;
    case 'h':
        num *= 60*60;
        break;
    case 'd':
        num *= 24*60*60;
        break;
    case 'w':
        num *= 24*60*60*7;
        break;
    default:
        fprintf(stderr, "--rotate-offset: unknown character\n");
        exit(1);
    }
    if (num >= 24*60*60) {
        fprintf(stderr, "--rotate-offset: value is greater than 1 day\n");
        exit(1);
    }
    if (is_negative)
        num = 24*60*60 - num;

    return num;
}



/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused 
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
static int
EQUALS(const char *lhs, const char *rhs)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

static unsigned
ARRAY(const char *rhs)
{
    const char *p = strchr(rhs, '[');
    if (p == NULL)
        return 0;
    else
        p++;
    return (unsigned)parseInt(p);
}

/***************************************************************************
 * Called either from the "command-line" parser when it sees a --parm,
 * or from the "config-file" parser for normal options.
 ***************************************************************************/
void
conf_set_parameter(struct Configuration *cfg, const char *name, const char *value)
{
    unsigned index = ARRAY(name);
    if (index >= 8) {
        fprintf(stderr, "%s: bad index\n", name);
        exit(1);
    }

    if (EQUALS("conf", name) || EQUALS("config", name)) {
        cfg_parse_file(cfg, value);
    } else if (EQUALS("load-threads", name) || EQUALS("load-thread", name)) {
        cfg->loader.load_threads = (unsigned)parseInt(value);
    } else if (EQUALS("parse-threads", name) || EQUALS("parse-thread", name)) {
        cfg->loader.load_threads = (unsigned)parseInt(value);
    } else {
        fprintf(stderr, "CONF: unknown config option: %s=%s\n", name, value);
    }
}


void
conf_help()
{
    printf("TODO: this feature (providing help) not yet implemented\n");
    exit(1);
}

/***************************************************************************
 * Tests if the command-line option is a directory, in which case, we
 * need to read configuration files and zone-files from that directory
 ***************************************************************************/
static int
is_directory(const char *filename)
{
    struct stat s;

    if (stat(filename, &s) != 0)
        return 0; /* bad filenames not directories */

    return (s.st_mode & S_IFDIR) > 0;
}




/***************************************************************************
 ***************************************************************************/
static int
has_configuration(const char *dirname)
{
    void *x;
    int is_found = 0;

    x = pixie_opendir(dirname);
    if (x == NULL)
        return 0; /* no content */

    for (;;) {
        const char *filename;
        
        filename = pixie_readdir(x);
        if (filename == NULL)
            break;

        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
            continue;

        if (ends_with(filename, ".zone") || ends_with(filename, ".conf")) {
            is_found = 1;
            break;
        }

        {
            char *xdirname = combine_filename(dirname, filename);

            if (is_directory(xdirname))
                is_found = has_configuration(xdirname);

            free(xdirname);

            if (is_found)
                break;
        }
    }


    pixie_closedir(x);
    return is_found;
}


/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void
conf_command_line(struct Configuration *cfg, int argc, char *argv[])
{
    int i;
    struct ParsedIpAddress ipaddr;

    for (i=1; i<argc; i++) {

        /*
         * --name=value
         * --name:value
         * -- name value
         */
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            if (strcmp(argv[i], "--help") == 0)
                conf_help();
            else {
                char name2[64];
                char *name = argv[i] + 2;
                unsigned name_length;
                const char *value;

                value = strchr(&argv[i][2], '=');
                if (value == NULL)
                    value = strchr(&argv[i][2], ':');
                if (value == NULL) {
                    value = argv[++i];
                    name_length = (unsigned)strlen(name);
                } else {
                    name_length = (unsigned)(value - name);
                    value++;
                }

                if (i >= argc) {
                    fprintf(stderr, "%.*s: empty parameter\n", name_length, name);
                    break;
                }

                if (name_length > sizeof(name2) - 1) {
                    fprintf(stderr, "%.*s: name too long\n", name_length, name);
                    name_length = sizeof(name2) - 1;
                }

                memcpy(name2, name, name_length);
                name2[name_length] = '\0';

                conf_set_parameter(cfg, name2, value);
            }
            continue;
        }

        /* For for a single-dash parameter */
        else if (argv[i][0] == '-') {
            const char *arg;

            switch (argv[i][1]) {
            case 'c':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                //conf_trackfile_add(cfg->tf, argv[i]);
                cfg_parse_file(cfg, argv[i]);
                break;
            case 'd':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                if (arg[0] < '0' || '9' < arg[0])
                    LOG_ERR(C_CONFIG, "expected numeric debug level after -d option\n");
                else
                    verbosity = atoi(arg);
                break;
            case 'i':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                conf_set_parameter(cfg, "adapter", arg);
                break;
            case 'h':
            case '?':
                conf_usage();
                break;
            case 'v':
                verbosity++;
                break;
            default:
                LOG_ERR(C_CONFIG, "FAIL: unknown option: -%s\n", argv[i]);
                LOG_ERR(C_CONFIG, " [hint] try \"--help\"\n");
                exit(1);
            }
            continue;
        }
        else if (ends_with(argv[i], ".zone"))
            cfg_add_zonefile(cfg, argv[i]);
        else if (ends_with(argv[i], ".conf")) {
            //conf_trackfile_add(cfg->tf, argv[i]);
            cfg_parse_file(cfg, argv[i]);
        } else if (parse_ip_address(argv[i], 0, 0, &ipaddr)) {
            ;//conf_set_parameter(conf, "adapter-ip", argv[i]);
        } else if (pixie_nic_exists(argv[i])) {
            //strcpy_s(conf->nic[0].ifname, sizeof(conf->nic[0].ifname), argv[i]);
        } else if (is_directory(argv[i]) && has_configuration(argv[i])) {
            //directory_to_zonefile_list(conf, argv[i]);
        } else {
            LOG_ERR(C_CONFIG, "%s: unknown command-line parameter\n", argv[i]);
        }
    }

}



/***************************************************************************
 ***************************************************************************/
void 
core_init(struct Core *core)
{
    memset(core, 0, sizeof(*core));

    /*
     * Create two databases. One database is for loading new/changed
     * content. The other database is used by the running system, with
     * multiple thtreads querying it. Once loaded, changes will be moved
     * from the loading db to the running db in a thread-safe manner.
     * (This is similar to cfg_load/cfg_run).
     */
    core->db_load = catalog_create();
    core->db_run = catalog_create();

}

