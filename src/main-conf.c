#include "main-conf.h"
#include "string_s.h"
#include "logger.h"
#include "util-ipaddr.h"
#include "zonefile-parse.h"
#include "zonefile-load.h"
#include "success-failure.h"
#include "pixie.h"
#include "pixie-nic.h"
#include "pixie-timer.h"
#include <ctype.h>
#include <limits.h>
#include <stdint.h>

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
 * This function parses the zone-file. Since parsing can take a long time,
 * such as when reading the .com file, we print status indicating how long
 * things are taking.
 ****************************************************************************/
static enum Status
parse_zone_file(struct Catalog *db, const char *filename, struct Core *conf)
{
    struct ZoneFileParser *parser;
    FILE *fp;
    int err;
    uint64_t filesize;
    uint64_t total_read = 0;
    uint64_t last_printed = 0;
    static const struct DomainPointer root = {(const unsigned char*)"\0",1};
    uint64_t start, stop;



    /*
     * Open the file
     */
    err = fopen_s(&fp, filename, "rb");
    if (err || fp == NULL) {
        perror(filename);
        return Failure;
    }

    /*
     * Get the size of the file
     * TODO: there is a TOCTOU race condition here
     */
    filesize = pixie_get_filesize(filename);
    if (filesize == 0) {
        LOG(0, "%s: file is empty\n", filename);
        fclose(fp);
        return Failure;
    }

    /*
     * Start the parsing
     */
    if (conf->is_zonefile_benchmark) {
        fprintf(stderr, "benchmarking...\n");
        parser = zonefile_begin(
                root, 
                60, filesize,             
                filename, 
                zonefile_benchmark,
                db,
                0
                );
    } else {
        parser = zonefile_begin(
                root, 
                60, filesize,             
                filename, 
                zonefile_load, 
                db,
                conf->insertion_threads
                );
    }

    /*
     * Continue parsing the file until end, reporting progress as we
     * go along
     */
    start = pixie_gettime();
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

        total_read += bytes_read;
        if (total_read > last_printed + 400*1000*1000) {
            double percent_done = (total_read*100.0)/filesize;
            fprintf(stderr, "%2.1f%% done, %12llu mbytes read\r", percent_done, total_read/(1024ULL*1024ULL));
            last_printed = total_read;
        }
    }
    stop = pixie_gettime();
    fclose(fp);

    /*
     * If benchmarking
     */
    {
        double rate = ((1.0*total_read)/(stop-start))*1.0;
        printf("elapsed: %02u:%02u (minutes:seconds)\n",
            (unsigned)((stop-start)/(60*1000000)),
            (unsigned)(((stop-start)/(1000000))%60)
            );

        printf("parse-speed: %5.3f-megabytes/second\n", rate);
        if (conf->is_zonefile_benchmark) 
            exit(0);
    }


    if (zonefile_end(parser) == Success) {
        fprintf(stderr, "%s: success\n", filename);
        return Success;
    } else {
        fprintf(stderr, "%s: failure\n", filename);
        return Failure;
    }

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
 * Echoes the configuration for one nic
 ***************************************************************************/
static void
conf_echo_nic(struct Core *conf, FILE *fp, unsigned i)
{
    char zzz[64];

    /* If we have only one adapter, then don't print the array indexes.
     * Otherwise, we need to print the array indexes to distinguish
     * the NICs from each other */
    if (conf->nic_count <= 1)
        zzz[0] = '\0';
    else
        sprintf_s(zzz, sizeof(zzz), "[%u]", i);

    fprintf(fp, "adapter%s = %s\n", zzz, conf->nic[i].ifname);
    fprintf(fp, "adapter-ip%s = %u.%u.%u.%u\n", zzz,
        (conf->nic[i].adapter_ip>>24)&0xFF,
        (conf->nic[i].adapter_ip>>16)&0xFF,
        (conf->nic[i].adapter_ip>> 8)&0xFF,
        (conf->nic[i].adapter_ip>> 0)&0xFF
        );
    fprintf(fp, "adapter-mac%s = %02x:%02x:%02x:%02x:%02x:%02x\n", zzz,
            conf->nic[i].adapter_mac[0],
            conf->nic[i].adapter_mac[1],
            conf->nic[i].adapter_mac[2],
            conf->nic[i].adapter_mac[3],
            conf->nic[i].adapter_mac[4],
            conf->nic[i].adapter_mac[5]);
    fprintf(fp, "router-mac%s = %02x:%02x:%02x:%02x:%02x:%02x\n", zzz,
            conf->nic[i].router_mac[0],
            conf->nic[i].router_mac[1],
            conf->nic[i].router_mac[2],
            conf->nic[i].router_mac[3],
            conf->nic[i].router_mac[4],
            conf->nic[i].router_mac[5]);

}

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all setable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
void
conf_echo(struct Core *conf, FILE *fp)
{
    unsigned i;

    fprintf(fp, "# ADAPTER SETTINGS\n");
    if (conf->nic_count == 0)
        conf_echo_nic(conf, fp, 0);
    else {
        for (i=0; i<conf->nic_count; i++)
            conf_echo_nic(conf, fp, i);
    }
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
static int
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
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
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
conf_set_parameter(struct Core *conf, const char *name, const char *value)
{
    unsigned index = ARRAY(name);
    if (index >= 8) {
        fprintf(stderr, "%s: bad index\n", name);
        exit(1);
    }

    if (EQUALS("conf", name) || EQUALS("config", name)) {
        conf_read_config_file(conf, value);
    } else if (EQUALS("zonefile-benchmark", name)) {
        conf->is_zonefile_benchmark = 1;
    } else if (EQUALS("insertion-threads", name) || EQUALS("insertion-thread", name)) {
        conf->insertion_threads = (unsigned)parseInt(value);
    } else if (EQUALS("adapter", name) || EQUALS("if", name) || EQUALS("interface", name)) {
        if (conf->nic[index].ifname[0]) {
            fprintf(stderr, "CONF: overwriting \"adapter=%s\"\n", conf->nic[index].ifname);
        }
        if (conf->nic_count < index + 1)
            conf->nic_count = index + 1;
        sprintf_s(  conf->nic[index].ifname, 
                    sizeof(conf->nic[index].ifname), 
                    "%s",
                    value);

    }
    else if (EQUALS("adapter-ip", name) || EQUALS("source-ip", name) 
             || EQUALS("source-address", name) || EQUALS("spoof-ip", name)
             || EQUALS("spoof-address", name)) {
            struct ParsedIpAddress ipaddr;
            int x;

            x = parse_ip_address(value, 0, 0, &ipaddr);
            if (!x) {
                fprintf(stderr, "CONF: bad source IPv4 address: %s=%s\n", 
                        name, value);
                return;
            }

            if (ipaddr.version == 4) {
                conf->nic[index].adapter_ip = ipaddr.address[0]<<24 | ipaddr.address[1]<<16 | ipaddr.address[2]<<8 | ipaddr.address[3];
            } else {
                memcpy(conf->nic[index].adapter_ipv6, ipaddr.address, 16);
            }
    } else if (EQUALS("adapter-port", name) || EQUALS("source-port", name)) {
        /* Send packets FROM this port number */
        unsigned x = strtoul(value, 0, 0);
        if (x > 65535) {
            fprintf(stderr, "error: %s=<n>: expected number less than 1000\n", 
                    name);
        } else {
            conf->nic[index].adapter_port = x;
        }
    } else if (EQUALS("adapter-mac", name) || EQUALS("spoof-mac", name)
               || EQUALS("source-mac", name)) {
        /* Send packets FROM this MAC address */
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "CONF: bad MAC address: %s=%s\n", name, value);
            return;
        }

        memcpy(conf->nic[index].adapter_mac, mac, 6);
    }
    else if (EQUALS("router-mac", name) || EQUALS("router", name)) {
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "CONF: bad MAC address: %s=%s\n", name, value);
            return;
        }

        memcpy(conf->nic[index].router_mac, mac, 6);
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

/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void
conf_command_line(struct Core *conf, int argc, char *argv[])
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

                conf_set_parameter(conf, name2, value);
            }
            continue;
        }

        /* For for a single-dash parameter */
        else if (argv[i][0] == '-') {
            const char *arg;

            switch (argv[i][1]) {
            case 'i':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                conf_set_parameter(conf, "adapter", arg);
                break;
            case 'h':
            case '?':
                conf_usage();
                break;
            default:
                LOG(0, "FAIL: unknown option: -%s\n", argv[i]);
                LOG(0, " [hint] try \"--help\"\n");
                LOG(0, " [hint] ...or, to list nmap-compatible options, try \"--nmap\"\n");
                exit(1);
            }
            continue;
        }
        else if (ends_with(argv[i], ".zone"))
            parse_zone_file(conf->db, argv[i], conf);
        else if (parse_ip_address(argv[i], 0, 0, &ipaddr)) {
            conf_set_parameter(conf, "adapter-ip", argv[i]);
        } else if (pixie_nic_exists(argv[i])) {
            strcpy_s(conf->nic[0].ifname, sizeof(conf->nic[0].ifname), argv[i]);
        } else {
            LOG(0, "%s: unknown command-line parameter\n", argv[i]);
        }

    }
}

/***************************************************************************
 * remove leading/trailing whitespace
 ***************************************************************************/
static void
trim(char *line)
{
    while (isspace(*line & 0xFF))
        memmove(line, line+1, strlen(line));
    while (isspace(line[strlen(line)-1] & 0xFF))
        line[strlen(line)-1] = '\0';
}

/***************************************************************************
 ***************************************************************************/
void
conf_read_config_file(struct Core *conf, const char *filename)
{
    FILE *fp;
    errno_t err;
    char line[65536];

    err = fopen_s(&fp, filename, "rt");
    if (err) {
        perror(filename);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *name;
        char *value;

        trim(line);

        if (ispunct(line[0] & 0xFF) || line[0] == '\0')
            continue;

        name = line;
        value = strchr(line, '=');
        if (value == NULL)
            continue;
        *value = '\0';
        value++;
        trim(name);
        trim(value);

        conf_set_parameter(conf, name, value);
    }

    fclose(fp);
}
