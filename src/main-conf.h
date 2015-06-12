#ifndef MAIN_CONF_H
#define MAIN_CONF_H
#include <stdint.h>
#include "adapter.h"
struct Core
{
    struct Catalog *db;


    struct {
        char ifname[256];
        struct Adapter *adapter;
        unsigned adapter_ip;
        unsigned char adapter_ipv6[16];
        unsigned adapter_port;
        unsigned char adapter_mac[6];
        unsigned char router_mac[6];
    } nic[8];
    unsigned nic_count;

    unsigned is_pfring:1;
    unsigned is_sendq:1;
    unsigned is_offline:1;
    unsigned is_packet_trace:1;
    unsigned is_zonefile_benchmark:1;
    unsigned is_zonefile_check:1;

    unsigned insertion_threads;

    char working_directory[512];

    /*
     * Zonefile list. During the configuration phase,
     * we build up a list of zonefiles that need to be 
     * parsed. After configuration, but before the 
     * server starts, we read in all the zonefiles
     * and insert their contents into the db.
     */
    struct {
        uint64_t total_bytes;
        uint64_t total_files;

        size_t length;
        size_t max;
        char *names;
    } zonefiles;


};

/**
 * Initialize a configuration structure
 */
void conf_init(struct Core *conf);

/**
 * Read configuration information from a file
 */
void conf_read_config_file(struct Core *conf, const char *filename);

/**
 * Read configuration information from the command-line
 */
void conf_command_line(struct Core *conf, int argc, char *argv[]);

/**
 * Once all configuration information has been read, then
 * read in all the zonefiles
 */
enum SuccessFailure
conf_zonefiles_parse(   struct Catalog *db, 
                        struct Core *conf);


#endif
