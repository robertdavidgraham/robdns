#ifndef MAIN_CONF_H
#define MAIN_CONF_H
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
};

void conf_read_config_file(struct Core *conf, const char *filename);
void conf_command_line(struct Core *conf, int argc, char *argv[]);


#endif
