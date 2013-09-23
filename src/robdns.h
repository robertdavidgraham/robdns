#ifndef ROBDNS_H
#define ROBDNS_H

/**
 * Configuration settings for the server
 */
struct RobDNS {
    int op;

    struct {
        char ifname[256];
        struct Adapter *adapter;
        unsigned adapter_ip;
        unsigned adapter_port;
        unsigned char adapter_mac[6];
        unsigned char router_mac[6];
    } nic[8];
    unsigned nic_count;

    unsigned is_pfring:1;       /* --pfring */
    unsigned is_sendq:1;        /* --sendq */
};

#endif
