#ifndef CONFIGURATION_ADAPTER_H
#define CONFIGURATION_ADAPTER_H

enum CoreSocketType {
    ST_Unknown, ST_IPv4, ST_IPv6, ST_Any, ST_Raw,
};

struct CoreSocketItem
{
    int fd;
    enum CoreSocketType type;
    unsigned proto;
    unsigned port;
    char *ifname;
    union {
        unsigned v4;
        unsigned char v6[16];
    } ip;
};

#endif