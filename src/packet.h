#ifndef PACKET_H
#define PACKET_H

struct Packet
{
    unsigned char *buf;
    unsigned offset;
    unsigned max;
    struct {
        unsigned network;
        unsigned transport;
    } fixup;
};

#endif
