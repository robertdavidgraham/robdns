#ifndef ADAPTER_H
#define ADAPTER_H
#include "packet.h"
#include <time.h>
struct Thread;
struct Adapter;

typedef struct Packet (*ALLOC_PACKET)(struct Adapter *, struct Thread *);
typedef void (*XMIT_PACKET)(struct Adapter *, struct Thread *, struct Packet *);


struct Adapter
{
    ALLOC_PACKET alloc_packet;
    XMIT_PACKET xmit_packet;
    void *userdata;

    struct {
	    unsigned char address[6];
    } mac[1];

    unsigned ipv4_count;
    struct {
	    unsigned address;
        unsigned mask;
    } ipv4[8];


    /**
     * The maximum length we can transmit. This will be set before the
     * adapter is open. It can also be:
     * - 1514 for normal Ethernet
     * - 1518 for 802.11q Ethernet
     * - 1600 for baby giant Ethernet
     * - 7935 for WiFi
     * - 9000 for jumbo frames
     * - 65536 for super jumbo frames (the max possible)
     */
    unsigned frame_size;

    unsigned ipv6_count;
    struct {
        unsigned char address[16];
        unsigned char mask[16];
    } ipv6[8];

    struct pcap_t *pcap;
    struct pcap_send_queue *sendq;
    struct pfring *ring;

};

int adapter_has_ipv4(const struct Adapter *adapter, unsigned ipv4);

struct Adapter *adapter_create(ALLOC_PACKET alloc_packet, XMIT_PACKET xmit_packet, void *userdata);
void adapter_destroy(struct Adapter *adapter);
struct Packet adapter_create_request_udp(struct Adapter *adapter, unsigned ip_dst, unsigned port_dst);
void adapter_xmit(struct Adapter *adapter, struct Thread *thread, struct Packet *packet);
void adapter_add_ipv4(struct Adapter *adapter, unsigned ipv4_address, unsigned mask);

#endif
