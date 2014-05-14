#ifndef NETWRK_H
#define NETWRK_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <string.h>
#include "packet.h"
#include "proto-dns.h"

struct Catalog;

struct ARP_IncomingRequest
{
    unsigned is_valid;
	unsigned opcode;
  	unsigned hardware_type;
	unsigned protocol_type;
	unsigned hardware_length;
	unsigned protocol_length;
	unsigned ip_src;
	unsigned ip_dst;
	const unsigned char *mac_src;
	const unsigned char *mac_dst;
};

struct ICMP_IncomingRequest
{
    unsigned is_valid:1;
    unsigned is_checksum_checked:1;
    unsigned is_checksum_valid:1;
    unsigned type;
    unsigned code;
    unsigned payload_length;
    unsigned original_checksum;
    const unsigned char *payload;
};


struct Frame
{
	struct Adapter *adapter;
	struct Thread *thread;
    int net_protocol;
	const unsigned char *mac_src;
	const unsigned char *mac_dst;
	unsigned ethertype;
	unsigned secs;
	unsigned usecs;
	unsigned ip_ver;
	unsigned ip_src;
	unsigned ip_dst;
    unsigned ip_checksum_is_valid:1;
    unsigned port_src;
    unsigned port_dst;
    unsigned time_secs;
    unsigned time_usecs;
    struct DNS_Incoming dns[1];
    struct ARP_IncomingRequest arp[1];
    struct ICMP_IncomingRequest icmp[1];
};

enum {
    NET_NOTHING,
    NET_ETHERNET,
    NET_ARP,
    NET_IP,
    NET_ICMP,
    NET_UDP,
    NET_TCP,
    NET_DNS,
};


/* Create a response packet going the other way. There MUST be a matching
 * call to frame_xmit_response() to free resources */
struct Packet frame_create_response(struct Frame *frame, int protocol);

/* Transmit packet allocated by frame_create_response(). Set 'buf-length' to
 * zero to drop packet without sending it */
void frame_xmit_response(struct Frame *frame, struct Packet *packet);


/* How the DNS server receives DNS request packets */
void
network_receive(struct Frame *frame,
                struct Thread *thread,
                struct Adapter *adapter,
                unsigned secs,
                unsigned usecs,
			    const unsigned char *px,
                unsigned length);


void proto_ethernet_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max);
void proto_ip_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max);

void proto_arp_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max);
void proto_arp_process(struct Frame *frame, const struct ARP_IncomingRequest *arp);

void proto_icmp_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max);
void proto_icmp_process(struct Frame *frame, const struct ICMP_IncomingRequest *icmp);

void proto_udp_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max);

void proto_dns_process(const struct DNS_Incoming *dns,
                       const struct Catalog *catalog,
                       struct Packet *pkt);


void stack_send_ip(struct Frame *frame, const unsigned char px[], unsigned length, unsigned ip_dst);

#ifdef __cplusplus
}
#endif
#endif
