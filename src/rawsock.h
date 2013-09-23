/*
    raw sockets stuff
*/
#ifndef RAWSOCK_H
#define RAWSOCK_H
#include <stdio.h>
struct Packet;
struct Thread;

void
rawsock_init();

/**
 * Does an "open" on the network adapter. What actually happens depends upon
 * the operating system and drivers that we are using, but usually this just
 * calls "pcap_open()"
 * @param adapter_name
 *      The name of the adapter, like "eth0" or "dna1".
 * @param is_pfring
 *      Whether we should attempt to use the PF_RING driver (Linux-only)
 * @param is_sendq
 *      Whether we should attempt to use a ring-buffer for sending packets.
 *      Currently Windows-only, but it'll be enabled for Linux soon. Big
 *      performance gains for Windows, but insignificant performance 
 *      difference for Linux.
 * @param is_packet_trace
 *      Whether then Nmap --packet-trace option was set on the command-line
 * @param is_offline
 *      Whether the --offline parameter was set on the command-line. If so,
 *      then no network adapter will actually be opened.
 * @return
 *      a fully instantiated network adapter
 */
struct Adapter *
rawsock_init_adapter(const char *adapter_name, 
                     unsigned is_pfring, 
                     unsigned is_sendq,
                     unsigned is_packet_trace,
                     unsigned is_offline);

void rawsock_list_adapters();


const char *rawsock_win_name(const char *ifname);

int rawsock_is_adapter_names_equal(const char *lhs, const char *rhs);

void
rawsock_send_packet(struct Adapter *adapter, 
                        struct Thread *thread, 
                        struct Packet *pkt);

int rawsock_recv_packet(
    struct Adapter *adapter,
    unsigned *length,
    unsigned *secs,
    unsigned *usecs,
    const unsigned char **packet);


void rawsock_ignore_transmits(struct Adapter *adapter, const unsigned char *adapter_mac);

#endif
