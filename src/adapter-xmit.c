/****************************************************************************
 * Transmission is a 3 step proces.
 * Step #1: grab a free buffer from the transmit queue
 * Step #2: compose the packet (DNS, UDP, IP, Ethernet)
 * Step #3: transmit the packet
 *
 * The first step is needed because an ideal driver pre-allocates its
 * transmit buffers. Therefore, instead of copying a packet into those 
 * buffers, or DMAing from outside those buffers, we compose a packet
 * directly in those buffers.
 *
 * The second step means that packet composition is backwards. Normally, 
 * usermode programs first compose the app layer, then transport layer,
 * then network layer, then link layer. We do the opposite. We build a
 * packet from the link-layer upwards, then append our stuff on top.
 *
 * Once we are done composing a packet, we always must transmit it. If an
 * error occurs and we decide after all that we don't want to transmit
 * the packet, we still must call the transmit function with a zero
 * length in order to tell it to free up the buffer.
 ****************************************************************************/
#include "network.h"
#include "adapter.h"
#include "thread.h"
#include <assert.h>

int
adapter_create_ipv4(struct Packet *pkt,
    int protocol,
    const unsigned char *mac_src,
    const unsigned char *mac_dst,
    unsigned ip_src,
    unsigned ip_dst,
    unsigned port_src,
    unsigned port_dst,
    unsigned ip_id)
{
    unsigned char *buf = pkt->buf;
	unsigned offset = pkt->offset;

	if (offset + 14 + 20 >= pkt->max)
		return 1;

	/*
     * Ethernet header: we simply swap the MAC addresses from the request
     * packet, copying the original <src> into outgoing <dst>, and likewise
     * original <dst> into outoing <src>
     */
	memcpy(buf+0, mac_dst, 6);
	memcpy(buf+6, mac_src, 6);
	buf[12] = 0x08;
	buf[13] = 0x00;
	offset += 14;
    if (protocol == NET_ETHERNET) {
	    buf[12] = 0x08;
	    buf[13] = 0x06; /* TODO: fix this kludge */
        pkt->offset = offset;
        pkt->fixup.network = offset;
        pkt->fixup.transport = offset;
        return 0;
    }
    /* TODO: 802.1q VLANs */


    /*
     * IP header: Create a temporary response header. After we finish building
     * the packet, we'll need to come back and re-do the length and checksum
     * fields.
     */
    pkt->fixup.network = offset;
	buf[offset+ 0] = 0x45;
	buf[offset+ 1] = 0;
	buf[offset+ 2] = (unsigned char)(0xFF);
	buf[offset+ 3] = (unsigned char)(0xFF);
	buf[offset+ 4] = (unsigned char)(ip_id>>8);
	buf[offset+ 5] = (unsigned char)(ip_id>>0);
	buf[offset+ 6] = 0; /* no fragmentation */
	buf[offset+ 7] = 0;
	buf[offset+ 8] = 255;
    switch (protocol) {
    case NET_UDP:
        buf[offset+ 9] = 17;
        break;
    default:
	    buf[offset+ 9] = 1;
    }
	buf[offset+10] = 0;
	buf[offset+11] = 0;
	buf[offset+12] = (unsigned char)(ip_src>>24);
	buf[offset+13] = (unsigned char)(ip_src>>16);
	buf[offset+14] = (unsigned char)(ip_src>> 8);
	buf[offset+15] = (unsigned char)(ip_src>> 0);
	buf[offset+16] = (unsigned char)(ip_dst>>24);
	buf[offset+17] = (unsigned char)(ip_dst>>16);
	buf[offset+18] = (unsigned char)(ip_dst>> 8);
	buf[offset+19] = (unsigned char)(ip_dst>> 0);

	offset += 20;
    if (protocol == NET_IP) {
        pkt->offset = offset;
        return 0;
    }

    /*
     * UDP header: just fill in the ports for now. Later we'll have to come
     * back and fixup the length and checksum fields.
     */
    pkt->fixup.transport = offset;
    if (protocol == NET_UDP) {
         buf[offset+0] = (unsigned char)(port_src>>8);
         buf[offset+1] = (unsigned char)(port_src>>0);
         buf[offset+2] = (unsigned char)(port_dst>>8);
         buf[offset+3] = (unsigned char)(port_dst>>0);
         buf[offset+4] = 0xFF;
         buf[offset+5] = 0xFF;
         buf[offset+6] = 0;
         buf[offset+7] = 0;
         offset += 8;
         pkt->offset = offset;
         return 0;
    } else if (protocol == NET_TCP) {
         buf[offset+0] = (unsigned char)(port_src>>8);
         buf[offset+1] = (unsigned char)(port_src>>0);
         buf[offset+2] = (unsigned char)(port_dst>>8);
         buf[offset+3] = (unsigned char)(port_dst>>0);
         offset += 20;
         pkt->offset = offset;
         return 0;
    }

    return 0;
}

/****************************************************************************
 ****************************************************************************/
static void
network_fixup(struct Packet *pkt)
{
    unsigned i;
    unsigned offset;
    unsigned length;
    unsigned checksum;    
    unsigned ip_header_length = pkt->fixup.transport - pkt->fixup.network;
    unsigned char *buf = pkt->buf;
    
    assert(pkt->offset >= pkt->fixup.network);

    pkt->max = pkt->offset;

    if (pkt->fixup.transport <= pkt->fixup.network)
        return;
    
    /*
     * IP header fixup
     */
    offset = pkt->fixup.network;
    length = pkt->max - offset;
	buf[offset+ 2] = (unsigned char)(length>>8);
	buf[offset+ 3] = (unsigned char)(length>>0);
    
	checksum = 0;
	for (i=0; i<ip_header_length; i += 2) {
		checksum += buf[offset+i]<<8 | buf[offset+i+1];
	}
	checksum = (checksum&0xFFFF) + (checksum>>16);
	checksum = (checksum&0xFFFF) + (checksum>>16);
    checksum = ~checksum;

	buf[offset+10] = (unsigned char)(checksum>>8);
	buf[offset+11] = (unsigned char)(checksum>>0);

    /*
     * UDP header fixup
     */
    offset = pkt->fixup.transport;
    length = pkt->max - offset;
	buf[offset+ 4] = (unsigned char)(length>>8);
	buf[offset+ 5] = (unsigned char)(length>>0);


    checksum = length;
    checksum += buf[pkt->fixup.network+12]<<8 | buf[pkt->fixup.network+13];
    checksum += buf[pkt->fixup.network+14]<<8 | buf[pkt->fixup.network+15];
    checksum += buf[pkt->fixup.network+16]<<8 | buf[pkt->fixup.network+17];
    checksum += buf[pkt->fixup.network+18]<<8 | buf[pkt->fixup.network+19];
    checksum += 17;

	for (i=0; i<(length&(~1)); i += 2)
		checksum += buf[offset+i]<<8 | buf[offset+i+1];
    if (i < length) {
        checksum += buf[offset+i]<<8;
    }
	checksum = (checksum&0xFFFF) + (checksum>>16);
	checksum = (checksum&0xFFFF) + (checksum>>16);
    checksum = ~checksum;
    buf[offset+6] = (unsigned char)(checksum>>8);
    buf[offset+7] = (unsigned char)(checksum>>0);

}


/****************************************************************************
 ****************************************************************************/
struct Packet
frame_create_response(struct Frame *frame, int protocol)
{
    struct Packet pkt;
    
    pkt = frame->adapter->alloc_packet(frame->adapter, frame->thread);

    adapter_create_ipv4(
        &pkt, protocol,
        frame->adapter->mac->address, frame->mac_src,
        frame->ip_dst, frame->ip_src,
        frame->port_dst, frame->port_src,
        frame->thread->ip_id++);
    return pkt;
}

struct Packet
adapter_create_request_udp(struct Adapter *adapter, unsigned ip_dst, unsigned port_dst)
{
    struct Packet pkt;
    
    pkt = adapter->alloc_packet(adapter, 0);

    adapter_create_ipv4(
        &pkt, NET_UDP,
        adapter->mac[0].address, adapter->mac[0].address,
        adapter->ipv4[0].address, ip_dst, 
        2000, port_dst,
        0);
    return pkt;
}

/****************************************************************************
 ****************************************************************************/
void frame_xmit_response(struct Frame *frame, struct Packet *pkt)
{
    if (pkt->max == 0)
        return;
    assert(pkt->offset >= pkt->fixup.network);
    network_fixup(pkt);
    frame->adapter->xmit_packet(frame->adapter, frame->thread, pkt);
}
void adapter_xmit(struct Adapter *adapter, struct Thread *thread, struct Packet *pkt)
{
    assert(pkt->offset >= pkt->fixup.network);
    network_fixup(pkt);
    adapter->xmit_packet(adapter, thread, pkt);
}

