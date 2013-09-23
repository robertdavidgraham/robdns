#include "network.h"
#include "adapter.h"

#define VERIFY_REMAINING(n) if (offset+(n) > max) return;

/****************************************************************************
 ****************************************************************************/
void
proto_arp_process(struct Frame *frame, const struct ARP_IncomingRequest *arp)
{
    struct Packet pkt;
    unsigned char *px;
    unsigned offset;

    if (!arp->is_valid)
        return;

	switch (arp->opcode) {
	case 1: /* request */
		/* Ignore ARP packets that aren't sent to our IP address */
        if (!adapter_has_ipv4(frame->adapter, arp->ip_dst))
            return;

        /*
         * Create a response packet that will be sent back to the sender
         * of this packet
         */
        pkt = frame_create_response(frame, NET_ETHERNET);
        px = pkt.buf;
        offset = pkt.offset;

        /*
         * Format outgoing Ethernet header
         */
		memcpy(&px[offset + 0], arp->mac_dst, 6);                      /* Ethernet destination */
		memcpy(&px[offset + 6], frame->adapter->mac[0].address, 6);    /* Ethernet source */
		memcpy(&px[offset + 12], "\x08\x06", 2);                       /* Ethertype */

        /*
         * Format ARP header
         */
        px[offset++] = (unsigned char)(arp->hardware_type>>8);
        px[offset++] = (unsigned char)(arp->hardware_type>>0);
        px[offset++] = (unsigned char)(arp->protocol_type>>8);
        px[offset++] = (unsigned char)(arp->protocol_type>>0);
        px[offset++] = (unsigned char)(arp->hardware_length);
        px[offset++] = (unsigned char)(arp->protocol_length);
        px[offset++] = (unsigned char)(0);
        px[offset++] = (unsigned char)(2); /* reply */

		/* Set our source address */
		memcpy(&px[offset], frame->adapter->mac[0].address, 6);
        offset += 6;
		px[offset++] = (unsigned char)(arp->ip_dst>>24);
		px[offset++] = (unsigned char)(arp->ip_dst>>16);
		px[offset++] = (unsigned char)(arp->ip_dst>> 8);
		px[offset++] = (unsigned char)(arp->ip_dst>> 0);

        /* Set our destination address */
        memcpy(&px[offset], arp->mac_src, 6);
        offset += 6;
		px[offset++] = (unsigned char)(arp->ip_src>>24);
		px[offset++] = (unsigned char)(arp->ip_src>>16);
		px[offset++] = (unsigned char)(arp->ip_src>> 8);
		px[offset++] = (unsigned char)(arp->ip_src>> 0);

		/*
		    * Send the packet
		    */
        pkt.offset = offset;
        pkt.max = offset;
		break;
	case 2: /* reply */
        pkt.offset = pkt.max = 0;
		break;
	default:
		/* we don't handle any other ARPs */
        pkt.offset = pkt.max = 0;
		break;
	}

    /*
     * Now transmit the packet
     */
    frame_xmit_response(frame, &pkt);
}


/****************************************************************************
 ****************************************************************************/
void
proto_arp_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max)
{
    struct ARP_IncomingRequest *arp = frame->arp;

	/*
	 * parse the header
	 */
	VERIFY_REMAINING(8);
    frame->net_protocol = NET_ARP;
    arp->is_valid = 0; /* not valid yet */

	arp->hardware_type = px[offset]<<8 | px[offset+1];
	arp->protocol_type = px[offset+2]<<8 | px[offset+3];
	arp->hardware_length = px[offset+4];
	arp->protocol_length = px[offset+5];
	arp->opcode = px[offset+6]<<8 | px[offset+7];
	offset += 8;

	/* We only support IPv4 and Ethernet addresses */
	if (arp->protocol_length != 4 && arp->hardware_length != 6)
		return;
	if (arp->protocol_type != 0x0800)
		return;
	if (arp->hardware_type != 1 && arp->hardware_type != 6)
		return;

	/*
	 * parse the addresses
	 */
	VERIFY_REMAINING(2 * arp->hardware_length + 2 * arp->protocol_length);
	arp->mac_src = px+offset;
	offset += arp->hardware_length;
	
	arp->ip_src = px[offset+0]<<24 | px[offset+1]<<16 | px[offset+2]<<8 | px[offset+3];
	offset += arp->protocol_length;

	arp->mac_dst = px+offset;
	offset += arp->hardware_length;

	arp->ip_dst = px[offset+0]<<24 | px[offset+1]<<16 | px[offset+2]<<8 | px[offset+3];
	offset += arp->protocol_length;

    arp->is_valid = 1;

    frame->ip_dst = arp->ip_dst;
    frame->ip_src = arp->ip_src;
}
