#include "network.h"

#define VERIFY_REMAINING(n) if (offset+(n) > max) return;

/****************************************************************************
 * 'parse' incoming UDP packets. We do little more than record
 * the port numbers and pass execution onto the next layer. 
 ****************************************************************************/
void
proto_udp_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max)
{
    unsigned checksum;
    unsigned udp_length;

    frame->net_protocol = NET_UDP;

    VERIFY_REMAINING(8);
    frame->port_src = px[offset+0]<<8 | px[offset+1];
    frame->port_dst = px[offset+2]<<8 | px[offset+3];

    /*
     * 'length' field
     */
    udp_length = px[offset+4]<<8 | px[offset+5];
    if (udp_length < 8) {
        return;
    } else if (udp_length > max) {
        return;
    }
    max = offset + udp_length; /* shrink remaining length to fit UDP length */

    /*
     * 'checksum' field.
     * TODO: skip this step when the underlying adapter offloads
     * checksumming, which is most adapters these days.
     */
    checksum = px[offset+6]<<8 | px[offset+7];
    if (checksum) {
        unsigned i;

        checksum = (frame->ip_src>>16)&0xFFFF;
        checksum += (frame->ip_src>> 0)&0xFFFF;
        checksum += (frame->ip_dst>>16)&0xFFFF;
        checksum += (frame->ip_dst>> 0)&0xFFFF;
        checksum += udp_length;
        checksum += 17;

	    for (i=offset; i<(max&(~1)); i += 2)
		    checksum += px[i]<<8 | px[i+1];
        if (i < max) {
            checksum += px[i]<<8;
        }
	    checksum = (checksum&0xFFFF) + (checksum>>16);
	    if (checksum != 0xFFFF)
		    return;
    }

    offset += 8;

    /*
     * 'destination port'
     */
    switch (frame->port_dst) {
    case 53:
        proto_dns_parse(frame->dns, px, offset, max);
        if (frame->dns->is_valid)
            frame->net_protocol = NET_DNS;
    }
}



