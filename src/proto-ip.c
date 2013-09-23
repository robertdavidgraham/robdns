#include "network.h"
#include "thread.h"
#include "adapter.h"
#include <string.h>

#define VERIFY_REMAINING(n) if (offset+(n) > max) return;

/****************************************************************************
 * parse the IPv4 header
 ****************************************************************************/
void
proto_ip_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max)
{
	unsigned checksum = 0;
	unsigned i;
	struct {
		unsigned header_length;
		unsigned total_length;
		unsigned id;
		unsigned flags;
		unsigned ttl;
		unsigned protocol;
		unsigned src;
		unsigned dst;
	} ip;

    frame->net_protocol = NET_IP;
	VERIFY_REMAINING(1);

	/* Must be IPv4 */
	if ((px[offset+0]>>4) != 4)
		return;

	/* Must be at least 20 bytes */
	if ((px[offset+0]&0xF) < 5)
		return;

	/* Make sure we have a full header */
	ip.header_length = (px[offset] & 0x0F) * 4;
	VERIFY_REMAINING(ip.header_length);

	/* Verify the checksum */
	checksum = 0;
	for (i=0; i<ip.header_length; i += 2) {
		checksum += px[offset+i]<<8 | px[offset+i+1];
	}
	checksum = (checksum&0xFFFF) + (checksum>>16);
    frame->ip_checksum_is_valid = (checksum == 0xFFFF);


	/*
	 * Decode the header
	 */
	ip.total_length = px[offset+2]<<8 | px[offset+3];
	ip.id = px[offset+4]<<8 | px[offset+5];
	ip.flags =px[offset+6] & 0x0f;
	ip.ttl = px[offset+8];
	ip.protocol = px[offset+9];
	frame->ip_ver = 4;
	frame->ip_src = px[offset+12]<<24 | px[offset+13]<<16 | px[offset+14]<<8 | px[offset+15]; 
	frame->ip_dst = px[offset+16]<<24 | px[offset+17]<<16 | px[offset+18]<<8 | px[offset+19]; 
	offset += 20;

	/* Process IP options */
	/* TODO: right now we ignore all IP options. Should support some
	 * of them I suppose */
	offset += ip.header_length - 20;


	switch (ip.protocol) {
	case 1: /* ICMP */
		proto_icmp_parse(frame, px, offset, max);
		break;
	case 6: /* TCP */
		break;
	case 17: /* UDP */
        proto_udp_parse(frame, px, offset, max); 
		break;
	}

	return;
}


