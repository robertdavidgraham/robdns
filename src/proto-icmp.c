#include "network.h"
#include "thread.h"

#define VERIFY_REMAINING(n) if (offset+(n) > max) return;


/****************************************************************************
 ****************************************************************************/
void
proto_icmp_process(struct Frame *frame, const struct ICMP_IncomingRequest *icmp)
{
	unsigned char *px;
    unsigned offset;
    struct Packet pkt;
    unsigned checksum;
    
	/*
	 * We only handle ICMP ping requests 
	 */
	if (icmp->type != 8) {
		frame->thread->stats.icmp_bad_type++;
		return;
	}

	/*
	 * Only handle short, unfragmented pings
	 */
	if (icmp->payload_length > 1400)
		return;

    /*
     * Grab a transmit buffer
     */
    pkt = frame_create_response(frame, NET_IP);
    px = pkt.buf;
    offset = pkt.offset;
      
    /*
     * The new checksum is just a conversion o the old checksum
     */
   	checksum = ~(icmp->original_checksum);
	checksum -= 0x800;
	checksum = (checksum&0xFFFF) + (checksum>>16);
	checksum = (checksum&0xFFFF) + (checksum>>16);
	checksum = ~checksum;

    /*
     * create echo response
     */
    offset = 0;
    px[offset++] = 0;
    px[offset++] = 0; 
	px[offset++] = (unsigned char)(checksum>>8);
	px[offset++] = (unsigned char)(checksum>>0);

    /*
     * Echo the contents exacty
     */
    if (offset + icmp->payload_length <= pkt.max)
	    memcpy(&px[offset], icmp->payload, icmp->payload_length);
    offset += icmp->payload_length;


    pkt.offset = offset;
    pkt.max = pkt.offset;
	frame_xmit_response(frame, &pkt);
}

/****************************************************************************
 ****************************************************************************/
void
proto_icmp_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max)
{
    struct ICMP_IncomingRequest *icmp = frame->icmp;
	unsigned i;
	unsigned checksum_length;
	unsigned checksum;


	VERIFY_REMAINING(4);
    frame->net_protocol = NET_ICMP;

	icmp->type = px[offset+0];
	icmp->code = px[offset+1];
    icmp->original_checksum = px[offset+2]<<8 | px[offset+3];
    icmp->payload_length = max - offset - 4;
    icmp->payload = px+4;

	/*
	 * Validate checksum
	 */
	checksum = 0;
	checksum_length = (max-offset) & (~1);
	for (i=0; i<checksum_length; i += 2) {
		checksum += px[i]<<8 | px[i+1];
	}
	if (checksum_length < (max-offset))
		checksum += px[i]<<8;
	checksum = (checksum&0xFFFF) + (checksum>>16);
	checksum = (checksum&0xFFFF) + (checksum>>16);
    icmp->is_checksum_checked = 1;
	if (checksum != 0xffff) {
		frame->thread->stats.icmp_bad_checksum++;
        icmp->is_checksum_valid = 0;
		//return;
	}
    icmp->is_checksum_valid = 1;

    icmp->is_valid = 1;


}
