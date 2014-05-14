#include "network.h"
#include "adapter.h"
#include <string.h>

#define VERIFY_REMAINING(n) if (offset+(n) > max) return;

/****************************************************************************
 ****************************************************************************/
int
adapter_has_ipv4(const struct Adapter *adapter, unsigned ipv4)
{
    unsigned i;

    for (i=0; i<adapter->ipv4_count; i++) {
        if (adapter->ipv4[i].address == (ipv4 & adapter->ipv4[i].mask))
            return 1;
    }
    return 0;
}

/****************************************************************************
 ****************************************************************************/
void
proto_ethernet_parse(struct Frame *frame, const unsigned char px[], unsigned offset, unsigned max)
{
    frame->net_protocol = NET_ETHERNET;

	VERIFY_REMAINING(14);
	frame->mac_src = &px[offset+6];
	frame->mac_dst = &px[offset+0];
	frame->ethertype = px[offset+12]<<8 | px[offset+13];
	offset += 14;

	switch (frame->ethertype) {
	case 0x0800:
		proto_ip_parse(frame, px, offset, max);
		break;
	case 0x0806:
		proto_arp_parse(frame, px, offset, max);
		break;
    /*TODO: add 802.1a */
	}
}

/****************************************************************************
 ****************************************************************************/
void
network_receive(struct Frame *frame,
                struct Thread *thread,
                struct Adapter *adapter,
                unsigned secs,
                unsigned usecs,
			    const unsigned char *px,
                unsigned length)
{

    frame->adapter = adapter;
	frame->thread = thread;
    frame->time_secs = secs;
    frame->time_usecs = usecs;
    frame->net_protocol = 0;

    /*
     * PARSE FIRST THEN PROCESS REQ:[d7Unn4]
     *
     * This parses Ethernet, IP, UDP, and DNS.
     *
     * TODO: this will change a bit once I add TCP handling
     */
    proto_ethernet_parse(frame, px, 0, length);

    /*
     * Reject packets that aren't sent to us.
     */
    if (!adapter_has_ipv4(adapter, frame->ip_dst))
        return;

    /*
     * AT this point, we have a fully validated packet. Now we will
     * go through and generate a response
     */
    switch (frame->net_protocol) {
    case NET_ARP:
        proto_arp_process(frame, frame->arp);
        break;
    case NET_ICMP:
        proto_icmp_process(frame, frame->icmp);
        break;
    case NET_DNS:
        /* IMPORTANT! this is the interesting bit that you are looking for,
         * taking a parsed DNS packet and interpretting it in order to 
         * generate a response */
        proto_dns_process(frame, frame->dns);
        break;
    }
}
