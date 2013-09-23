#include "proto-dns-compressor.h"
#include "proto-dns-formatter.h"
#include "packet.h"
#include "domainname.h"
#include "db-rrset.h"

/****************************************************************************
 ****************************************************************************/
void
dns_format_response(struct DNS_OutgoingResponse *response, struct Packet *pkt)
{
    unsigned offset_start = pkt->offset;
    unsigned i;
    static const struct DomainPointer root = {0,0};
    struct Compressor compressor[1];
    unsigned actual_ancount=0;
    unsigned actual_nscount=0;
    unsigned actual_arcount=0;

    if (pkt->offset + 12 > pkt->max) {
        pkt->offset = 0; /* mark packet as bad */
        return;
    }
    pkt->offset += 12;


    /*
     * Initialize the compressor
     */
    compressor_init(compressor, response, offset_start);

    /*
     * Append the QR record
     */
    compressor_append_name(compressor, pkt, response->query_name, root);
    if (pkt->offset + 4 < pkt->max) {
        pkt->buf[pkt->offset+0] = (unsigned char)(response->query_type>>8);
        pkt->buf[pkt->offset+1] = (unsigned char)(response->query_type>>0);
        pkt->buf[pkt->offset+2] = 0;
        pkt->buf[pkt->offset+3] = 1;
    }
    pkt->offset += 4;

    /*
     * Append all the required resource records
     */
    for (i=0; i<response->ancount+response->nscount; i++) {
        struct DNS_ResponseRRset *rrr = &response->rrsets[i];
        unsigned truncate_offset = pkt->offset;
        unsigned count;

        count = rrset_packet_append(rrr->rrset, pkt, compressor, rrr->name, rrr->origin);
        if (i < response->ancount)
            actual_ancount += count;
        else
            actual_nscount += count;


        if (pkt->offset > pkt->max) {
            response->tc = 1;
            if (i < response->ancount) {
                response->ancount = i;
                response->nscount = 0;
                response->arcount = 0;
            } else {
                response->nscount = i-response->ancount;
                response->arcount = 0;
            }
            /* set packet length back to start of overflow record, so
             * so that we don't have a partial RR */
            pkt->offset = truncate_offset; 
            return;
        }
    }

    /*
     * Append the optional resource records
     */
    for ( ; i<response->ancount+response->nscount+response->arcount; i++) {
        struct DNS_ResponseRRset *rrr = &response->rrsets[i];
        unsigned truncate_offset = pkt->offset;
        unsigned count;

        count = rrset_packet_append(rrr->rrset, pkt, compressor, rrr->name, rrr->origin);
        actual_arcount += count;

        if (pkt->offset > pkt->max) {
            /* don't set TC for additional-records overflow */
            response->arcount = i - response->ancount - response->nscount;

            /* set packet length back to start of overflow record, so
             * so that we don't have a partial RR */
            pkt->offset = truncate_offset;
            return;
        }
    }

    /*
     * If 'edns0', then add the OPT record
     */
    /*TODO*/

    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */
    pkt->buf[offset_start+0] = (unsigned char)(response->id>>8);
    pkt->buf[offset_start+1] = (unsigned char)(response->id>>0);
    pkt->buf[offset_start+2] = (unsigned char)(
        0x80 |                  /* QR=1 (response) */
        (response->opcode<<3) |
        (response->aa<<2) |
        (response->tc<<1)
        );
    pkt->buf[offset_start+3] = (unsigned char)(response->rcode);
    pkt->buf[offset_start+4] = 0;
    pkt->buf[offset_start+5] = 1;
    pkt->buf[offset_start+6] = (unsigned char)(actual_ancount>>8);
    pkt->buf[offset_start+7] = (unsigned char)(actual_ancount>>0);
    pkt->buf[offset_start+8] = (unsigned char)(actual_nscount>>8);
    pkt->buf[offset_start+9] = (unsigned char)(actual_nscount>>0);
    pkt->buf[offset_start+10] = (unsigned char)(actual_arcount>>8);
    pkt->buf[offset_start+11] = (unsigned char)(actual_arcount>>0);

}
