#include "proto-dns-compressor.h"
#include "proto-dns-formatter.h"
#include "packet.h"
#include "domainname.h"
#include "db-rrset.h"
#include <string.h>

/**
 * Hard-coded response packet to the "version.bind" query. Maybe in the future
 * we'll make this more of a generic thing
 */
static const unsigned char version_bind_response[] = {
    0x87, 0x31, 
    0x85, 0x00, 
    0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 
    
    0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00, 
    0x00, 0x10, 
    0x00, 0x03, 
    
    0xc0, 0x0c, 
    0x00, 0x10, 
    0x00, 0x03, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x09, 
    0x08, 
    'r', 'o', 'b', 'd', 'n', 's', '/', '1',
    
    0xc0, 0x0c,
    0x00, 0x02, 
    0x00, 0x03,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xc0, 0x0c,
};

/******************************************************************************
 * Creates the DNS response packet.
 *
 * The "response" parameter is the internal data structure built for the
 * responses, which is largely just an array of pointers into the
 * catalog/database structure.
 *
 * The "pkt" parameter points to the network packet that we are building.
 * This is entire packet including Ethernet, IP, and UDP headers. Thus,
 * we are appending data at "pkt->offset" location.
 *
 * FIXME: rrset_packet_append() should be defined in this file
 *
 * This has following steps:
 * 0. append the query record
 * 1. append all the required records
 * 2. append all the optional records
 * 3. append the edns0 record
 * 4. prepend the DNS header
 * Along the way, we need to check for truncation
 ******************************************************************************/
void
dns_format_response(struct DNS_OutgoingResponse *response, 
                    struct Packet *pkt)
{
    unsigned offset_start = pkt->offset;
    unsigned i;
    static const struct DomainPointer root = {0,0};
    struct Compressor compressor[1];
    unsigned actual_ancount =0 ;
    unsigned actual_nscount = 0;
    unsigned actual_arcount = 0;

    /* check for programming error */
    if (pkt->offset + 12 > pkt->max) {
        pkt->offset = 0;
        return;
    }
    
    /*
     * Handle format error case with a hard-coded response
     */
format_error:
    if (response->rcode == RCODE_FORMERR) {
        static const char format_err[] = 
            "\0\0" "\x80\1" "\0\0" "\0\0" "\0\0" "\0\0";

        memcpy(&pkt->buf[pkt->offset], format_err, 12);
        pkt->buf[pkt->offset+0] = (unsigned char)(response->id>>8);
        pkt->buf[pkt->offset+1] = (unsigned char)(response->id>>0);
        pkt->offset += 12;
        pkt->max = pkt->offset;
        return;
    }
    
    /*
     * Handle "version" request as a hard-coded special case
     */
    if (response->is_version_bind) {
        if (pkt->offset + sizeof(version_bind_response) >= pkt->max) {
            response->rcode = RCODE_FORMERR;
            goto format_error;
        }
        
        memcpy(&pkt->buf[pkt->offset], 
               version_bind_response, 
               sizeof(version_bind_response));
        
        pkt->buf[pkt->offset+0] = (unsigned char)(response->id>>8);
        pkt->buf[pkt->offset+1] = (unsigned char)(response->id>>0);
        
        pkt->offset += sizeof(version_bind_response);
        pkt->max = pkt->offset;
        return;
    }
    
    /*
     * Skip DNS header for now, fill it in at the end. That's because while
     * generating the packet, we might find overflow conditions, meaning
     * we need to go back to the header and change things.
     */
    pkt->offset += 12;


    /*
     * Initialize the compressor. DNS names can be compressed, both the 
     * 'label' for each record, as well as sometimes the record-data
     * contents as well.
     */
    compressor_init(compressor, response, offset_start);

    /*
     * Append the QR record (the original query)
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
        const struct DNS_ResponseRRset *rrr = &response->rrsets[i];
        unsigned truncated_offset;
        unsigned count;
        
        /* remember the current offset in case the next record doesn't fit */
        truncated_offset = pkt->offset;
        
        /* attempt to append the next record-set to the packet */
        count = rrset_packet_append(rrr->rrset, pkt, compressor, 
                                    rrr->name, rrr->origin);
        if (i < response->ancount)
            actual_ancount += count;
        else
            actual_nscount += count;

        /* check for truncation */
        if (pkt->offset > pkt->max) {
            /* oops, the response didn't fit, so we need to generate a 
             * "truncated" response */
            response->tc = 1;
            
            /* FIXME: I don't think the following bits of code are needed*/
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
            pkt->offset = truncated_offset; 
            goto generate_header;
        }
    }

    /*
     * Append the optional resource records
     */
    for ( ; i<response->ancount+response->nscount+response->arcount; i++) {
        const struct DNS_ResponseRRset *rrr = &response->rrsets[i];
        unsigned truncated_offset;
        unsigned count;

        /* remember the current offset in case the next record doesn't fit */
        truncated_offset = pkt->offset;
        
        /* attempt to append the next record to the packet */
        count = rrset_packet_append(rrr->rrset, pkt, compressor, 
                                    rrr->name, rrr->origin);
        actual_arcount += count;

        if (pkt->offset > pkt->max) {
            /* don't set TC for additional-records overflow */
            response->arcount = i - response->ancount - response->nscount;

            /* set packet length back to start of overflow record, so
             * so that we don't have a partial RR */
            pkt->offset = truncated_offset;
            goto generate_header;
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
generate_header:
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
