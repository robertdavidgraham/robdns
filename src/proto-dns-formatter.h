#ifndef PROTO_DNS_FORMATTER_H
#define PROTO_DNS_FORMATTER_H
#include "domainname.h"
struct Packet;

struct DNS_ResponseRRset
{
    struct DomainPointer name;
    struct DomainPointer origin;
    const struct DBrrset *rrset;
};

struct DNS_OutgoingResponse
{
    unsigned id;
    unsigned is_version_bind:1;
    unsigned aa:1;
    unsigned ra:1;
    unsigned tc:1;
    unsigned rcode;
    unsigned opcode;

    unsigned ancount;
    unsigned nscount;
    unsigned arcount;

    int query_type;
    struct DomainPointer query_name;
    
    struct DNS_ResponseRRset rrsets[4096];
};

enum {
    RCODE_OK        =   0,
    RCODE_FORMERR   =   1,
    RCODE_NXDOMAIN  =   3,
    RCODE_REFUSED   =   5,
};



enum {
    SECTION_ANSWER=1,
    SECTION_AUTHORITATIVE,
    SECTION_ADDITIONAL,
};

/**
 * Convert the internal representation of a response into the external
 * form, formatting a DNS response packet
 */
void dns_format_response(struct DNS_OutgoingResponse *response, 
                         struct Packet *pkt);

#endif
