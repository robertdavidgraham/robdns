#include "proto-dns-compressor.h"
#include "proto-dns-formatter.h"
#include "zonefile-rr.h"
#include "resolver.h"
#include "packet.h"
#include "string_s.h"
#include "util-realloc2.h"
#include <string.h>


/******************************************************************************
 * Tests if two labels are the same.
 *
 * Note: don't use a generic function here. This has very narrow requirements
 * just for labels in this narrow case. Namely, it's doing a case-insensitive
 * compare. As defined by the RFC (FIXME: reference needed), when compressing
 * names, it can be done so in a case insensitive manner.
 ******************************************************************************/
static int
is_equal(const unsigned char *lhs, const unsigned char *rhs)
{
    size_t lhs_len = lhs[0];
    size_t rhs_len = rhs[0];
    
    if (lhs_len != rhs_len)
        return 0;
    
    return strncasecmp((char*)lhs+1, (char*)rhs+1, lhs_len) == 0;
}

/******************************************************************************
 ******************************************************************************/
static unsigned short
compressor_new(struct Compressor *compressor, const unsigned char *label)
{
    compressor->ids[compressor->count].child = 0;
    compressor->ids[compressor->count].label = label;
    compressor->ids[compressor->count].sibling = 0;
    compressor->ids[compressor->count].compression_code = 0;
    return (unsigned short)compressor->count++;
}


/******************************************************************************
 ******************************************************************************/
static unsigned
compressor_init_label(struct Compressor *compressor, 
                      unsigned id_index, const unsigned char *label)
{
    struct CompressorId *parent = &compressor->ids[id_index];
    unsigned child_index;

    /* First born */
    if (parent->child == 0) {
        parent->child = compressor_new(compressor, label);
        return parent->child;
    }

    /* Existing child */
    child_index = parent->child;
    for (;;) {
        struct CompressorId *child = &compressor->ids[child_index];

        if (is_equal(child->label, label))
            return child_index;

        if (child->sibling == 0) {
            child->sibling = compressor_new(compressor, label);
            return child->sibling;
        }
        child_index = child->sibling;
    }
}


/******************************************************************************
 ******************************************************************************/
static unsigned
compressor_init_partialname(struct Compressor *compressor, 
                            struct DomainPointer domain, unsigned id_index)
{
    unsigned char label_offsets[128];
    unsigned i;
    unsigned n;
    const unsigned char *name;
    unsigned name_length;

    name = domain.name;
    name_length = domain.length;

    /* go forward in order to go backwards */
    i = 0;
    for (n=0; n<name_length; n += name[n] + 1) {
        label_offsets[i] = (unsigned char)n;
        i++;
    }
    
    /* traverse the tree trying to match existing items */
    while (i) {
        id_index = compressor_init_label(compressor, 
                                         id_index, 
                                         &name[label_offsets[i-1]]);
        i--;
    }
    return id_index;
}

/******************************************************************************
 ******************************************************************************/
static unsigned
compressor_append_partialname(
    struct Compressor *compressor, 
    struct Packet *pkt, 
    struct DomainPointer domain, 
    unsigned id_index,
    unsigned prefix_length)
{
    unsigned char label_offsets[128];
    unsigned i;
    unsigned n;
    const unsigned char *name;
    unsigned name_length;
    unsigned compression_code = compressor->ids[id_index].compression_code;
    unsigned uncompressed_length = 0;

    name = domain.name;
    name_length = domain.length;

    /* go forward in order to go backwards */
    i = 0;
    for (n=0; n<name_length; n += name[n] + 1) {
        label_offsets[i] = (unsigned char)n;
        i++;
    }
    
    /* traverse the tree trying to match existing items */
    uncompressed_length = name_length;
    while (i) {
        unsigned packet_offset;
        id_index = compressor_init_label(compressor, 
                                         id_index, 
                                         &name[label_offsets[i-1]]);
        packet_offset = compressor->ids[id_index].compression_code;

        if (packet_offset == 0) {
            break;
        }
        
        compression_code = packet_offset;
        uncompressed_length = label_offsets[i-1];
        i--;
    }


    /* record the remaining offsets */
    while (i) {
        compressor->ids[id_index].compression_code = (unsigned short)(
                                        pkt->offset 
                                        + label_offsets[i-1] 
                                        + prefix_length 
                                        - compressor->offset_start);
        i--;
        if (i == 0)
            break;
        id_index = compressor_init_label(compressor, 
                                         id_index, 
                                         &name[label_offsets[i-1]]);
    }

    /* Write the uncompressed portions of the name, if there are any */
    if (uncompressed_length) {
        if (pkt->offset + uncompressed_length <= pkt->max) {
            memcpy(&pkt->buf[pkt->offset], name, uncompressed_length);
        }
        pkt->offset += uncompressed_length;
        if (!compression_code) {
            if (pkt->offset + 1 <= pkt->max)
                pkt->buf[pkt->offset] = 0;
            pkt->offset += 1;
        }
    }

    /* write the trailing compression code, if there is one */
    if (compression_code) {
        if (pkt->offset+2 < pkt->max) {
            pkt->buf[pkt->offset+0] = (unsigned char)(0xC0|compression_code>>8);
            pkt->buf[pkt->offset+1] = (unsigned char)(compression_code);
        }
        pkt->offset += 2;
    }

    return id_index;
}

/******************************************************************************
 ******************************************************************************/
static void
compressor_init_fullname(struct Compressor *compressor, 
                         struct DomainPointer name, struct DomainPointer origin)
{
    unsigned id_index;

    id_index = compressor_init_partialname(compressor, origin, 0);
    id_index = compressor_init_partialname(compressor, name, id_index);
}


/******************************************************************************
 ******************************************************************************/
void
compressor_append_name(struct Compressor *compressor, 
                       struct Packet *pkt, 
                       struct DomainPointer name, struct DomainPointer origin)
{
    unsigned id_index;

    id_index = compressor_append_partialname(compressor, pkt, 
                                             origin, 0, name.length);
    if (name.length)
        id_index = compressor_append_partialname(compressor, pkt, 
                                                 name, id_index, 0);
}


/******************************************************************************
 ******************************************************************************/
void
compressor_init(struct Compressor *compressor, 
                const struct DNS_OutgoingResponse *response, 
                unsigned offset_start)
{
    unsigned i;
    unsigned rrcount;
    static const struct DomainPointer root = {0,0};

    compressor->offset_start = offset_start;
    compressor->count = 0;
    compressor_new(compressor, (const unsigned char*)"");

    compressor_init_fullname(compressor, response->query_name, root);

    rrcount = response->ancount + response->nscount + response->arcount;
    for (i=0; i<rrcount; i++) {
        compressor_init_fullname(compressor, 
                                 response->rrsets[i].name, 
                                 response->rrsets[i].origin);
    }
}


/******************************************************************************
 ******************************************************************************/
int
compressor_selftest(const struct DNS_OutgoingResponse *response)
{
    unsigned char *buf = REALLOC2(NULL, 65536, 1);
    struct Packet pkt;
    struct Compressor compressor[1];
    unsigned i;
    static const struct DomainPointer root = {0,0};

    pkt.buf = buf;
    pkt.max = sizeof(buf);
    pkt.offset = 16;
    memset(buf, '*', pkt.offset);
    
    compressor_init(compressor, response, pkt.offset);
    compressor_append_name(compressor, &pkt, response->query_name, root);

    for (i=0; i<response->ancount; i++) {
        const struct DNS_ResponseRRset *rrr = &response->rrsets[i];

        compressor_append_name(compressor, &pkt, rrr->name, rrr->origin);
    }


    return 0;
}

