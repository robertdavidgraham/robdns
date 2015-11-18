/****************************************************************************
  IMPORTANT! WE COMPRESS DATABASE ENTRIES

  Each entry starts with it's "owner" name, a domain-name minus the
  zone-name. Thus, an entry for "www.jp.example.com." what have an owner of
  "www.jp" within the zone "example.com." (assumming there is no zone with
  the name "jp.example.com.", of course). This name is encoded as normal
  with a one-byte length followed by a label, terminating in a zero length.

  After the "owner", we then have sequential "RRsets", each containing
  a number of "RRs" (resource-records). We don't have internal data structs
  for this, but instead, compress them one byte at a time manually.

 ****************************************************************************/
#include "db.h"
#include "db-entry.h"
#include "db-rrset.h"
#include "domainname.h"
#include "db-zone.h"
#include "source.h"
#include "packet.h"
#include "proto-dns-compressor.h"
#include "success-failure.h"
#include "string_s.h"
#include "util-realloc2.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>



#define BLOCK_SIZE 8
#define ALIGN(x,mask) (((x)+(mask))&~(mask))

extern int is_verbose;
uint64_t entry_bytes;
uint64_t entry_count;
uint64_t total_chain_length;

struct DBEntry
{
    struct DBEntry *next;
    unsigned short sizeof_buf;
    unsigned short offset;
    unsigned char domain_length;
    unsigned char is_ns:1;
    unsigned char buf[1];
};

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                TOTALLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct RRSETPARSER {
    const unsigned char *buf;
    unsigned offset;
    unsigned max;
    int type;
    unsigned ttl;
};
void R_init(struct RRSETPARSER *r, const void *rrset)
{
    r->buf = (const unsigned char *)rrset;
    r->max = r->buf[0]<<8 | r->buf[1];
    r->type = r->buf[2]<<8 | r->buf[3];
    r->ttl = r->buf[4]<<24 | r->buf[5]<<16 | r->buf[6]<<8 | r->buf[7];
    r->offset = 8;
}
void R_next_rr(struct RRSETPARSER *r, unsigned *rdlength, unsigned *rdoffset)
{
    *rdlength = r->buf[r->offset+0]<<8 | r->buf[r->offset+1];
    *rdoffset = r->offset + 2;

    r->offset = *rdoffset + *rdlength;
}

/******************************************************************************
 * This is the "formater" function that appends a record-set onto the end
 * of a DNS response packet.
 *
 * As per DNS spec, we don't append individual records, but record-sets. In
 * other, if two IP addresses match the DNS query name, then both should
 * always be returned in the response, or neither.
 *
 * Since we have a weird internal format in the catalog/database, we need to
 * parse that internal format while appending to the packet.
 *
 * For almost all records we simply blindly append the opaque contents.
 * However, for old record types containing names, we need to do name
 * compression when generating responses.
 * 
 * FIXME: this function belongs in proto-dns-formatter.c
 ******************************************************************************/
unsigned
rrset_packet_append(
        const struct DBrrset *rrset,
        struct Packet *pkt,
        struct Compressor *compressor,
        struct DomainPointer owner,
        struct DomainPointer origin)
{
    unsigned char *px = pkt->buf;
    unsigned max = pkt->max;
    static const struct DomainPointer root = {0,0};
    struct RRSETPARSER r[1];
    unsigned count = 0; /* number of RR in RRset that were added */

    R_init(r, rrset);

    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    while (r->offset < r->max) {
        unsigned rdlength;
        unsigned rdoffset;

        R_next_rr(r, &rdlength, &rdoffset);

        compressor_append_name(compressor, pkt, owner, origin);
        
        if (pkt->offset + 10 <= max) {
            px[pkt->offset++] = (unsigned char)(r->type>>8);
            px[pkt->offset++] = (unsigned char)(r->type>>0);
            px[pkt->offset++] = (unsigned char)(0);
            px[pkt->offset++] = (unsigned char)(1);
            px[pkt->offset++] = (unsigned char)(r->ttl>>24);
            px[pkt->offset++] = (unsigned char)(r->ttl>>16);
            px[pkt->offset++] = (unsigned char)(r->ttl>> 8);
            px[pkt->offset++] = (unsigned char)(r->ttl>> 0);
            px[pkt->offset++] = (unsigned char)(rdlength>>8);
            px[pkt->offset++] = (unsigned char)(rdlength>>0);
        } else {
            pkt->offset += 10;
        }
        
        /*
         * Just copy the opaque RDATA -- except when there are names to
         * compress.
         * FIXME: add more types that need compression
         */
        switch (r->type) {
        case TYPE_NS:
        case TYPE_CNAME:
        case TYPE_PTR:
            {
                struct DomainPointer domain;
                domain.name = r->buf + rdoffset;
                domain.length = rdlength;
                compressor_append_name(compressor, pkt, domain, root);
            }
            break;
        case TYPE_A:
        case TYPE_AAAA:
        case TYPE_TXT:
        case TYPE_SRV:
        default:
            if (pkt->offset + rdlength <= max)
                memcpy(&px[pkt->offset], &r->buf[rdoffset], rdlength);
            pkt->offset += rdlength;
        }
        count++;
    }

    return count;
}

/****************************************************************************
 ****************************************************************************/
const struct DBrrset *
rrset_first(const struct DBEntry *entry, int type)
{
    const unsigned char *buf = entry->buf;
    size_t max = entry->offset; /* offset=start of free space */
    size_t offset = entry->domain_length;

    /* Hunt through the linear list of RRsets and return the first one
     * that matches */
    while (offset < max) {
        struct RRSETPARSER r[1];
        R_init(r, &buf[offset]);

        if (type == TYPE_ANY || type == r->type)
            return (struct DBrrset *)&buf[offset];

        offset += r->max;
    }

    return 0; /* not found */
}


/****************************************************************************
 ****************************************************************************/
const struct DBrrset *
rrset_next(const struct DBEntry *entry, int type, const struct DBrrset *rrset)
{
    const unsigned char *buf = entry->buf;
    size_t max = entry->offset; /* offset=start of free space */
    size_t offset = (const unsigned char*)rrset - buf;
    struct RRSETPARSER r[1];

    /* skip this one */
    R_init(r, &buf[offset]);
    offset += r->max;

    /* Hunt through the linear list of RRsets and return the first one
     * that matches */
    while (offset < max) {
        R_init(r, &buf[offset]);

        if (type == TYPE_ANY || type == r->type)
            return (struct DBrrset *)&buf[offset];

        offset += r->max;
    }

    return 0; /* reached end of list */
}

#if 0
/****************************************************************************
 ****************************************************************************/
const struct DBEntry *
rrset_get_glue(const struct DBZone *zone, const struct DBEntry *entry, const struct DBrrset *rr, struct DomainPointer *domain_pointer)
{
    const unsigned char *buf = entry->buf;
    //size_t length = entry->offset;
    size_t offset = (const unsigned char *)rr - buf;
    int type;

    /* Get the 'type' of this resource-entry */
    type = GET_TYPE(buf, offset);

    /* Handle 'CNAME' and 'NS' records */
    switch (type) {
    case TYPE_NS:
    case TYPE_CNAME:
    case TYPE_PTR:
        domain_pointer->length = GET_RDLENGTH(buf, offset);
        domain_pointer->name = buf+offset+HDR_LENGTH;
        return zone_lookup_exact2(zone, domain_pointer->name, domain_pointer->length);
    default:
        return 0;
    }
}
#endif


/****************************************************************************
 ****************************************************************************/
static void
xm_string(unsigned char *buf, unsigned *offset, unsigned max, const unsigned char *src, unsigned src_length)
{
    if (*offset + src_length <= max)
        memcpy(&buf[*offset], src, src_length);
    *offset += src_length;
}
static void
xm_integer32(unsigned char *buf, unsigned *offset, unsigned max, uint64_t src)
{
    if (*offset + 4 <= max) {
        buf[*offset + 0] = (unsigned char)(src>>24);
        buf[*offset + 1] = (unsigned char)(src>>16);
        buf[*offset + 2] = (unsigned char)(src>> 8);
        buf[*offset + 3] = (unsigned char)(src>> 0);
    }   
    *offset += 4;
}
void
xm_ttl(unsigned char *buf, unsigned *offset, unsigned max, uint64_t src)
{
    xm_integer32(buf, offset, max, src);
}

void
xm_integer16(unsigned char *buf, unsigned *offset, unsigned max, uint64_t src)
{
    if (*offset + 2 <= max) {
        buf[*offset + 0] = (unsigned char)(src>> 8);
        buf[*offset + 1] = (unsigned char)(src>> 0);
    }   
    *offset += 2;
}
static void
xm_integer8(unsigned char *buf, unsigned *offset, unsigned max, uint64_t src)
{
    if (*offset + 1 <= max) {
        buf[*offset + 0] = (unsigned char)(src>> 0);
    }   
    *offset += 1;
}

void
xm_nsec_bitmap(unsigned char *buf, unsigned *offset, unsigned max, unsigned count, const unsigned short *list)
{
    unsigned max_type = 0;
    unsigned i;

    /* First, find the maximum */
    for (i=0; i<count; i++) {
        if (max < list[i])
            max = list[i];
    }

    /* Now go through all possible bit masks */
    for (i=0; i<max_type; i += 256) {
        unsigned char bitmask[32];
        unsigned bitmask_length = 0;
        unsigned j;

        memset(bitmask, 0, sizeof(bitmask));

        for (j=0; j<count; j++) {
            unsigned x;
            if ((list[j] & 0xFF00) != (unsigned short)(i & 0xFF00))
                continue;
            x = list[j]&0xFF;

            bitmask[x>>3] |= (1<<(x&0x7));
            if (bitmask_length < (x>>3))
                bitmask_length = (x>>3);
        }

        xm_integer8(buf, offset, max, i>>8);
        xm_integer8(buf, offset, max, bitmask_length);
        xm_string(buf, offset, max, bitmask, bitmask_length+1);
    }
}

/****************************************************************************
 ****************************************************************************/
static unsigned
entry_marshal(
    int type,
    unsigned rdlength, const unsigned char *rdata,
    unsigned char *buf, unsigned offset, unsigned max)
{
    unsigned start_offset = offset;

    switch (type) {
    default:
        if (offset + rdlength <= max)
            memcpy(&buf[offset], rdata, rdlength);
        offset += rdlength;
    }

    /* fixup the length */
    if (start_offset <= max) {
        unsigned marshalled_length = offset - start_offset;
        buf[start_offset-2] = (unsigned char)(marshalled_length>> 8);
        buf[start_offset-1] = (unsigned char)(marshalled_length>> 0);
    }

    return offset - start_offset;
}


/****************************************************************************
 ****************************************************************************/
void
entry_print_selfname(const struct DBEntry *entry)
{
    unsigned i;
    const unsigned char *name = entry->buf;
    unsigned name_length = entry->domain_length;

    for (i=0; i<name_length; i++) {
        fprintf(stderr, "%.*s", name[i], &name[i+1]);
        i += name[i];
        if (i+1<name_length)
            fprintf(stderr, ".");
    }
    if (name_length == 0)
        fprintf(stderr, "@");
    fprintf(stderr, " ");
}

/****************************************************************************
 ****************************************************************************/
unsigned 
entry_chain_length(const struct DBEntry *entry)
{
    unsigned chain_length;

    chain_length = 0;
    while (entry) {
        entry = entry->next;
        chain_length++;
    }
    return chain_length;
}

extern void zprint_rr(FILE *fp, unsigned type, const unsigned char *px, unsigned max);

/****************************************************************************
 ****************************************************************************/
void
print_entry(const struct DBEntry *entry, FILE *fp)
{
    const unsigned char *px = entry->buf;
    unsigned i;

    for (i=0; i<entry->domain_length; i += px[i] + 1) {
        fprintf(fp, "%.*s.", px[i], px+i+1);
    }

    for (i=entry->domain_length; i<entry->offset; ) {
        struct RRSETPARSER R = {0};
        R_init(&R, entry->buf + i);

        while (R.offset < R.max) {
            unsigned rdlength;
            unsigned rdoffset;
            const unsigned char *rdata;

            R_next_rr(&R, &rdlength, &rdoffset);
            rdata = entry->buf + rdoffset + i;

            zprint_rr(stderr, R.type, rdata, rdlength);
        
        }

        i += R.max;
    }
}

/****************************************************************************
 ****************************************************************************/
static int
entry_has_rr(
    struct DBEntry *entry, 
    int type,
    unsigned ttl,
    unsigned in_rdlength,
    const unsigned char *in_rdata)
{
    unsigned i;
    struct RRSETPARSER R = {0};

    //if (type == 0x2e)
    //    ;//printf(".");

    for (i=entry->domain_length; i<entry->offset; ) {
        R_init(&R, entry->buf + i);

        if (R.type == type)
            break;
        i += R.max;
    }
    if (i >= entry->offset)
        return 0;

    while (R.offset < R.max) {
        unsigned rdlength;
        unsigned rdoffset;
        const unsigned char *rdata;

        R_next_rr(&R, &rdlength, &rdoffset);
        rdata = entry->buf + rdoffset + i;
        if (rdlength != in_rdlength)
            continue;
        
        if (memcmp(rdata, in_rdata, rdlength) == 0)
            return 1;
    }

    return 0;
}

/****************************************************************************
 ****************************************************************************/
static int
entry_add_rr(
    struct DBEntry **p_record, 
    int type,
    unsigned ttl,
    unsigned rdlength,
    const unsigned char *rdata)
{
    struct DBEntry *entry = *p_record;
    unsigned marshalled_length;
    

    /*if (type == TYPE_RRSIG && _stricmp(entry->buf, "\x20" "CK0POJMG874LJREF7EFN8430QVIT8BSM") == 0) {
        zprint_rr(stderr, type, rdata, rdlength);
    }*/

    /*
     * Attempt to marshal the data at end of entry. This function
     * aborts if it overflow the entry, meaning that we need to expand
     * the entry to make sure there is enough space, then marshal
     * a second time.
     * CODEAUDIT: This is where you want to look for a typical buffer-overflow
     * problem. Look at the marshalling function to see that it's 
     * rigorous enough. Also, if you fuzz this program and succeed
     * in overflowing here, I've put a nice little sentry that'll
     * tell you that you succeeded.
     */
again:
    marshalled_length = entry_marshal(
                            type, rdlength, rdata,
                            entry->buf, 
                            entry->offset+2, 
                            entry->sizeof_buf
                            );
    if (entry->buf[entry->sizeof_buf] != 0xa3) {
        printf("overflow: %.*s (YOUR FUZZING SUCCEEDED)\n", entry->domain_length, entry->buf);
        exit(1);
    }



    /*
     * If the data won't fit, then expand the entry.
     * TODO: right now, this is a simple realloc(). In the future, this 
     * needs to work from thread-local memory pools.
     */
    assert(entry->offset <= entry->sizeof_buf);
    if (entry->offset + marshalled_length + 2 > entry->sizeof_buf) {
        unsigned new_size;

        if (entry->offset + marshalled_length + 2 > 0xFFFFUL) {
            print_entry(entry, stderr);
            fprintf(stderr, "exceeded maximum entry size\n");
            return Failure;
        }

        resize_chunk:
        entry_bytes += (unsigned short)ALIGN(marshalled_length + 2, BLOCK_SIZE-1);

        new_size = entry->sizeof_buf + (unsigned short)ALIGN(marshalled_length + 2, BLOCK_SIZE-1);
        if (new_size > 0xFFFF) {
            print_entry(entry, stderr);
            fprintf(stderr, "exceeded maximum entry size\n");
            return Failure;
        } else
            entry->sizeof_buf = (unsigned short)new_size;

        *p_record = REALLOC2(*p_record, offsetof(struct DBEntry, buf) + entry->sizeof_buf + 1, 1);

        entry = *p_record;
        if (entry == 0) {
            fprintf(stderr, "ran out of memory\n");
            exit(1);
        }
        entry->buf[entry->sizeof_buf] = 0xa3; /*fuzzing sentry*/
        assert(entry->offset <= entry->sizeof_buf);
        goto again;
    }
    assert(entry->offset <= entry->sizeof_buf);


    /*
     * KLUDGE MASTER FIXUPS
     *
     * Assuming we have 'xxx' for his new data, the bytes currently look like
     * the following:
     * [1] RRRRRAaaaaBbbbbbCccccXxxxx.xxx
     *                          ^^^^^ ^^^
     *     Ah! we are in the right location! we just need to fix the length
     *     and we are good. This happens as we sequentially add data of the 
     *     same type.
     * [2] RRRRRAaaaaXxxxxBbbbbbCcccc.xxx
     *               ^^^^^            ^^^
     *     Doh! we are out of order, so we need to rearrange memory.
     *     Assuming we'll have more the same type, we'll move the
     *     all the xx to the end, making it look like case [1].
     * [2] RRRRRAaaaaBbbbbbCcccc.xxx
     *                           ^^^
     *     There is no data of type 'x', so we need to create a
     *     header for it.
     */
    {
        unsigned i;

        for (i=entry->domain_length; i<entry->offset; ) {
            struct RRSETPARSER R;
            R_init(&R, entry->buf + i);
            if (R.type == type && i + R.max != entry->offset) {
                /* [2] need to rearrange stuff. Assume we'l*/
                unsigned char tmp[65536];
                memcpy(&tmp[0], &entry->buf[i], R.max);
                memmove(&entry->buf[i], &entry->buf[i+R.max], entry->offset-i-R.max);
                memcpy(&entry->buf[entry->offset - R.max], &tmp[0], R.max);
                /* we'll now fall through to case [1] below */
                continue;
            }
            if (R.type == type && i + R.max == entry->offset) {
                /* [1] append to trailing RRset */
                R.max += marshalled_length + 2;
                entry->buf[i+0] = (unsigned char)(R.max>>8);
                entry->buf[i+1] = (unsigned char)(R.max>>0);
                break;
            }
            i += R.max;
        }

        if (i >= entry->offset) {
            /* [3] create new RRset */
            if (entry->offset + 2 + marshalled_length + 8 > entry->sizeof_buf) {
                marshalled_length += entry->offset + 2 + marshalled_length + 8 - entry->sizeof_buf;
                goto resize_chunk;
            }
            memmove(&entry->buf[i + 8], &entry->buf[i], 2 + marshalled_length);

            entry->buf[i+0] = (unsigned char)((2+marshalled_length + 8)>>8);
            entry->buf[i+1] = (unsigned char)((2+marshalled_length + 8)>>0);
            entry->buf[i+2] = (unsigned char)(type>>8);
            entry->buf[i+3] = (unsigned char)(type>>0);
            entry->buf[i+4] = (unsigned char)(ttl>>24);
            entry->buf[i+5] = (unsigned char)(ttl>>16);
            entry->buf[i+6] = (unsigned char)(ttl>>8);
            entry->buf[i+7] = (unsigned char)(ttl>>0);
            entry->offset += 8;
        }

    
    }
    entry->offset += (unsigned short)(2 + marshalled_length);

    if (entry->buf[entry->sizeof_buf] != 0xa3) {
        printf("overflow: %.*s (YOUR FUZZING SUCCEEDED)\n", entry->domain_length, entry->buf);
        exit(1);
    }

    /*
     * Mark "NS" cut records for enabling faster searches. That's because
     * an "NS" record trumps any other RRsets (except DNSsec records),
     * so most searches don't need to go deeper looking for NS records
     */
    if (type == TYPE_NS)
        (*p_record)->is_ns = 1;

    //print_entry(*p_record, stderr);
    return Success;
}


/****************************************************************************
 ****************************************************************************/
void
entry_create_self(
    struct DBEntry **p_record, 
    const struct DB_XDomain *xdomain, 
    unsigned prefix_labels,
    int type,
    unsigned ttl,
    unsigned rdlength,
    const unsigned char *rdata
    )
{
    unsigned char name[256+1];
    unsigned name_length;
    unsigned i;
    unsigned chain_length;


    /* 
     * Format our internal name 
     */
    name_length = 0;
    for (i=xdomain->label_count; i>prefix_labels; i--) {
        unsigned label_length = xdomain->labels[i-1].name[0] + 1;
        memcpy(name+name_length, xdomain->labels[i-1].name, label_length);
        name_length += label_length;
        assert(name_length + 1 < sizeof(name));
        name[name_length] = '\0'; /*FIXME: test this for overflow */
    }

//printf("." " -> %s 0x%x\n", name, xdomain->hash);

    /* Move forward until we get a valid entry */
    chain_length = 0;
    for (   ; 
            *p_record; 
            p_record = &(*p_record)->next) {
        chain_length++;

        /* Make sure hashes equal */
        /*if ((*p_record)->hash != hash)
            continue;*/

        /* Make sure the name lengths equal */
        if ((*p_record)->domain_length != name_length)
            continue;

        /* Make sure then name equals */
        if (memcasecmp((*p_record)->buf, name, name_length) != 0)
            continue;
        break;
    }
    total_chain_length += chain_length;

    /* If we cannot find the entry, then create a new
     * one */
    if ((*p_record) == NULL) {
        struct DBEntry *entry;
        size_t size_to_malloc = sizeof(*entry);

        if (name_length > sizeof(entry->buf)) {
            size_to_malloc += name_length + 16;
        }

        size_to_malloc = ALIGN(size_to_malloc, BLOCK_SIZE-1);

        /* Allocate space for a linked-list at this hash location */
        entry = MALLOC2(size_to_malloc+1);
        memset(entry, 0, offsetof(struct DBEntry, buf));

        //entry->hash = hash;
        entry->domain_length = (unsigned char)name_length;
        memcpy(entry->buf, name, name_length);
        entry->offset = (unsigned short)name_length;
        entry->sizeof_buf = (unsigned short)(size_to_malloc - offsetof(struct DBEntry, buf));
        
        entry->buf[entry->sizeof_buf] = 0xA3;

        entry->next = 0;
        (*p_record) = entry;

        entry_count++;
        entry_bytes += size_to_malloc;

    }

    /*
     * At the resource-record 
     */
    if (!entry_has_rr(*p_record, type, ttl, rdlength, rdata)) {
        int x;
        
        x = entry_add_rr(p_record, type, ttl, rdlength, rdata);
        if (x == Failure)
            print_entry(*p_record, stdout);
    }
}

/****************************************************************************
 ****************************************************************************/
const struct DBEntry *
entry_find(
    const struct DBEntry *entry,
    const struct DB_XDomain *xdomain,
    unsigned prefix_labels,
    unsigned label_count)
{
    //uint64_t hash = xdomain->hash;
    unsigned char name[256];
    unsigned name_length;
    unsigned i;

    
    /* 
     * Format our internal name 
     */
    name_length = 0;
    for (i=label_count; i>prefix_labels; i--) {
        unsigned label_length = xdomain->labels[i-1].name[0] + 1;
        memcpy(name+name_length, xdomain->labels[i-1].name, label_length);
        name_length += label_length;
        assert(name_length < sizeof(name));
        name[name_length] = '\0'; /*FIXME: test this for overflow */
    }

//printf("." "<-  %s 0x%x\n", name, xdomain->hash);

    /* Move forward until we get a valid entry */
    for (; entry; entry = entry->next) {
        /* Make sure hashes equal */
        //if (entry->hash != hash)
        //    continue;

        /* Make sure the name lengths equal */
        if (entry->domain_length != name_length)
            continue;

        /* Make sure then name equals */
        if (memcasecmp(entry->buf, name, name_length) != 0)
            continue;
        break;
    }

    return entry;
}

/****************************************************************************
 ****************************************************************************/
int
entry_is_delegation(const struct DBEntry *entry)
{
    if (entry == NULL)
        return 0;
    return entry->is_ns;
}


/****************************************************************************
 ****************************************************************************/
struct DomainPointer
entry_name(const struct DBEntry *entry)
{
    struct DomainPointer result;
    
    result.length = entry->domain_length;
    result.name = entry->buf;

    return result;
}
