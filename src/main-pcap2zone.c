#define _CRT_SECURE_NO_WARNINGS
#include "db.h"
#include "domainname.h"
#include "zonefile-parse.h"
#include "zonefile-load.h"
#include "zonefile-tracker.h"
#include "success-failure.h"
#include "adapter-pcapfile.h"
#include "network.h"
#include "thread.h"
#include "adapter.h"
#include "proto-preprocess.h"
#include "proto-dns.h"
#include "zonefile-rr.h"
#include <string.h>

extern void dns_extract_name(const unsigned char px[], unsigned offset, unsigned max, struct DomainPointer *name);
extern unsigned dns_name_skip(const unsigned char px[], unsigned offset, unsigned max);

static const struct DomainPointer root = {(const unsigned char*)"\0",1};

struct Pcap2Zone
{
    struct Catalog *db;

};

/****************************************************************************
 ****************************************************************************/
static void extract_name(
    unsigned char *dst, unsigned *dst_offset, size_t dst_max,
    const unsigned char *src, unsigned *src_offset, size_t src_max)
{
    struct DomainPointer rrname;

    if (*dst_offset + 256 > dst_max)
        return;
    
    rrname.name = dst + *dst_offset;
    dns_extract_name(src, *src_offset, (unsigned)src_max, &rrname);
    *dst_offset += rrname.length;
    dst[*dst_offset] = 0;
    *dst_offset += 1;

    *src_offset = dns_name_skip(src, *src_offset, (unsigned)src_max);
}
static void extract_copy(
    unsigned char *dst, unsigned *dst_offset, size_t dst_max,
    const unsigned char *src, unsigned *src_offset, size_t src_max,
    unsigned len)
{
    if (*dst_offset + len <= dst_max) {
        memcpy( dst + *dst_offset,
                src + *src_offset,
                len);
    }
    *dst_offset += len;
    *src_offset += len;
}

/****************************************************************************
 ****************************************************************************/
static int
grab_dns_response(struct Catalog *catalog, const unsigned char *px, unsigned offset, unsigned max)
{
    struct DNS_Incoming dns[1];
    unsigned i;
    struct DomainPointer domain;
    unsigned char domain_buffer[256];
    char unsigned tmp_buffer[65536];
    unsigned tmp_offset;
    unsigned src_offset;

    /* kludge */
    px += offset;
    offset = 0;
    max -= offset;

    domain.name = domain_buffer;

    proto_dns_parse(dns, px, offset, max);

    if (!dns->is_valid)
        return Failure;
    if (!dns->qr)
        return Failure;

    for (i=dns->qdcount; i<dns->rr_count; i++) {
        int type;
        int xclass;
        unsigned ttl;
        unsigned rdlength;
        const unsigned char *rdata;

        offset = dns->rr_offset[i];

        /* extract the domain name */
        dns_extract_name(px, offset, max, &domain);
        offset = dns_name_skip(px, offset, max);

        /* extract the data */
        if (offset + 10 > max)
            continue;
        type = px[offset+0]<<8 | px[offset+1];
        xclass = px[offset+2]<<8 | px[offset+3];
        if (xclass != 1)
            continue;
        ttl = px[offset+4]<<24 | px[offset+5]<<16 | px[offset+6]<<8 | px[offset+7];
        rdlength = px[offset+8]<<8 | px[offset+9];
        rdata = &px[offset + 10];
        offset += 10;
        

        /* insert the data into the catalog */
        if (offset + rdlength > max)
            continue;
        else
            offset += rdlength;

        tmp_offset = 0;
        src_offset = (unsigned)(rdata - px);

        switch (type) {
        case 41: /*OPT*/
            continue;

        case TYPE_NS:
        case TYPE_CNAME:
        case TYPE_PTR:
            extract_name(   tmp_buffer, &tmp_offset, sizeof(tmp_buffer),
                            px, &src_offset, max);
            rdata = tmp_buffer;
            rdlength = tmp_offset;
            break;

        case TYPE_SOA:
            extract_name(   tmp_buffer, &tmp_offset, sizeof(tmp_buffer),
                            px, &src_offset, max);
            extract_name(   tmp_buffer, &tmp_offset, sizeof(tmp_buffer),
                            px, &src_offset, max);
            extract_copy(   tmp_buffer, &tmp_offset, sizeof(tmp_buffer),
                            px, &src_offset, max,
                            offset-src_offset);
            rdata = tmp_buffer;
            rdlength = tmp_offset;
            break;
        case TYPE_RRSIG:
            //printf(".");
            break;
        }


        zonefile_load(
            domain,
            root,
            type,
            ttl,
            rdlength,
            rdata,
            10000,
            catalog,
            "",
            0);

        
    }

    return Success;
}


extern void LOAD(const char *string, struct ZoneFileParser *parser);

/****************************************************************************
 ****************************************************************************/
int
pcap2zone(int argc, char *argv[])
{
    struct Pcap2Zone pcap2zone[1];
    struct Catalog *catalog;
    int i;

    /*
     * Create a catalog/database
     */
    catalog = catalog_create();
    pcap2zone->db = catalog;

    /* 
     * Initialize it with a pseudo-SOA record for the root zone
     */
    {
    	struct ZoneFileParser *parser;
        parser = zonefile_begin(
                    root,           /* origin */
                    60,             /* TTL */
                    10000,          /* filesize */
                    "<pcap2zone>",  /* filename */
                    zonefile_load,  /* callback */
                    catalog,        /* callback data */
                    0
                    );
        LOAD("$TTL 60\r\n"
             "@    IN    SOA   ns hostmaster (\r\n"
             "                     2003080800 ; sn = serial number\r\n"
             "                     172800     ; ref = refresh = 2d\r\n"
             "                     15m        ; ret = update retry = 15m\r\n"
             "                     1209600    ; ex = expiry = 2w\r\n"
             "                     1H         ; nx = nxdomain ttl = 1h\r\n"
             "                     )\r\n", parser);
        zonefile_end(parser);

    }

    
    
    for (i=2; i<argc; i++) {
        const char *filename = argv[i];
        struct Tracker tracker[1];
        struct PcapFile *p;
        //uint64_t filesize;

        memset(tracker, 0, sizeof(tracker[0]));
        //filesize = 
            tracker_get_filesize(tracker, filename);

        p = pcapfile_openread(filename);
        if (p == NULL) {
            perror(filename);
            continue;
        }
               

        for (;;) {
            unsigned char buf[65536];
            int x;
            unsigned secs;
            unsigned usecs;
            unsigned original_length;
            unsigned bytes_read;

            x = pcapfile_readframe(
	            p,
                &secs, &usecs,
                &original_length, &bytes_read,
                buf, 
                sizeof(buf)
	            );
            if (x <= 0)
                break;


            {
                struct PreprocessedInfo info;

                x = preprocess_frame(
                    buf, 
                    bytes_read,
                    1,
                    &info);


                if (x && info.found == FOUND_DNS && info.port_src == 53)
                    grab_dns_response(catalog, buf, info.found_offset, bytes_read);

            }

            tracker_report(tracker, bytes_read);
        }

        pcapfile_close(p);
    }


    return Success;
}

