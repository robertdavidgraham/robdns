#define _CRT_SECURE_NO_WARNINGS
/*

    IMPORTANT! the selftest creates a database, parses zone-file input, handles
    a bunch of requests, then destroys the database. This self-test runs by
    default EVERY time the program is run. Therefore, after compiling on a
    new platform, just run the program with no arguments to run the self-test
    in order to verify that compilation has succeeded.
*/
#include "adapter.h"
#include "network.h"
#include "zonefile-parse.h"
#include "success-failure.h"
#include "zonefile-rr.h"
#include "db.h"
#include "db-zone.h"
#include "packet.h"
#include "unusedparm.h"
#include "adapter-pcapfile.h"
#include "thread.h"
#include "zonefile-load.h"
#include "string_s.h"
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>


extern void dns_extract_name(const unsigned char px[], unsigned offset, unsigned max, struct DomainPointer *name);
extern unsigned dns_name_skip(const unsigned char px[], unsigned offset, unsigned max);

static const struct DomainPointer example_origin = {(const unsigned char*)"\7example\3com",12};

extern const char *name_of_type(unsigned type);

const char *selftestthing[] = {
"$ORIGIN example.com.     ; designates the start of this zone file in the namespace\r\n",
"$TTL 1h                  ; default expiration time of all resource records without their own TTL value\r\n",
"example.com.  IN  SOA  ns.example.com. username.example.com. (\r\n",
"              2007120710 ; serial number of this zone file\r\n",
"              1d         ; slave refresh (1 day)\r\n",
"              2h         ; slave retry time in case of a problem (2 hours)\r\n",
"              4w         ; slave expiration time (4 weeks)\r\n",
"              1h         ; maximum caching time in case of failed lookups (1 hour)\r\n",
"              )\r\n",
"example.com.  NS    ns                    ; ns.example.com is a nameserver for example.com\r\n",
"example.com.  NS    ns.somewhere.example. ; ns.somewhere.example is a backup nameserver for example.com\r\n",
"example.com.  MX    10 mail.example.com.  ; mail.example.com is the mailserver for example.com\r\n",
"@             MX    20 mail2.example.com. ; equivalent to above line, \"@\" represents zone origin\r\n",
"@             MX    50 mail3              ; equivalent to above line, but using a relative host name\r\n",
"example.com.  A     192.0.2.1             ; IPv4 address for example.com\r\n",
"              AAAA  2001:db8:10::1        ; IPv6 address for example.com\r\n",
"ns            A     192.0.2.2             ; IPv4 address for ns.example.com\r\n",
"              AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com\r\n",
"www           CNAME example.com.          ; www.example.com is an alias for example.com\r\n",
"wwwtest       CNAME www                   ; wwwtest.example.com is another alias for www.example.com\r\n",
"mail          A     192.0.2.3             ; IPv4 address for mail.example.com,\r\n",
"                                          ;  any MX record host must be an address record\r\n",
"                                          ; as explained in RFC 2181 (section 10.3)\r\n",
"mail2         A     192.0.2.4             ; IPv4 address for mail2.example.com\r\n",
"mail3         A     192.0.2.5             ; IPv4 address for mail3.example.com\r\n",
0
};



/****************************************************************************
 ****************************************************************************/
void
LOAD(const char *string, struct ZoneFileParser *parser)
{
    size_t string_length = strlen(string);
    zonefile_parse(
        parser,
        (const unsigned char *)string,
        string_length
        );

}

/****************************************************************************
 ****************************************************************************/
struct TestAdapter
{
    struct Adapter *adapter;
    struct Selftest *parent;
    unsigned char buf[65536];

};

struct Selftest
{
    va_list marker;
    struct Catalog *db;
    struct ZoneFileParser *parser;
    struct Thread thread[1];
    struct TestAdapter client;
    struct TestAdapter server;

    int test_code;
    int total_code;

    unsigned is_edns0:1;
};

/****************************************************************************
 ****************************************************************************/
static struct Packet 
selftest_alloc_packet(struct Adapter *adapter, struct Thread *thread)
{
    struct TestAdapter *testadapter = (struct TestAdapter *)adapter->userdata;
    struct Packet pkt;

    UNUSEDPARM(thread);

    pkt.buf = testadapter->buf;
    pkt.max = sizeof(testadapter->buf);
    pkt.offset = 0;
    pkt.fixup.network = 0;
    pkt.fixup.transport = 0;

    return pkt;
}

void selftest_client_xmit_packet(struct Adapter *adapter, struct Thread *thread, struct Packet *pkt)
{
    struct TestAdapter *testadapter = (struct TestAdapter *)adapter->userdata;
    struct TestAdapter *other;
    struct Selftest *selftest = testadapter->parent;
    struct Frame frame[1];

    if (&selftest->client == testadapter)
        other = &selftest->server;
    else
        other = &selftest->client;

    {
        struct PcapFile *x;
        x = pcapfile_openwrite("self-query.pcap", 1);
        pcapfile_writeframe(x, pkt->buf, pkt->max, pkt->max, 0, 0);
        pcapfile_close(x);
    }

    network_receive(
                frame,
                thread,
                other->adapter,
                0,
                0,
			    pkt->buf,
                pkt->max);
}

struct CheckerA
{
    const char *rname;
    int rtype;
    unsigned rdlength;
    const void *rdata;
};
struct CheckerB
{
    unsigned offset_name;
    unsigned offset_data;
};
struct Checker
{
    unsigned a_count;
    unsigned b_count;
    struct CheckerA a[100];
    struct CheckerB b[100];
};

/****************************************************************************
 * Expands the packet's SOA record to a full uncompressed SOA record so
 * that we can compare it with the origin SOA that we parsed.
 *
 * @param buf
 *      The target buffer that will hold the expanded SOA record.
 * @param buf_offset
 *      The current offset into this buffer. We'll move this index
 *      forward as we append to the buffer
 * @param buf_size
 *      The size of the buffer, to prevent buffer overruns.
 * @param soa
 *      The compressed SOA record from the packet.
 * @param soa_length
 *      The RDLENGTH (compressed length) of the packet SOA record.
 * @param hdr
 *      The beginning of the packet header, which we need when decompressing
 *      names (because DNS name compression is done as offsets from the
 *      start of the packet).
 ****************************************************************************/
int expand_soa(
    unsigned char *buf, unsigned *buf_offset, size_t buf_size,
    const unsigned char *soa, unsigned soa_length,
    const unsigned char *hdr)
{
    struct DomainPointer d;
    unsigned soa_offset = (unsigned)(soa-hdr);
    unsigned soa_max = soa_length + soa_offset;

    /* Decompress the first DNS name in the record (which is the 
     * primary DNS server name) */
    d.name = buf + *buf_offset;
    dns_extract_name(hdr, soa_offset, soa_max, &d);
    soa_offset = dns_name_skip(hdr, soa_offset, soa_max);
    *buf_offset += d.length;
    buf[*buf_offset] = 0;
    *buf_offset += 1;

    /* Decompress the second DNS name in the record (which is the
     * contact email address */
    d.name = buf + *buf_offset;
    dns_extract_name(hdr, soa_offset, soa_max, &d);
    soa_offset = dns_name_skip(hdr, soa_offset, soa_max);
    *buf_offset += d.length;
    buf[*buf_offset] = 0;
    *buf_offset += 1;

    /* remainder */
    if (soa_offset > soa_max)
        return Failure;
    memcpy(buf + *buf_offset, hdr+soa_offset, soa_max-soa_offset);

    *buf_offset += soa_max - soa_offset;
    return Success;
}


int
checker_check(const struct CheckerA *a, const struct CheckerB *b, const unsigned char *px)
{
    const unsigned char *a_name = (const unsigned char *)a->rname;
    const unsigned char *b_name = px;
    unsigned a_offset;
    unsigned b_offset;
    int b_type;
    int b_class;
    unsigned b_rdlength;
    const unsigned char *b_rdata;

    b_type = px[b->offset_data+0]<<8 | px[b->offset_data+1];
    if (b_type != a->rtype)
        return 0;
    b_class = px[b->offset_data+2]<<8 | px[b->offset_data+3];
    if (b_class != 1)
        return 0;
    b_rdlength = px[b->offset_data+8]<<8 | px[b->offset_data+9];
    b_rdata = px + b->offset_data + 10;


    /*
     * First let's check the names
     */
    a_offset = 0;
    b_offset = b->offset_name;
    for (;;) {
        unsigned a_len;
        unsigned b_len;

        /* handle compression at this point */
        if (b_name[b_offset] & 0xC0) {
            b_offset = (b_name[b_offset]&0x3F)<<8 | b_name[b_offset+1];
        }

        /* find the lable lengths */
        for (a_len=0; a_name[a_offset+a_len] != '.' && a_name[a_offset+a_len]; a_len++)
            ;
        b_len = b_name[b_offset++];

        /* compare the labels */
        if (a_len != b_len)
            return 0;
        if (memcasecmp(&a_name[a_offset], &b_name[b_offset], a_len) != 0)
            return 0;

        /* move to next label */
        a_offset += a_len;
        if (a_name[a_offset] == '.')
            a_offset++;
        b_offset += b_len;

        /* BREAK when we reac the end */
        if (a_len == 0)
            break; 
    }

    /* now let's check the data */
    switch (b_type) {
    case TYPE_SOA:
        {
            unsigned char buf[1024];
            unsigned buf_length = 0;
            int x;
            

            x = expand_soa(buf, &buf_length, sizeof(buf),
                b_rdata, b_rdlength,
                px);
            if (x == Failure)
                return 0;
            if (a->rdlength != buf_length)
                return 0;
            
            return memcasecmp(a->rdata, buf, buf_length) == 0;
        }
        break;

    default:
        if (a->rdlength != b_rdlength)
            return 0;
        return memcmp(a->rdata, b_rdata, b_rdlength) == 0;
    }
}
 enum {
     VERIFY_PARTIAL,
     VERIFY_EXACT = 1,
 };

/****************************************************************************
 * Verifies a response sorta matches the expected response. We do this by
 * checking that it has AT LEAST the elements specified in the parameter
 * list. It MAY contain other elements, like EDNS0 OPT or glue records, but
 * we aren't checking for that here.
 *
 * Note that we do a MANUAL decode of the packet here, rather than leverage
 * the packet decoding features elsewhere in the code base. That's because
 * it's an independent check of the real code.
 ****************************************************************************/
static int
selftest_verify(struct Selftest *selftest, const unsigned char *px, unsigned offset, unsigned max)
{
    unsigned qdcount;
    unsigned ancount;
    unsigned nscount;
    unsigned arcount;
    va_list marker;
    struct Checker checker[1];
    unsigned i;
    const unsigned char *dns_header = &px[offset];
    unsigned offset_start = offset;
    int verify_type;

    memcpy(&marker, &selftest->marker, sizeof(marker));

    /*
     * Kludge: test for exact match. This is used only a in a few
     * places to test specific functionality, like EDNS0, most 
     * other matches are partial matches
     */
    verify_type = va_arg(marker, int);
    if (verify_type == VERIFY_EXACT) {
        unsigned length = va_arg(marker, unsigned);
        const unsigned char *p = va_arg(marker, const unsigned char *);
        if (length != max-offset)
            return Failure;
        if (memcmp(px+offset, p, length) == 0)
            return Success;
        else
            return Failure;
    } else
        memcpy(&marker, &selftest->marker, sizeof(marker));



    memset(checker, 0, sizeof(checker));

    if (max-offset < 12)
        return Failure;

    qdcount = px[offset+ 4]<<8 | px[offset+ 5];
    ancount = px[offset+ 6]<<8 | px[offset+ 7];
    nscount = px[offset+ 8]<<8 | px[offset+ 9];
    arcount = px[offset+10]<<8 | px[offset+ 11];
    offset += 12;

    UNUSEDPARM(arcount);
    UNUSEDPARM(nscount);
    UNUSEDPARM(ancount);

    if (qdcount != 1)
        return Failure;

    /* skip query name */
    while (offset < max && px[offset])
        offset += px[offset] + 1;
    if (offset < max && px[offset] == 0)
        offset++;
    if (offset + 4 > max)
        return Failure;
    if (1 != (px[offset+2]<<8 | px[offset+3]))
        return Failure;
    offset += 4;

    while (offset < max) {
        checker->b[checker->b_count].offset_name = offset-offset_start;

        while (offset < max) {
            if (px[offset] == 0) {
                offset++;
                break;
            } else if (px[offset]&0xC0) {
                offset += 2;
                break;
            } else
                offset += px[offset]+1;
        }

        checker->b[checker->b_count].offset_data = offset-offset_start;
        checker->b_count++;

        if (offset + 10 > max)
            return Failure;
        offset += 10 + (px[offset+8]<<8 | px[offset+9]);
    }

    /*
     * Now go through and pull out all the variable length parms
     */
    for (;;) {
        unsigned i = checker->a_count;;
        checker->a[i].rname = va_arg(marker, const char *);
        if (checker->a[i].rname == 0)
            break;
        checker->a[i].rdlength = va_arg(marker, unsigned);
        checker->a[i].rdata = va_arg(marker, const unsigned char *);
        checker->a[i].rtype = va_arg(marker, int);
        checker->a_count++;
    }

    /*
     * Now make sure that the response contains all the expected data
     */
    for (i=0; i<checker->a_count; i++) {
        unsigned j;

        for (j=0; j<checker->b_count; j++) {
            if (checker_check(&checker->a[i], &checker->b[j], dns_header))
                break;
        }
        if (j == checker->b_count) {
            /* not found, so failure */
            return Failure;
        }
    }

    return Success;
}

/****************************************************************************
 ****************************************************************************/
void
selftest_server_xmit_packet(struct Adapter *adapter, struct Thread *thread, struct Packet *pkt)
{
    struct TestAdapter *testadapter = (struct TestAdapter *)adapter->userdata;
    struct TestAdapter *other;
    struct Selftest *selftest = testadapter->parent;

    UNUSEDPARM(thread);

    if (&selftest->client == testadapter)
        other = &selftest->server;
    else
        other = &selftest->client;

    UNUSEDPARM(other);

    {
        struct PcapFile *x;
        x = pcapfile_openwrite("self-response.pcap", 1);
        pcapfile_writeframe(x, pkt->buf, pkt->max, pkt->max, 0, 0);
        pcapfile_close(x);
    }

    selftest->test_code = selftest_verify(selftest, pkt->buf, 42, pkt->max);

}


/****************************************************************************
 * Appends a name onto our self-test query packet
 ****************************************************************************/
static void
append_name(struct Packet *pkt, const char *name)
{
    unsigned i;
    for (i=0; name[i] == '.'; i++)
        ;
    for (; name[i];) {
        unsigned len;
        for (len=0; name[i+len] && name[i+len] != '.'; len++)
            ;
        if (pkt->offset + len + 1 <= pkt->max) {
            pkt->buf[pkt->offset] = (unsigned char)len;
            memcpy(&pkt->buf[pkt->offset+1], &name[i], len);
        }
        pkt->offset += len + 1;
        i += len;
        if (name[i] == '.')
            i++;
    }
}

/****************************************************************************
 * Send a DNS request to ourselves, then parse the response and make sure
 * it contains at least the information we requested.
 ****************************************************************************/
int
QUERY(
        const char *query_name,     /* like "www" */
        int query_type,             /* like "A" or "TXT" or "MX" */
        struct Selftest *selftest, 
        //const char *rname, unsigned rdlength, const void *rdata, int rtype, 
        ...)
{
    struct Adapter *adapter = selftest->client.adapter;
    struct Adapter *adapter_server = selftest->server.adapter;
    struct Packet pkt;
    unsigned char *px;
    unsigned offset;
    
    va_start(selftest->marker, selftest);

    selftest->test_code = Failure;
    /*UNUSEDPARM(rdata);
    UNUSEDPARM(rtype);
    UNUSEDPARM(rdlength);
    UNUSEDPARM(rname);*/

    /* Since the parser cache's RRs before insertion into the catalog, we
     * need to make sure they've all been flushed into the catalog before
     * continueing. */
    if (zonefile_flush(selftest->parser) == Failure)
        return Failure;


    /* Create a request packet */
    pkt = adapter_create_request_udp(adapter, adapter_server->ipv4[0].address, 53);

    /* fill it in */
    px = pkt.buf;
    if (pkt.offset + 12 <= pkt.max) {
        offset = pkt.offset;
        px[offset++] = 0x12;
        px[offset++] = 0x34;
        px[offset++] = 0x00;
        px[offset++] = 0x00;
        px[offset++] = 0x00;
        px[offset++] = 0x01;
        px[offset++] = 0x00;
        px[offset++] = 0x00;
        px[offset++] = 0x00;
        px[offset++] = 0x00;
        px[offset++] = 0x00;
        px[offset++] = selftest->is_edns0?1:0;
    }
    pkt.offset += 12;

    /* query name */
    append_name(&pkt, query_name);
    if (query_name[strlen(query_name)-1] != '.')
        append_name(&pkt, "example.com");
    if (pkt.offset < pkt.max)
        pkt.buf[pkt.offset] = 0; /* terminating nul for domain name */
    pkt.offset++;
    if (pkt.offset + 4 <= pkt.max) {
        px[pkt.offset+0] = (unsigned char)(query_type>>8);
        px[pkt.offset+1] = (unsigned char)(query_type>>0);
        px[pkt.offset+2] = 0;
        px[pkt.offset+3] = 1;
    }
    pkt.offset += 4;

    if (selftest->is_edns0) {
        if (pkt.offset + 11 <= pkt.max) {
            memcpy(pkt.buf+pkt.offset,
                "\0\0\x29\x10\0\0\0\0\0\0\0",
                11);
        }
        pkt.offset += 11;
    }

    adapter_xmit(adapter, selftest->thread, &pkt);

    if (selftest->test_code == Failure) {
        fprintf(stderr, "<selftest>:fail: qtype=%u qname=%s\n", query_type, query_name);
        //exit(1);
        selftest->total_code = Failure;
        return Failure;
    }

    return Success;
}

/****************************************************************************
 * [1] test "zonefile" parser
 *      - test that program recognizes the zone-file format
 *      - test weird valid input
 *      - test rejection of invalid input
 * [2] test the "catalog" database
 *      - test that the database accepts good records
 *      - test that the database rejects bad records
 *      - try to break the catalog (e.g. rrsets that exceed 64k)
 * [3] test the "resolver"
 *      - use the catalog created in steps [1] and [2]
 *      - add additional entries designed to stress the resolver
 *      - verify that resolver produces correct output
 ****************************************************************************/
int
selftest(int argc, char *argv[])
{
    struct Selftest selftest[1];
	struct ZoneFileParser *parser;
    unsigned parse_results;
    unsigned i;
    const char *element;
    struct Catalog *db;
    

    UNUSEDPARM(argc);
    UNUSEDPARM(argv);

    selftest->total_code = Success;

    /*
     * Create a pseudo-network subsystem for generating packets
     */
    selftest->client.parent = selftest;
    selftest->client.adapter = adapter_create(
                                    selftest_alloc_packet, 
                                    selftest_client_xmit_packet, 
                                    &selftest->client);
    selftest->server.parent = selftest;
    selftest->server.adapter = adapter_create(
                                    selftest_alloc_packet, 
                                    selftest_server_xmit_packet, 
                                    &selftest->server);
    adapter_add_ipv4(selftest->client.adapter, 0x0a000001, 0xFFFFffff);
    adapter_add_ipv4(selftest->server.adapter, 0xC0A00002, 0xFFFFffff);


    /* create a catalog/database, this is where all the parsed zonefile
     * records will be put */
    selftest->db = catalog_create();
    selftest->thread->catalog = selftest->db;
    db = selftest->db;

    /* create a parser object */
    parser = zonefile_begin(
                example_origin, /* origin */
                60,             /* TTL */
                10000,          /* filesize */
                "<selftest>",   /* filename */
                zonefile_load,  /* callback */
                db              /* callback data */
                );
    selftest->parser = parser;

    /* needs SOA record to start */
    LOAD("$TTL 60\r\n"
         "example.com.    IN    SOA   ns hostmaster (\r\n"
         "                     2003080800 ; sn = serial number\r\n"
         "                     172800     ; ref = refresh = 2d\r\n"
         "                     15m        ; ret = update retry = 15m\r\n"
         "                     1209600    ; ex = expiry = 2w\r\n"
         "                     1H         ; nx = nxdomain ttl = 1h\r\n"
         "                     )\r\n", parser);
    QUERY("example.com.", TYPE_SOA, selftest,
        "example.com.", 0x3c, 
                "\x02" "ns" "\x07" "example" "\x03" "com" "\x00"
                "\x0a" "hostmaster" "\x07" "example" "\x03" "com" "\x00"
                "\x77\x64\x96\x60"
                "\x00\x02\xa3\x00"
                "\x00\x00\x03\x84"
                "\x00\x12\x75\x00"
                "\x00\x00\x0e\x10",
        TYPE_SOA,
        0);


    /*
     * tests the most basic name lookup there is, the "A" record
     * for an IP address.
     */
    LOAD("hydrogen A 1.0.0.1                ; a simple IP address\n", parser);
    QUERY("hydrogen", TYPE_A, selftest,
        "hydrogen.example.com.", 4, "\1\0\0\1", TYPE_A,
        0, selftest);
    selftest->is_edns0 = 1;
    QUERY("hydrogen", TYPE_A, selftest,
        "hydrogen.example.com.", 4, "\1\0\0\1", TYPE_A,
        0, selftest);
    
    /*
     * tests that an "Entry" can hold multiple "RRsets", in this case
     * for basic types
     */
    LOAD("helium A 2.0.0.1                  ; multiple RRsets\n", parser);
    LOAD("helium TXT \"hello, world\"       \n", parser);
    LOAD("helium AAAA 2002::1\n", parser);
    QUERY("helium", TYPE_ANY, selftest,
        "helium.example.com", 4, "\2\0\0\1", TYPE_A,
        "helium.example.com", 13, "\x0c" "hello, world", TYPE_TXT,
        "helium.example.com", 16, "\x20\2\0\0\0\0\0\0\0\0\0\0\0\0\0\1", TYPE_AAAA,
        0);


    /*
     * This test is designed to stress the RRset compression. All RRs in an RRset
     * must be held together. By specifying them in a 'random' order instead of 
     * together, we verify that this logic is workign correctly.
     */
    LOAD("lithium A 3.0.0.1                 ; more than one entry in RRset\n", parser);
    LOAD("lithium A 3.0.0.2                 ; more than one entry in RRset\n", parser);
    LOAD("lithium TXT \"hello\"             \n", parser);
    LOAD("lithium TXT \"world\"             \n", parser);
    LOAD("lithium A 3.0.0.3                 ; more than one entry in RRset\n", parser);
    LOAD("lithium TXT \"42\"             \n", parser);
    LOAD("lithium A 3.0.0.4                 ; more than one entry in RRset\n", parser);
    LOAD("lithium TXT \"don't eat yellow snow\"             \n", parser);
    QUERY("lithium", TYPE_A, selftest,
        "lithium.example.com", 4, "\3\0\0\1", TYPE_A,
        "lithium.example.com", 4, "\3\0\0\2", TYPE_A,
        "lithium.example.com", 4, "\3\0\0\3", TYPE_A,
        "lithium.example.com", 4, "\3\0\0\4", TYPE_A,
        0);
    QUERY("lithium", TYPE_TXT, selftest,
        "lithium.example.com", 6, "\x05" "hello", TYPE_TXT,
        "lithium.example.com", 6, "\x05" "world", TYPE_TXT,
        "lithium.example.com", 3, "\x02" "42", TYPE_TXT,
        "lithium.example.com", 22, "\x15" "don't eat yellow snow", TYPE_TXT,
        0);

    /*
     * This verifies that domain-names are case-insensitive
     */
    LOAD("Beryllium A 4.0.0.1               ; case sensitivity\n", parser);
    LOAD("bErYlLiUm A 4.0.0.2               ; case sensitivity\n", parser);
    QUERY("berylliuM", TYPE_A, selftest,
        "berylliuM.example.com", 4, "\4\0\0\1", TYPE_A,
        "berylliuM.example.com", 4, "\4\0\0\2", TYPE_A,
        0);

    /* try to cause a buffer overflow */
    element = "boron";
    for (i=0; i<100; i++) {
        char line[1024];
        sprintf_s(line, sizeof(line), "%04x.%s TXT \"%.*s\"\n",
            i, element,
            i,
            "****************************************************************************************"
            "****************************************************************************************"
            "****************************************************************************************"
            );
        //printf("%s", line);
        //LOAD(line, parser);
        sprintf_s(line, sizeof(line), "%04x.%s TXT o\n", i, element);
        //printf("%s", line);
        LOAD(line, parser);
    }
    QUERY("0007.boron", TYPE_TXT, selftest,
        "0007.boron.example.com", 2, "\x01" "o", TYPE_TXT,
        0);

    /* try to cause a buffer overflow */
    element = "nitrogen";
    for (i=0; i<100; i++) {
        char line[1024];
        sprintf_s(line, sizeof(line), "%04x.%s TXT \"%.*s\"\n",
            i, element,
            i,
            "****************************************************************************************"
            "****************************************************************************************"
            "****************************************************************************************"
            );
        LOAD(line, parser);
        sprintf_s(line, sizeof(line), "%04x.%s A 0.0.0.0\n", i, element);
        LOAD(line, parser);
        sprintf_s(line, sizeof(line), "%04x.%s TXT o\n", i, element);
        LOAD(line, parser);
    }

    LOAD("carbon A 6.0.0.1               ; identical entry\n", parser);
    LOAD("carbon A 6.0.0.1               ; identical entry\n", parser);

    LOAD("oxygen TXT \"a\" (", parser);
    LOAD("\"bb\" \"ccc\" )\n", parser);
    QUERY("oxygen", TYPE_TXT, selftest,
        "oxygen.example.com", 9, "\x01" "a" "\x02" "bb" "\x03" "ccc", TYPE_TXT,
        0);


    /* we are now done parsing the zonefile, so free the parser */
    parse_results = zonefile_end(parser);
    if (parse_results != Success) {
        fprintf(stderr, "error: <self-test> failed\n");
        return Failure;
    }


        


    if (selftest->total_code == Success) {
        fprintf(stderr, "info: <self-test> succeeded\n");
        return Success;
    } else {
        fprintf(stderr, "error: <self-test> failed\n");
        return Failure;
    }
}

