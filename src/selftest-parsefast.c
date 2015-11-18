/*
    SELFTEST - fast parser

    This tests the parser parsing too fast having to catch
*/
#include "zonefile-parse.h"
#include "zonefile-load.h"
#include "success-failure.h"
#include "unusedparm.h"
#include "db.h"
#include "db-zone.h"
#include "string_s.h"
#include "util-realloc2.h"
#include <stdlib.h>
#include <string.h>

extern void
LOAD(const char *string, struct ZoneFileParser *parser, struct Catalog *db);

unsigned myrand(unsigned *seed)
{
    *seed = *seed * 1103515245 + 12345;
    return *seed;
}

int
selftest2(int argc, char *argv[])
{
	struct ZoneFileParser *parser;
    struct Catalog *catalog;
    static const struct DomainPointer example_origin = {(const unsigned char*)"\7example\3com",12};
    size_t zonetext_size = 256*1024*1024;
    size_t zonetext_offset = 0;
    unsigned char *zonetext;
    unsigned seed = 0;
    int result;

    
    UNUSEDPARM(argc);
    UNUSEDPARM(argv);


    catalog = catalog_create();
    parser = zonefile_begin(
            example_origin, /* origin */
            60,             /* TTL */
            zonetext_size,  /* filesize */
            "<selftest>",   /* filename */
            zonefile_load,  /* callback */
            catalog,        /* callback data */
            0
            );

    LOAD("$TTL 60\r\n"
         "example.com.    IN    SOA   ns hostmaster (\r\n"
         "                     2003080800 ; sn = serial number\r\n"
         "                     172800     ; ref = refresh = 2d\r\n"
         "                     15m        ; ret = update retry = 15m\r\n"
         "                     1209600    ; ex = expiry = 2w\r\n"
         "                     1H         ; nx = nxdomain ttl = 1h\r\n"
         "                     )\r\n", parser, catalog);
    LOAD("foo    IN  A 1.2.3.4\n", parser, catalog);


    /*
     * Create a huge number of entries
     */
    zonetext = MALLOC2(zonetext_size);
    if (zonetext == 0)
        return -1;
    for (;;) {
        char tmp[256];
        switch (myrand(&seed)&0xF) {
        case 0:
            sprintf_s(tmp, sizeof(tmp), "%08x TXT \"%08X%08x%08x\"\n",
                myrand(&seed)&0xFFFF, myrand(&seed), myrand(&seed), myrand(&seed));
            break;
        case 1:
            sprintf_s(tmp, sizeof(tmp), "%08x%08x CNAME %08x\n",
                myrand(&seed), myrand(&seed), myrand(&seed));
            break;
        default:
            sprintf_s(tmp, sizeof(tmp), "%08x A %u.%u.%u.%u\n",
                myrand(&seed), 
                myrand(&seed)&0xFF, 
                myrand(&seed)&0xFF, 
                myrand(&seed)&0xFF, 
                myrand(&seed)&0xFF
                );
        }
        if (zonetext_offset + strlen(tmp) + 1 < zonetext_size) {
            memcpy(&zonetext[zonetext_offset], tmp, strlen(tmp));
            zonetext_offset += strlen(tmp);
        } else
            break;
    }
    zonetext[zonetext_offset] = '\0';



    {
        clock_t start, stop;
        double elapsed;

        start = clock();
        LOAD((const char *)zonetext, parser, catalog);
        stop = clock();
        elapsed = (stop-start)*1.0/CLOCKS_PER_SEC;


        printf("%5.2f-sec %5.2f-MBps\n", elapsed, zonetext_offset/(1024.0*1024.0)/elapsed);
    }



    result = zonefile_end(parser);
    if (result != Success) {
        fprintf(stderr, "error: <self-test> failed\n");
        return Failure;
    }



    


        

    return Success;
}

