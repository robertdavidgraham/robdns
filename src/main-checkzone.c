#define _CRT_SECURE_NO_WARNINGS
#include "db.h"
#include "domainname.h"
#include "zonefile-parse.h"
#include "zonefile-load.h"
#include "zonefile-tracker.h"
#include "string_s.h"
#include "success-failure.h"
#include <string.h>


static const struct DomainPointer root = {(const unsigned char*)"\0",1};

struct ZoneCheck
{
    struct Catalog *db;

};

extern uint64_t entry_bytes;
extern uint64_t entry_count;
extern uint64_t total_chain_length;

int checkzone(int argc, char *argv[])
{
    clock_t start, stop;
    struct ZoneCheck zonecheck[1];
    int i;


    zonecheck->db = catalog_create();
    
    start = clock();
    for (i=2; i<argc; i++) {
        const char *filename = argv[i];
        struct ZoneFileParser *parser;
        struct Tracker tracker[1];
        FILE *fp;
        uint64_t filesize;

        memset(tracker, 0, sizeof(tracker[0]));
        filesize = tracker_get_filesize(tracker, filename);

        fp = fopen(filename, "rb");
        if (fp == NULL) {
            perror(filename);
            continue;
        }

        parser = zonefile_begin(root, 60, filesize,
                filename, 
                zonefile_load, 
                zonecheck->db,
                0
                );

        for (;;) {
            unsigned char buf[65536];
            size_t bytes_read;

            bytes_read = fread((char*)buf, 1, sizeof(buf), fp);
            if (bytes_read == 0)
                break;

            zonefile_parse(
                parser,
                buf,
                bytes_read
                );

            tracker_report(tracker, bytes_read);
        }

        if (zonefile_end(parser) == Success) {
            fprintf(stderr, "%s: success\n", filename);
        } else {
            fprintf(stderr, "%s: failure\n", filename);
        }
    }

    stop = clock();
    {
        double ellapsed = 1.0*(stop-start)/CLOCKS_PER_SEC;
        printf("ellapsed = %f-sec\n", ellapsed);
        if (entry_count) {
            double avg_chain_len = (1.0*total_chain_length)/entry_count;
            printf(" %" PRIu64 "-entries, %" PRIu64 "-bytes, %" PRIu64 "-avg, %f-chain\n", 
                        entry_count, 
                        entry_bytes, 
                        entry_bytes/entry_count, 
                        avg_chain_len);
        }

    }

    return Success;
}

