#define _CRT_SECURE_NO_WARNINGS
#define _POSIX_C_SOURCE 200112L
#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include "grind.h"
#include "zonefile-parse.h"
#include "zonefile-rr.h"
#include "zonefile-load.h"
#include "db.h"
#include "db-xdomain.h"
#include "db-zone.h"
#include "db-entry.h"
#include "zonefile-tracker.h"
#include "util-realloc2.h"
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

struct Grind
{
	struct Network *network;
	struct Catalog *catalog;
};

struct Catalog *
grind_get_catalog(struct Grind *grind)
{
    return grind->catalog;
}

/****************************************************************************
 ****************************************************************************/
struct Grind *
grind_create()
{
	struct Grind *grind;

    /*
     * Allocate memory for our DNS server instance.
     */
    grind = REALLOC2(0, 1, sizeof(grind[0]));
    memset(grind, 0, sizeof(grind[0]));

   	/*
	 * Initialize the master database (i.e. hashtables) object
	 */
	grind->catalog = catalog_create();

    return grind;
}

void
grind_destroy(struct Grind *grind)
{
    catalog_destroy(grind->catalog);
    grind->catalog = 0;

    free(grind);
}

/****************************************************************************
 * Temporary function for checking how good hashing works, by checking
 * the distribution of chain lengths across the hash table. We should expect
 * to see an even distriubtion, not some very long chains with short chains.
 ****************************************************************************/
void
check_chain_lengths(struct Grind *grind)
{
    struct DomainPointer domain;
    struct DomainPointer origin;
    struct DB_XDomain xdomain[1];
    struct DBZone *zone;
    unsigned i;
    unsigned lengths[1024];

    /* Start all counters from zero */
    memset(lengths, 0, sizeof(lengths));

    /* Tesing with the hard-code ".net" domain, using the "net.zone" 
     * from verisign. Change this if you are looking at a different
     * zone */
    domain.length = 5;
    domain.name = (const unsigned char *)"\x03NET\x00";
    origin.length = 0;
    origin.name = (const unsigned char *)"\0";
    xdomain_reverse3(xdomain, &domain, &origin);

    /* Lookup the zone that we are analyzing */
	zone = catalog_lookup_zone(grind->catalog, xdomain);

    /* Go through the entire hash table and measure the the 
     * chain length for each entry */
    i = 0;
    for (;;) {
        const struct DBEntry *record;
        unsigned chain_length;

        record = zone_entry_by_index(zone, i);
        if (record == 0)
            break;

        chain_length = entry_chain_length(record);

        if (chain_length >= sizeof(lengths)/sizeof(lengths[0]))
            chain_length = sizeof(lengths)/sizeof(lengths[0]) - 1;

        lengths[chain_length]++;
        i++;
    }
    printf("%u records\n", i);
    printf("%u number\n", 64*1024*1024);

    /* Now print the distribution */
    for (i=0; i<sizeof(lengths)/sizeof(lengths[0]); i++) {
        if (lengths[i] || i == 0 || i == sizeof(lengths)/sizeof(lengths[0])-1) {
            printf("%4u %u\n", i, lengths[i]);
        }
    }
    

}



/****************************************************************************
 * Reports percent complete.
 *
 * This is useful for loading large zone files, like ".com" zone, that can
 * take a couple minutes to load.
 ****************************************************************************/
void
tracker_report(struct Tracker *tracker, size_t len)
{
    clock_t now;
    double period;
    double bytes_per_second;
    int bytes_printed;
    int i;

	tracker->bytes_read += len;

	if (tracker->bytes_reported + 1024*1024*16 > tracker->bytes_read)
        return;
    
	now = clock();
	period = (now - tracker->when_reported)*1.0 / (CLOCKS_PER_SEC * 1.0);
	bytes_per_second = (tracker->bytes_read - tracker->bytes_reported)/period;
    
	bytes_printed = fprintf(stderr, "%2u%% %5.0fMB/s", (unsigned)(tracker->bytes_read*100UL/tracker->file_size), bytes_per_second/(1024.0*1024.0));
    for (i=0; i<bytes_printed; i++)
        putc('\b', stderr);

	tracker->when_reported = now;
	tracker->bytes_reported = tracker->bytes_read;
}

uint64_t
tracker_get_filesize(struct Tracker *tracker, const char *filename)
{
        
#if defined(_MSC_VER)
#define stat64 _stat64
#elif defined(__GNUC__)
#define stat64 stat
#endif
    struct stat64 s;
    int x;
      
    s.st_size = 1;
    x = stat64(filename, &s);
    if (x != 0) {
        fprintf(stderr, "couldn't stat(%s)\n", filename);
        perror(filename);
        return 1000;
    } else if (s.st_size == 0) {
        fprintf(stderr, "%s: file is empty\n", filename);
        return 1000;
    }
    tracker->file_size = s.st_size;
    return s.st_size;
}


/****************************************************************************
 * Called to load the initial zone-file(s).
 ****************************************************************************/
int
grind_load_zonefile(struct Grind *grind, const char *filename, struct DomainPointer origin, uint64_t ttl)
{
	struct Tracker tracker[1];
	FILE *fp;
	struct ZoneFileParser *parser;
    int x;
    uint64_t filesize;
    /*
     * Initialize a tracker for tracking progress. This is mostly
     * so that we can track the progress when loading huge zone
     * files, like .com or .net. This is used during development
     * to optimize the speed of the zone-file parser so that it
     * doesn't take so long to load zone-files.
     */
   	memset(tracker, 0, sizeof(tracker[0]));


    /*
     * Figure out the size of the file. We support 64-bit file sizes
     * because currently the .com zone file is 8-gigabytes in size,
     * and thus its size does not fit in 32 bits.
     * TOCTOU-potential: we only do this for printing "percent complete"
     * to the command-line. There is no vulnerability if the file changes
     * between time-of-check and time-of-use.
     */
    filesize = tracker_get_filesize(tracker, filename);

	
	/*
	 * Open the file for reading. Note that even though this is technically
     * text file, we are opening it in binary mode. That's because we parse
     * it as a binary format rather than a text format.
	 */
	fp = fopen(filename, "rb");
	if (fp == NULL) {
		perror(filename);
		return Failure;
	} else {
		fprintf(stderr, "%s: parsing\n", filename);
        tracker->fp = fp;
	}

    /*
     * Create a parser
     */
    parser = zonefile_begin(origin, ttl, filesize,
                filename,                   /* used for printing error messages */
                zonefile_load,              /* called for each resource record */
                grind,                       /* opaque user data (void*) */
                0
            );


    /*
     * Reads through the file a binary-block at a time. The parser treats
     * the file as "binary" instead of "text lines" for much faster
     * parsing.
     */
    {
		static const unsigned sizeof_buf = 65536 * 16;
		unsigned char *buf;

        /* Allocate a large buffer. We want large buffers to minimize
         * overhead reading from disk.
         * TODO: use async I/O (overlapped) in order to read file even
         * faster. */
        buf = MALLOC2(sizeof_buf);

        /* read through the file */
		for (;;) {
			size_t bytes_read;
            
            bytes_read = fread(buf, 1, sizeof_buf, fp);
			if (bytes_read == 0 || sizeof_buf < bytes_read)
				break;
			zonefile_parse(
                parser,                     /* temporary parser object */
                buf,                        /* the chunk of zone-file data to be parsed */
                bytes_read                  /* size of this chunk */
                );

			tracker_report(tracker, bytes_read);
		}
        free(buf);
	}

    /*
     * Close the file
     */
    fclose(fp);

    /*
     * Free the parser object, and return the success/failure
     * notification
     */
    x = zonefile_end(parser);
    if (x == Success) {
        fprintf(stderr, "%s: zonefile read, no errors\n", filename);
        return Success;
    } else {
        fprintf(stderr, "%s: zonefile had errors\n", filename);
        return Failure;
    }
}
