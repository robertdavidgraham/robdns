#ifndef ZONEFILE_BLOCK_H
#define ZONEFILE_BLOCK_H
#include <stdint.h>
#include "domainname.h"
struct ZoneFileParser;


/****************************************************************************
 * A "block" contains many parsed records from a zone file. This will be
 * handed off to a separate thread that will then insert them into
 ****************************************************************************/
struct ParsedBlock
{
    /* The "origin" domain name. Whenever the origin changes in a zonefile
     * it forces the creation of a new block. Thus, the single origin
     * parameter can be considered valid for all records within a block. */
	struct DomainPointer origin;
    unsigned char origin_buffer[256];
    uint64_t ttl;

    char filename[256];

    /* The buffer containing parsed resource-records */
    unsigned char buf[256*1024];
    unsigned offset;
    unsigned offset_start;
};


/**
 * finish the old block of RR records and hand them off to a db-insertion
 * thread, and start a fresh block of records
 */
struct ParsedBlock *
block_next_to_parse(struct ZoneFileParser *parser);


struct ParsedBlock *
block_init(struct ZoneFileParser *parser, struct DomainPointer origin, uint64_t ttl);

void
block_end(struct ZoneFileParser *parser);

void
block_flush(struct ZoneFileParser *parser);

#endif
