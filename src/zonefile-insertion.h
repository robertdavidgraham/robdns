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
    
    /* The last domain that was parsed, for when records start with spaces */
    struct DomainPointer domain;
    unsigned char domain_buffer[256];
    
    /* The current default TTL */
    uint64_t ttl;

    /* A hint as to the filename, useful for printing error messages. This is
     * because 'parsing' the text of the file happens early, but insertion
     * of records into the catalog/database happens much later. If there is
     * an insertion error, we need to be able to tie it back to the file
     * the original record came from. For example, if entering two CNAMEs
     * for the same label produces an error on insertion into the database.
     */
    char filename[256];
    uint64_t filesize;

    /* The buffer containing parsed resource-records. We append onto this
     * buffer as we parse the file. Later, we hand the whole block over to
     * an insertion thread that pulls those records out and inserts them
     * into the database. */
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

void
block_rr_finish(struct ParsedBlock *block);

void
block_rr_start(struct ParsedBlock *block);

struct ParsedBlock *
block_init(struct ZoneFileParser *parser, struct DomainPointer origin, uint64_t ttl);

void
block_end(struct ZoneFileParser *parser);

void
block_flush(struct ZoneFileParser *parser);

#endif
