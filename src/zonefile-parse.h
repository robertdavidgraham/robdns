#ifndef ZONE_PARSE_H
#define ZONE_PARSE_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "source.h"
#include "domainname.h"


enum {
	CLASS_ERROR,
	CLASS_IN, /* Internet */
	CLASS_CS, /* CSNET (Obsolete) */
	CLASS_CH, /* Chaos (used for version strings) */
	CLASS_HS, /* Hesiod (Obsolete) */
};


const char * name_of_type(unsigned type);



typedef void (*RESOURCE_RECORD_CALLBACK)(
    struct DomainPointer domain,
    struct DomainPointer origin,
	unsigned type,
    unsigned ttl,
    unsigned rdlength,
    const unsigned char *rdata,
    uint64_t filesize,
	void *userdata);
	
/* Call this before parsing a zone-file */
struct ZoneFileParser *zonefile_begin(struct DomainPointer origin, uint64_t ttl, uint64_t filesize,
    const char *filename, RESOURCE_RECORD_CALLBACK callback, void *callbackdata);

/* Call this when done, check return code for success(1) or failure(0) */
int zonefile_end(struct ZoneFileParser *parser);

/* Write any cached info into the catalog */
int zonefile_flush(struct ZoneFileParser *parser);


/* Parse a chunk of a zone-file */
void zonefile_parse(
    struct ZoneFileParser *parser,
    /*const char *filename, 
    RESOURCE_RECORD_CALLBACK callback, 
    void *userdata,*/
    const unsigned char *buf,
    size_t buf_length);

/**
 * Process-wide configuration for this module. Should be called by main()
 * right at startup.
 */
int zonefile_parser_init();

#ifdef __cplusplus
}
#endif
#endif
