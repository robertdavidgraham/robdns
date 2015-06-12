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
#include "success-failure.h"


enum {
	CLASS_ERROR,
	CLASS_IN, /* Internet */
	CLASS_CS, /* CSNET (Obsolete) */
	CLASS_CH, /* Chaos (used for version strings) */
	CLASS_HS, /* Hesiod (Obsolete) */
};


const char * name_of_type(unsigned type);



typedef enum SuccessFailure (*RESOURCE_RECORD_CALLBACK)(
    struct DomainPointer domain,
    struct DomainPointer origin,
	unsigned type,
    unsigned ttl,
    unsigned rdlength,
    const unsigned char *rdata,
    uint64_t filesize,
	void *userdata,
    const char *filename,
    unsigned line_number);
	
/**
 * Call this before parsing a zone-file .
 * @param origin
 *      The DNS "origin" of the zone, such as "." or ".com." or
 *      ".example.net.". Normally empty, unless this is being
 *      called to recursively parse files, in which case this
 *      will be the current origin of the parent file.
 * @param ttl
 *      The default Time-To-Live, which is normally just 0, unless
 *      being recursively called, in which case this will be the
 *      current TTL of the parent file
 * @param filesize
 *      This is a hint for pre-allocating the data structures of a zone.
 *      This assumes a file containing information as dense as the
 *      .com zonefile, and does it's calculations from there.
 * @param filename
 *      The name of the file being parsed. This is only used for printing
 *      diagnostic information -- it's not used to open/close files.
 * @param callback
 *      This function will be called once we've parsed a resource record.
 *      This is almost always the function "zonefile_load()", which will
 *      insert the parsed record into the database. The only case when
 *      it isn't is when we are just benchmarking the parser, in which
 *      case this function just drops the record.
 * @param callbackdata
 *      Opaque user data associated with the callback. This is almost
 *      always the global catalog/db.
 * @param extra_threads
 *      The number of extra insertion threads to spawn, 0 if not using 
 *      multi-threaded parsing. Inserting records into the database
 *      is the slow part, so it's useful to have more than one thread
 *      doing it.
 */
struct ZoneFileParser *
zonefile_begin(struct DomainPointer origin, uint64_t ttl, 
               uint64_t filesize, const char *filename, 
               RESOURCE_RECORD_CALLBACK callback, void *callbackdata,
               unsigned extra_threads);
void
zonefile_begin_again(
    struct ZoneFileParser *parser,
    struct DomainPointer origin, uint64_t ttl, uint64_t filesize,
    const char *filename);

/* Call this when done, check return code for success(1) or failure(0) */
int zonefile_end(struct ZoneFileParser *parser);

/* Write any cached info into the catalog */
int zonefile_flush(struct ZoneFileParser *parser);

/**
 * Insert resource-records immediately into the catalog/database instead 
 * of as a batch. This is useful for debugging only, and shouldn't be used
 * otherwise 
 */
void zonefile_set_singlestep(struct ZoneFileParser *parser);

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
