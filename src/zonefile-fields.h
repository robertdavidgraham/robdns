/*
	For parsing individual fields within zone files
*/
#ifndef ZONE_FIELDS_H
#define ZONE_FIELDS_H
#include "zonefile-rr.h"
#include "zonefile-insertion.h"
#include "source.h"
#include "zonefile-parse.h"

struct ParseBuffer
{
    unsigned length;
    unsigned line_offset;
    unsigned char *data;
};

struct DomainBuilder
{
	unsigned char length;
	unsigned char is_absolute;
	unsigned char label;
	unsigned char *name;
};

struct rte_ring;

/****************************************************************************
 ****************************************************************************/
struct ZoneFileParser
{
	unsigned s;
	unsigned s2;
	unsigned substring_esc;
    unsigned is_singlestep:1;
	unsigned is_multiline:1;
    unsigned is_commenting:1;
    unsigned is_string:1;

    uint64_t filesize;
	struct MyDFA *type_dfa;
	struct MyDFA *variable_dfa;

    uint64_t rr_number;
    struct DomainBuilder rr_domain;
    struct ParseBuffer rr_buffer;
    struct {
        unsigned count; 
        unsigned short list[64];
    } rr_typelist;
    struct {
        unsigned length;
        unsigned ellision;
        unsigned val;
    } rr_ipv6;
    struct {
        unsigned number;
        unsigned longitude;
        unsigned latitude;
        unsigned altitude;
        unsigned size;
        unsigned horiz_pre;
        unsigned vert_pre;
        unsigned char field;
        unsigned char digits;
        unsigned is_negative:1;
    } rr_location;
    struct {
	    uint64_t result;
	    unsigned count;
    } rr_base64;
    struct {
	    uint64_t result;
	    unsigned count;
    } rr_base32hex;
    struct {
	    uint64_t result;
	    unsigned count;
    } rr_hex;
    struct {
        uint64_t result;
    } rr_type;
    struct {
        unsigned result;
        unsigned count;
        unsigned intermediate;
    } rr_ipv4;
    


    struct InputSource src;

    /*
     * Insertion stuff
     */
    RESOURCE_RECORD_CALLBACK callback;
    void *callbackdata;
	struct ParsedBlock the_blocks[64]; /*IMPORTANT: count must be power of 2 */
    struct ParsedBlock *block;
    struct rte_ring *insertion_queue;
    struct rte_ring *free_queue;
    unsigned additional_threads;
    volatile unsigned running_threads;
    volatile unsigned is_running;
};
struct Bytes;

void x_parse_ipv4(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length);
void x_parse_ipv6(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length, unsigned char *ipv6);
void x_parse_txt(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length);
void x_parse_base32hex(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length);
void x_parse_base64(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length);
void x_parse_ttl(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length);
void x_parse_hex(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length, unsigned is_whitespace_allowed);

void parse_err(struct ZoneFileParser *parser,  const char *fmt, ...);

void mm_location_start(struct ZoneFileParser *parser);
void mm_location_end(struct ZoneFileParser *parser);
void mm_location_parse(struct ZoneFileParser *parser, 
    const unsigned char *buf, unsigned *offset, unsigned length);



extern char CONTROLCHAR[257];

unsigned
parse_default2( struct ZoneFileParser *parser, 
                const unsigned char *buf, unsigned *offset, unsigned *length,
                unsigned char *c);


#endif
