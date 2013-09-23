/*
	For parsing individual fields within zone files
*/
#ifndef ZONE_FIELDS_H
#define ZONE_FIELDS_H
#include "zonefile-rr.h"

struct ParseBuffer
{
    unsigned length;
    unsigned line_offset;
    unsigned char *data;
};

enum BlockStatus {
    BLOCK_EMPTY=0,
    BLOCK_FULL=1,
    BLOCK_INSERTING=2,
};
/****************************************************************************
 * A "block" contains many parsed records from a zone file. This will be
 * handed off to a separate thread that will then insert them into
 ****************************************************************************/
struct ParsedBlock
{
    enum BlockStatus status;

    /* The "origin" domain name. Whenever the origin changes in a zonefile
     * it forces the creation of a new block. Thus, the single origin
     * parameter can be considered valid for all records within a block. */
	struct DomainPointer origin;
    unsigned char origin_buffer[256];

    /* The buffer containing parsed resource-records */
    unsigned char buf[256*1024];
    unsigned offset;
    unsigned offset_start;

};

struct DomainBuilder
{
	unsigned char length;
	unsigned char is_absolute;
	unsigned char label;
	unsigned char *name;
};


/****************************************************************************
 ****************************************************************************/
struct ZoneFileParser
{
	unsigned s;
	unsigned s2;
	unsigned substring_esc;
	unsigned is_multiline;
    uint64_t filesize;
	struct MyDFA *type_dfa;
	struct MyDFA *variable_dfa;

	struct DomainPointer origin;
    unsigned char origin_buffer[256];
	uint64_t ttl;

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
    

	struct ParsedBlock blocks[64]; /*IMPORTANT: count must be power of 2 */
    uint64_t block_index;
    struct ParsedBlock *block;

    struct Source src;

    RESOURCE_RECORD_CALLBACK callback;
    void *callbackdata;

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




#endif
