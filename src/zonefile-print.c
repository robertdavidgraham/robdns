#include "zonefile-parse.h"
#include "zonefile-rr.h"
#include <stdio.h>

extern const char *name_of_type(unsigned type);

/****************************************************************************
 * Prints a domain name
 ****************************************************************************/
void zprint_domain(FILE *fp, struct DomainPointer domain)
{
	unsigned i;

	for (i=0; i<domain.length; ) {
		unsigned label = domain.name[i++];
		if (label > 63) {
			fprintf(fp, "ERR[label=%u]", label);
			break;
		}
		fprintf(fp, "%.*s.", label, domain.name+i);
		i += label;
	}
}



/****************************************************************************
 * Prints a TTL value
 ****************************************************************************/
void zprint_ttl_value(FILE *fp, unsigned ttl)
{
	if (ttl % 60) {
		fprintf(fp, "%u", ttl);
		return;
	}
	ttl /= 60;
	if (ttl % 60) {
		fprintf(fp, "%um", ttl);
		return;
	}
	ttl /= 60;
	if (ttl % 24) {
		fprintf(fp, "%uh", ttl);
		return;
	}
	ttl /= 24;
	if (ttl % 7) {
		fprintf(fp, "%ud", ttl);
		return;
	}
	ttl /= 7;
	fprintf(fp, "%uw", ttl);
}



void
zprint_label(FILE *fp, const unsigned char *px, unsigned offset, unsigned max)
{
    unsigned i;
    unsigned length;

    length = px[offset];
    offset++;

    if (length > max-offset)
        length = max-offset;

    for (i=0; i<length; i++) {
        unsigned char c = px[offset+i];

        if ('A' <= c && c <= 'Z')
            fprintf(fp, "%c", c);
        else if ('a' <= c && c <= 'z')
            fprintf(fp, "%c", c);
        else if ('0' <= c && c <= '9')
            fprintf(fp, "%c", c);
        else if (c == '-' || c == '_')
            fprintf(fp, "%c", c);
        else
            fprintf(fp, "\\%03u", c&0xFF);
    }
    fprintf(fp, ".");
}

/****************************************************************************
 ****************************************************************************/
static unsigned xx_domain(FILE *fp, const unsigned char *px, unsigned offset, unsigned max)
{
    while (px[offset] && offset<max) {
        zprint_label(fp, px, offset, max);
        offset += px[offset] + 1;
    }
    if (px[offset] == 0 && offset<max)
        offset++;
    fprintf(fp, " ");
    return offset;
}
static unsigned xx_integer32(FILE *fp, const unsigned char *px, unsigned offset, unsigned max)
{
    unsigned n = 0;
    if (offset + 4 <= max) {
        n = px[offset+0]<<24
            | px[offset+1]<<16
            | px[offset+2]<<8
            | px[offset+3]<<0;
    }
    fprintf(fp, "%u ", n);
    return offset + 4;
}
static unsigned xx_integer16(FILE *fp, const unsigned char *px, unsigned offset, unsigned max)
{
    unsigned n = 0;
    if (offset + 2 <= max) {
        n = px[offset+0]<<8
            | px[offset+1]<<0;
    }
    fprintf(fp, "%u ", n);
    return offset + 2;
}
static unsigned xx_integer8(FILE *fp, const unsigned char *px, unsigned offset, unsigned max)
{
    unsigned n = 0;
    if (offset + 1 <= max) {
        n = px[offset+0]<<0;
    }
    fprintf(fp, "%u ", n);
    return offset + 1;
}
static unsigned xx_ttl(FILE *fp, const unsigned char *px, unsigned offset, unsigned max)
{
    unsigned ttl = 0;
    if (offset + 4 <= max) {
        ttl = px[offset+0]<<24
            | px[offset+1]<<16
            | px[offset+2]<<8
            | px[offset+3]<<0;
    }
    if (ttl % (7 * 24 * 60 * 60) == 0)
        fprintf(fp, "%uw ", ttl / (7 * 24 * 60 * 60));
    else if (ttl % (24 * 60 * 60) == 0)
        fprintf(fp, "%ud ", ttl / (24 * 60 * 60));
    else if (ttl % (60 * 60) == 0)
        fprintf(fp, "%uh ", ttl / (60 * 60));
    else if (ttl % (60) == 0)
        fprintf(fp, "%um ", ttl / (60));
    else
        fprintf(fp, "%u ", ttl);

    return offset + 4;
}
static unsigned xx_type(FILE *fp, const unsigned char *px, unsigned offset, unsigned max)
{
    unsigned n = 0;
    if (offset + 2 <= max) {
        n = px[offset+0]<<8
            | px[offset+1]<<0;
    }
	fprintf(fp, " %s ", name_of_type(n));
    return offset + 2;
}

static unsigned xx_base64(FILE *fp, const unsigned char *px, unsigned offset, unsigned max)
{
    static const char base64[] = 
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
       "abcdefghijklmnopqrstuvwxyz"
       "01234567890"
       "/.";
    unsigned n;

    while (offset + 3 <= max) {
        n = px[offset+0]<<16
            | px[offset+1]<<8
            | px[offset+2]<<0;
        fprintf(fp, "%c%c%c%c",
                base64[(n>>18)&0x3F],
                base64[(n>>12)&0x3F],
                base64[(n>>6)&0x3F],
                base64[(n>>0)&0x3F]
            );
        offset += 3;
    }

    switch (max-offset) {
    case 2:
        n = px[offset+0]<<16
            ;
        fprintf(fp, "%c%c%c%c",
                base64[(n>>18)&0x3F],
                base64[(n>>12)&0x3F],
                '=',
                '='
            );
        break;
    case 1:
        n = px[offset+0]<<16
            | px[offset+1]<<8
            ;
        fprintf(fp, "%c%c%c%c",
                base64[(n>>18)&0x3F],
                base64[(n>>12)&0x3F],
                base64[(n>>6)&0x3F],
                '='
            );
        break;
    case 0:
        break;
    }
    
    fprintf(fp, " ");
    return max;
}

/****************************************************************************
 ****************************************************************************/
void
zprint_rr(FILE *fp, unsigned type, const unsigned char *px, unsigned max)
{
	unsigned i = 0;


	fprintf(fp, " %s ", name_of_type(type));


	switch (type) {
	case TYPE_NS:
	case TYPE_CNAME:
        i = xx_domain(fp, px, i, max);
        break;
	case TYPE_SOA:
        i = xx_domain(fp, px, i, max);
        i = xx_domain(fp, px, i, max);
        i = xx_integer32(fp, px, i, max);
        i = xx_ttl(fp, px, i, max);
        i = xx_ttl(fp, px, i, max);
        i = xx_ttl(fp, px, i, max);
        i = xx_ttl(fp, px, i, max);
		break;
    case TYPE_RRSIG:
        /*
                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |        Type Covered           |  Algorithm    |     Labels    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Original TTL                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Signature Expiration                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Signature Inception                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |            Key Tag            |                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                                                               /
       /                            Signature                          /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
       */
        i = xx_type(fp, px, i, max);
        i = xx_integer8(fp, px, i, max);
        i = xx_integer8(fp, px, i, max);
        i = xx_ttl(fp, px, i, max);
        i = xx_integer32(fp, px, i, max);
        i = xx_integer32(fp, px, i, max);
        i = xx_integer16(fp, px, i, max);
        i = xx_domain(fp, px, i, max);
        i = xx_base64(fp, px, i, max);
        break;

    
    default:
        fprintf(fp, "--");
	}

    fprintf(fp, "\n");
}
