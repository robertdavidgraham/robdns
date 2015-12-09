#include "domainname.h"
#include "zonefile-rr.h"
#include "crypto-siphash.h"
#include "crypto-murmur3.h"
#include "crypto-md5.h"
#include "string_s.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>


struct DomainPointer ROOT = {0,0};

/****************************************************************************
 ****************************************************************************/
#if 0
static uint64_t
md5(const void *p, unsigned length, uint64_t secret)
{
    MD5_CTX ctx[1];
    unsigned char digest[16];
    
    MD5Init(ctx);
    MD5Update(ctx, (const unsigned char *)&secret, sizeof(secret));
    MD5Update(ctx, (const unsigned char *)p, length);
    MD5Final((unsigned char *)digest, ctx);

    
    return (*(uint64_t*)(digest + 0)) 
         ^ (*(uint64_t*)(digest + 8));
}
#endif

/******************************************************************************
 * A domain-name comparison function.
 *
 * Remember that we represent domain names in a number of different formats
 * in the code. This compares names from two different formats.
 *
 * Called from the Zone lookup routine to find which zone the query name
 * refers to.
 *
 * FIXME: this function takes up a lot of time. it needs to be optimized
 ******************************************************************************/
int
xdomain_is_equal(const struct DB_XDomain *lhs, 
                 const struct DomainPointer *rhs, unsigned max_labels)
{
	unsigned i;
	const unsigned char *rhs_label = rhs->name;

    if (max_labels > lhs->label_count)
        return 0;

	for (i=max_labels; i>0; i--) {
		const unsigned char *lhs_label = lhs->labels[i-1].name;
	
		if (strncasecmp((char*)lhs_label, (char*)rhs_label, *lhs_label+1) != 0)
			return 0;

		rhs_label += *rhs_label + 1;
	}

	return 1;
}

/****************************************************************************
 ****************************************************************************/
void
xdomain_copy(const struct DB_XDomain *lhs, struct DomainPointer *rhs)
{
	unsigned i;
	unsigned char *rhs_label = (unsigned char*)rhs->name;
	

	for (i=lhs->label_count; i>0; i--) {
		const unsigned char *lhs_label = lhs->labels[i-1].name;

		memcpy(rhs_label, lhs_label, *lhs_label + 1);

		rhs_label += *rhs_label + 1;
	}

	rhs->length = (unsigned char)(rhs_label - rhs->name);
}

/****************************************************************************
 ****************************************************************************/
static void
convert_domain(struct DB_XDomain *result, 
        const unsigned char *name, unsigned name_length, 
        const unsigned char *origin, unsigned origin_length, 
        unsigned label_index)
{
	unsigned label_length;
	unsigned next_label;

	/* This is the normal end-condition as we first consume the "domain"
	 * then the "origin" then "null" */
	if (name == 0)
		return;

	/* Sanity check. This shouldn't be possible, due to sanity checks 
	 * elsewhere, but we are going to check it anyway. On debug builds,
	 * the assert() will also trip */
	if (result->label_count >= sizeof(result->labels)/sizeof(result->labels[0])) {
		assert(result->label_count < sizeof(result->labels)/sizeof(result->labels[0]));
		return;
	}

	/* See if we've reached the end of a fully-qualified domain name. This
	 * happens either when we are processing the "origin", but also if the
	 * original domain-name was fully qualified */
	if (label_index + 1 == name_length)
		return;

	/* See if we've reached the end of a non-FQDN, in which case continue
	 * with the "origin". this is just a hack that replaces the "domain"
	 * with the "origin", then sets the "origin" to NULL. If this happens
	 * becuase we've reached the end of the origin, this function call
	 * will immediately return. */
	if (label_index == name_length) {
		convert_domain(result, origin, origin_length, 0, 0, 0);
		return;
	}

	/* Find the next label */
	label_length = name[label_index];
	next_label = label_index + 1 + label_length;

	/* Recursively call the next function, BEFORE appending our own
	 * label, so that they get appended in reverse order */
	convert_domain(result, name, name_length, origin, origin_length, next_label);

	/* Now add our label onto the end */
	result->labels[result->label_count].name = name+label_index;
	result->label_count++;
}

/****************************************************************************
 ****************************************************************************/
void
xdomain_calc_hashes(struct DB_XDomain *xdomain)
{
    unsigned i;
    unsigned char name[256];
    unsigned name_length = 0;

    /* Convert the name into a single buffer */
    for (i=0; i<xdomain->label_count; i++) {
        const unsigned char *label = xdomain->labels[i].name;
        unsigned len = label[0]+1;
        if (name_length + len >= sizeof(name))
            break;
        memcpy(name+name_length, label, len);
        name_length += len;
    }

    /* Now calculate the hashes */
    name_length = 0;
    for (i=0; i<xdomain->label_count; i++) {
        uint64_t hash;
        name_length += xdomain->labels[i].name[0]+1;
#if 1
        hash = murmurhash3(
            name,           /* text being hashed */
            name_length,    /* length of text to hash */
            1234);
#endif
#if 0
        hash = md5(name, name_length, 1234);
#endif
        xdomain->labels[i].hash = hash;
        xdomain->hash = hash;
		/*siphash_x(&hash, domain->name+label_index, label_length+1, 
            result->secret_key, result->hash);*/
    }

}
/****************************************************************************
 ****************************************************************************/
uint64_t calc_hash(const unsigned char label[], uint64_t previous_hash)
{
    unsigned len = label[0];

    return siphash_x(label, len+1, 0, previous_hash);
}


void
xdomain_reverse2(struct DB_XDomain *result, const unsigned char *name, unsigned name_length)
{
    unsigned i;
    uint64_t hash = 0;

	result->label_count = 0;

	convert_domain(result, name, name_length, 0, 0, 0);

    for (i=0; i<result->label_count; i++) {
        hash = calc_hash(result->labels[i].name, hash);
        result->labels[i].hash = hash;
    }

    result->hash = hash;
}

/******************************************************************************
 ******************************************************************************/
void
xdomain_reverse3(struct DB_XDomain *result, const struct DomainPointer *prefix, const struct DomainPointer *suffix)
{
    unsigned i;
    uint64_t hash = 0;

	result->label_count = 0;
    if (suffix) {
        convert_domain(result, prefix->name, prefix->length, suffix->name, suffix->length, 0);
    } else
	    convert_domain(result, prefix->name, prefix->length, 0, 0, 0);


    for (i=0; i<result->label_count; i++) {
        hash = calc_hash(result->labels[i].name, hash);
        result->labels[i].hash = hash;
    }

    result->hash = hash;
}

/******************************************************************************
 ******************************************************************************/
uint64_t
xdomain_label_hash(const struct DB_XDomain *xdomain, unsigned index)
{
    uint64_t previous_hash;
    if (index == 0)
        previous_hash = 0;
    else
        previous_hash = xdomain->labels[index-1].hash;
    return calc_hash(xdomain->labels[index].name, previous_hash);
}


/****************************************************************************
 ****************************************************************************/
static void
print_domain_err_v(const struct DB_XDomain *xdomain, const char *fmt, va_list marker)
{
	unsigned i;

	for (i=0; i<xdomain->label_count; i++) {
		fprintf(stderr, "%.*s", xdomain->labels[i].name[0], xdomain->labels[i].name+1);
		if (i + 1 < xdomain->label_count)
			fprintf(stderr, ".");
	}

	vprintf(fmt, marker);
}

/****************************************************************************
 ****************************************************************************/
void
xdomain_err(const struct DB_XDomain *xdomain, const char *fmt, ...)
{
	va_list marker;

	va_start(marker, fmt);
	print_domain_err_v(xdomain, fmt, marker);
	va_end(marker);
}

/****************************************************************************
 * Test to see if this is domain starting with "*" label.
 ****************************************************************************/
int
xdomain_is_wildcard(const struct DB_XDomain *domain)
{
    if (domain->label_count == 0)
        return 0;
    if (domain->labels[domain->label_count-1].name[0] != 1)
        return 0;
    if (domain->labels[domain->label_count-1].name[1] != '*')
        return 0;
    return 1;
}


