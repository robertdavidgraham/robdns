#ifndef DB_ZONE_H
#define DB_ZONE_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include "zonefile-rr.h"


struct DBZone;
struct DB_XDomain;
struct Source;
struct DomainPointer;

struct DBZone *zone_create_self(
    const struct DB_XDomain *xdomain, 
    uint64_t filesize,
    const char *filename);

void zone_create_record(
    struct DBZone *zone, 
    const struct DB_XDomain *xdomain, 
    unsigned type,
    unsigned ttl,
    unsigned rdlength,
    const unsigned char *rdata);
void zone_create_record2(struct DBZone *zone,
    struct DomainPointer domain,
    struct DomainPointer origin,
    unsigned type,
    unsigned ttl,
    unsigned rdlength,
    const unsigned char *rdata
    );
struct DBZone *zone_follow_chain(struct DBZone *zone, const struct DB_XDomain *xdomain, unsigned max_labels);
const struct DBEntry *zone_lookup_exact(const struct DBZone *zone, const struct DB_XDomain *xdomain);
const struct DBEntry *zone_lookup_exact2(const struct DBZone *zone, const unsigned char *name, unsigned length);
const struct DBEntry *zone_lookup_wildcard(const struct DBZone *zone, const struct DB_XDomain *xdomain);
const struct DBEntry *zone_lookup_delegation(const struct DBZone *zone, const struct DB_XDomain *xdomain);
const struct DBEntry *zone_lookup_delegation2(const struct DBZone *zone, struct DomainPointer domain);

const struct DBrrset *zone_get_soa_rr(const struct DBZone *zone);
void zone_name_from_record(const struct DBZone *zone, const struct DBEntry *record, struct DomainPointer *name, struct DomainPointer *origin);
void zone_name(const struct DBZone *zone, struct DomainPointer *origin);
uint64_t zone_hash(const struct DBZone *zone);
struct DBZone *zone_next(struct DBZone *zone);
void zone_insert_self(struct DBZone *zone, volatile struct DBZone **next);

const struct DBEntry *zone_entry_by_index(const struct DBZone *zone, unsigned i);


#ifdef __cplusplus
}
#endif
#endif
