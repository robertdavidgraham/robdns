#include "db.h"
#include "db-zone.h"
#include "zonefile-load.h"

void
zonefile_load(
        struct DomainPointer domain,
        struct DomainPointer origin,
	    unsigned type,
        unsigned ttl,
        unsigned rdlength,
        const unsigned char *rdata,
        uint64_t filesize,
	    void *userdata)
{
    struct DBZone *zone;
    struct Catalog *db = (struct Catalog *)userdata;

    if (type == TYPE_SOA) {
        catalog_create_zone2(db, domain, origin, filesize);
    }

	zone = catalog_lookup_zone2(db, domain, origin);
    if (zone)
       zone_create_record2(
            zone, 
            domain,
            origin,
            type, ttl, rdlength, rdata);

/*
	if (rr->ztype == TYPE_SOA) {
		
	} else {
        struct DomainPointer prefix;
        struct DomainPointer suffix;

        prefix.name = rr->domain->name;
        prefix.length = rr->domain->length;
        suffix.name = rr->origin->name;
        suffix.length = rr->origin->length;

		zone = catalog_lookup_zone2(db, prefix, suffix);

        if (zone)
            zone_create_record2(zone, rr);

	}
*/
}

