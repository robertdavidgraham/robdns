#include "db.h"
#include "db-zone.h"
#include "zonefile-load.h"

/*****************************************************************************
 *****************************************************************************/
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

    /*
     * If this is an SOA record, first make sure that the zone
     * exists.
     */
    if (type == TYPE_SOA) {
        catalog_create_zone2(db, domain, origin, filesize);
    }

    /*
     * Find the zone associated with the record.
     */
	zone = catalog_lookup_zone2(db, domain, origin);
    if (!zone) {
        /* todo: print error message here?? */
        return;
    }

    /*
     * Now insert the record into the zone
     */
    zone_create_record2(
            zone, 
            domain,
            origin,
            type, ttl, rdlength, rdata);
}

