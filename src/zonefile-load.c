#include "db.h"
#include "db-zone.h"
#include "zonefile-load.h"
#include <string.h>

/*****************************************************************************
 *****************************************************************************/
void
ERROR_zone_not_found(const char *filename, unsigned line_number, struct DomainPointer domain, struct DomainPointer origin)
{
    struct Offset {
        unsigned length;
        const unsigned char *pointer;
    } offsets[256];
    unsigned o = 0;
    unsigned i;

    memset(&offsets, 0, sizeof(offsets));

    for (i=0; i<domain.length; i++) {
        offsets[o].length = domain.name[i];
        offsets[o].pointer = domain.name+1;
        i += offsets[o].length;
        o++;
    }

    for (i=0; i<origin.length; i++) {
        offsets[o].length = origin.name[i];
        offsets[o].pointer = origin.name+1;
        i += offsets[o].length;
        o++;
    }

    fprintf(stderr, "%s: %u: zone not found: "
            "%*s%s" "%*s%s" "%*s%s" "%*s%s" "%*s%s" "%*s%s" "%*s%s" "%*s%s",
            filename, line_number,
            offsets[0].length, offsets[0].pointer, offsets[0].length?".":"",
            offsets[1].length, offsets[1].pointer, offsets[1].length?".":"",
            offsets[2].length, offsets[2].pointer, offsets[2].length?".":"",
            offsets[3].length, offsets[3].pointer, offsets[3].length?".":"",
            offsets[4].length, offsets[4].pointer, offsets[4].length?".":"",
            offsets[5].length, offsets[5].pointer, offsets[5].length?".":"",
            offsets[6].length, offsets[6].pointer, offsets[6].length?".":"",
            offsets[7].length, offsets[7].pointer, offsets[7].length?".":""
            );
            


}

/*****************************************************************************
 *****************************************************************************/
enum SuccessFailure
zonefile_load(
        struct DomainPointer domain,
        struct DomainPointer origin,
	    unsigned type,
        unsigned ttl,
        unsigned rdlength,
        const unsigned char *rdata,
        uint64_t filesize,
	    void *userdata,
        const char *filename,
        unsigned line_number)
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
        fprintf(stderr, "%s:%u: zone not found\n", filename, line_number);
        ERROR_zone_not_found(filename, line_number, domain, origin);
        /* todo: print error message here?? */
        return Failure;
    }

    /*
     * Now insert the record into the zone
     */
    zone_create_record2(
            zone, 
            domain,
            origin,
            type, ttl, rdlength, rdata);

    return Success;
}

