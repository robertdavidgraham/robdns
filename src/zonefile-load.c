#include "db.h"
#include "db-zone.h"
#include "zonefile-load.h"
#include <string.h>

/******************************************************************************
 ******************************************************************************/
static void
format_domain(char *dst, size_t sizeof_dst, 
              struct DomainPointer domain, 
              struct DomainPointer origin)
{
    unsigned i;
    unsigned d = 0;
    
    for (i=0; i<domain.length; i++) {
        unsigned j;
        unsigned len = domain.name[i];
        const unsigned char *p = domain.name+1;
        for (j=0; j<len && d+1<sizeof_dst; j++)
            dst[d++] = p[j];
        if (d+1<sizeof_dst)
            dst[d++] = '.';
    }
    
    for (i=0; i<origin.length; i++) {
        unsigned j;
        unsigned len = origin.name[i];
        const unsigned char *p = origin.name+1;
        for (j=0; j<len && d+1<sizeof_dst; j++)
            dst[d++] = p[j];
        if (d+1<sizeof_dst)
            dst[d++] = '.';
    }
    
    if (d+1<sizeof_dst)
        dst[d] = '\0';
    else {
        dst[d-4] = '*';
        dst[d-3] = '*';
        dst[d-2] = '*';
        dst[d-1] = '\0';
    }
}

/*****************************************************************************
 *****************************************************************************/
void
ERROR_zone_not_found(const char *filename, unsigned line_number, struct DomainPointer domain, struct DomainPointer origin)
{
    char name[300];

    format_domain(name, sizeof(name), domain, origin);

    fprintf(stderr, "%s: %u: zone not found: %s\n",
            filename, line_number, name);
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
        catalog_create_zone2(db, domain, origin, filesize, filename);
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

