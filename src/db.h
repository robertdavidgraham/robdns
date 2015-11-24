#ifndef DB_H
#define DB_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include "domainname.h"
struct Source;
struct Catalog;

/**
 * Create a new/empty DNS database with no zones or names.
 */
struct Catalog *catalog_create();

/**
 * Reset the hashtable for the zones, in case we are holding
 * thousands instead of hundreds
 */
void
catalog_reset_zonecount(struct Catalog *db, unsigned new_count);


/**
 * Free all the memory used in the DNS database, including
 * the individual zones.
 *
 * @param db
 *      A catalog created by a call to "catalog_create()"
 */
void catalog_destroy(struct Catalog *db);

/**
 * Creates a "zone" fomr an SOA RR record. This is a special insertion event
 * unlike all other normal RRs, because it creates a new zone rather than
 * inserting information into a zone.
 *
 * @param catalog
 *      A database created with a call to 'catalog_create()'
 * @param xdomain
 *      The domain-name of the zone
 * @param filesize
 *      A hint about the size of the file containing the zone. We use this
 *      hint in order to initialize an appropriately sized hash-table.
 *      If this hint is wrong, and we need to, we'll grow the size of the
 *      table
 * @return
 *      a pointer to the newly created zone, or NULL if an error occurred.
 */
const struct DBZone *
catalog_create_zone(
    struct Catalog *catalog,
    const struct DB_XDomain *xdomain,
    uint64_t filesize,
    const char *filename
    );

/* called with an SOA record to create a zone */    
const struct DBZone *
catalog_create_zone2(struct Catalog *db, 
    struct DomainPointer domain, struct DomainPointer origin, 
    uint64_t filesize, const char *filename);



/* "longest suffix" search for best matching zone */
struct DBZone *
catalog_lookup_zone(
    const struct Catalog *db,
    const struct DB_XDomain *xdomain
    );
struct DBZone *
catalog_lookup_zone2(
    struct Catalog *db,
    struct DomainPointer prefix,
    struct DomainPointer suffix
    );

/**
 * Counts the number of zones that have been created. This can be called
 * after parsing zone-files to see if any have been successfully parsed.
 *
 * @param catalog
 *      A database containing zones and domains.
 * @return
 *      the total number of zones that have been created.
 */
unsigned
catalog_zone_count(const struct Catalog *catalog);


#ifdef __cplusplus
}
#endif
#endif
