#include "db.h"
#include "db-zone.h"
#include "db-xdomain.h"
#include "zonefile-rr.h"
#include "pixie-threads.h"
#include "logger.h"
#include "util-realloc2.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>



struct Catalog
{
	struct DBZone **zones;
    unsigned zone_count;
    unsigned zone_mask;
    unsigned zones_created;

    unsigned min_labels;
	unsigned max_labels;
};

/****************************************************************************
 ****************************************************************************/
unsigned
catalog_zone_count(const struct Catalog *catalog)
{
    return catalog->zones_created;
}

/****************************************************************************
 * nearest power of 2 greater than the given number
 ****************************************************************************/
static uint64_t 
pow2(uint64_t x)
{
    uint64_t result = 1;

    while (result < x)
        result *= 2;

    return result;
}

/****************************************************************************
 * When reading in a million zones, we'll need to expand the hash table.
 * Therefore, we need to remove all the existing entries and expand
 ****************************************************************************/
void
catalog_reset_zonecount(struct Catalog *db, unsigned new_count)
{
    struct DBZone **old_zones = db->zones;
    size_t old_count = db->zone_count;
    size_t i;

    new_count = (unsigned)pow2(new_count);
    db->zone_count = new_count;
    db->zone_mask = new_count - 1;
    db->zones = MALLOC2(sizeof(db->zones[0]) * db->zone_count);
    if (db->zones == NULL)
        exit(1);
    memset(db->zones, 0, sizeof(db->zones[0]) * db->zone_count);

    for (i=0; i<old_count; i++) {

        while (old_zones[i]) {
            volatile struct DBZone **location;
            struct DBZone *zone;

            zone = old_zones[i];
            old_zones[i] = zone_next(zone);

            location = (volatile struct DBZone **)&db->zones[zone_hash(zone) & db->zone_mask];
            zone_insert_self(zone, location);
        }
    }
}


/****************************************************************************
 ****************************************************************************/
struct Catalog *
catalog_create()
{
	struct Catalog *db;


    /* Create object */
	db = REALLOC2(0, 1, sizeof(*db));
	memset(db, 0, sizeof(*db));
	
    /* Create the zone table */
    catalog_reset_zonecount(db, 128);

    /* Set min/max lable counts */
    db->min_labels = 128; /* impossible value: first zone entry will reduce this */
    db->max_labels = 0; /* also impossible, first zone increases this */
	return db;
}

void catalog_destroy(struct Catalog *catalog)
{
	free(catalog);
}



#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif



/****************************************************************************
 ****************************************************************************/
struct DBZone *
catalog_lookup_zone(const struct Catalog *db, const struct DB_XDomain *xdomain)
{
	int i;
    int min_labels;
    int max_labels;
    struct DBZone *zone = NULL;

	/* 
     * Work from longest possible zone-name to shortest possible
     * zone-name when doing the lookup.
     */
    max_labels = MIN(db->max_labels, xdomain->label_count);
    min_labels = db->min_labels;
	for (i=max_labels; i>=min_labels && i>0; i--) {
       	uint64_t hash_index;

        /* Get the hash table entry for this zone */
        hash_index = xdomain->labels[i-1].hash & db->zone_mask;
        zone = zone_follow_chain(db->zones[hash_index], xdomain, i);


        if (zone != NULL)
            break;
	}

    /* KLUDGE: handle if we host <root> domain */
    if (zone == NULL && min_labels == 0)
        zone = zone_follow_chain(db->zones[0], xdomain, i);


    /*
     * TODO: temporarily print an error if we cannot find
     * the zone
     */
	if (zone == NULL) {
		//xdomain_err(xdomain, ": does not match any zones\n");
	}

	return zone;
}
struct DBZone *
catalog_lookup_zone2(
    struct Catalog *db,
    struct DomainPointer prefix,
    struct DomainPointer suffix
    )
{
    struct DB_XDomain xdomain[1];

    xdomain_reverse3(xdomain, &prefix, &suffix);

    return catalog_lookup_zone(db, xdomain);
}

/****************************************************************************
 * Creates a new zone.
 * @param catalog
 *      The database. There is normally only one database for the entire
 *      process.
 * @param domain
 *      The domain-name of the zone, like "example.com".
 * @param soa
 *      The SOA resource-record for the zone.
 * @param filesize
 *      A hint about the size of the zone for pre-allocating a hash-table.
 ****************************************************************************/
const struct DBZone *
catalog_create_zone(
    struct Catalog *catalog,
    const struct DB_XDomain *domain,
    uint64_t filesize,
    const char *filename
    )
{
	struct DBZone **location;
    struct DBZone *zone;

    /*
     * Find the location in the linked-list
     */
    location = &catalog->zones[domain->hash & catalog->zone_mask];
    
    /*
     * See if it already exists
     */
    zone = zone_follow_chain(*location, domain, domain->label_count);
    if (zone)
        return zone;

    /* TODO: check chain depth, and if it's too long, increase
     * the size of the hash table */

    /*
     * If it doesn't exist, then create it, making it the new head
     * of the linked list at this hash location.
     */
    zone = zone_create_self(
                        domain,
                        filesize,
                        filename
                        );
    zone_insert_self(zone, (volatile struct DBZone **)location);

    if (verbosity > 3)
        xdomain_err(domain, ": create zone\n");

    if (catalog->min_labels >= domain->label_count)
        catalog->min_labels = domain->label_count;
    if (catalog->max_labels <= domain->label_count)
        catalog->max_labels = domain->label_count;

    /*
     * Remember how many zones are created. Basically, all we really
     * care is if the number is non-zero, which other parts can use
     * to detect that we failed to load a zone-file correctly
     */
    catalog->zones_created++;

    return *location;
}
const struct DBZone *
catalog_create_zone2(
    struct Catalog *db,
	struct DomainPointer domain,
    struct DomainPointer origin,
    uint64_t filesize,
    const char *filename)
{
    struct DB_XDomain xdomain[1];

    xdomain_reverse3(xdomain, &domain, &origin);

    return catalog_create_zone(db, xdomain, filesize, filename);
}
