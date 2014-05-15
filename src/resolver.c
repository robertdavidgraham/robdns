#include "resolver.h"
#include "db-zone.h"
#include "db.h"
#include "db-rrset.h"
#include "proto-dns-compressor.h"
#include "proto-dns-formatter.h"
#include "proto-dns.h"
#include "string_s.h"
#include <stddef.h>

/****************************************************************************
 * Register an RRset in the appropriate answer/authority/additional section.
 * We don't copy the RRset to the packet right now, but instead, remember
 * the RRset for later when building a packet.
 ****************************************************************************/
void
response_copy_rrset_item(
        const struct DBrrset *rrset, 
        struct DNS_OutgoingResponse *response, 
        int section,
        struct DomainPointer name, 
        struct DomainPointer origin)
{
    struct DNS_ResponseRRset *rrr = &response->rrsets[0];
    static const size_t MAX_RRs = sizeof(response->rrsets)/sizeof(response->rrsets[0]);

    /* TRUNCATION CHECK: 
     * while we aren't building a packet yet, we may run out of room
     * in our list, so report this as a truncation error as well */
    if (response->ancount + response->nscount + response->arcount >= MAX_RRs) {
        /* additional records can be dropped without setting
         * truncation TC bit */
        if (section == SECTION_ADDITIONAL) {
            return;
        } else if (response->arcount) {
            response->arcount--;
        } else {
            response->tc = 1; /* truncation error */
            return;
        }
    }

    /* add to the appropriate location in our list */
    switch (section) {
    case SECTION_ANSWER:
        rrr = &response->rrsets[response->ancount];
        memmove(rrr+1, rrr, response->nscount * sizeof(*rrr));
        response->ancount++;
        break;
    case SECTION_AUTHORITATIVE:
        rrr = &response->rrsets[response->ancount + response->nscount];
        response->nscount++;
        break;
    case SECTION_ADDITIONAL:
        response->arcount++;
        rrr = &response->rrsets[MAX_RRs - response->arcount];
        break;
    }

    /* fill in pointers */
    rrr->rrset = rrset;
    rrr->name = name;
    rrr->origin = origin;
}


/****************************************************************************
 * Register all matching RRsets. If this is a narrow type, like an
 * AAAA or CNAME, then we'll register only a single RRset. If this is a
 * broad type, like ANY, then we'll copy more than one RRset.
 ****************************************************************************/
void
response_copy_rrsets(
        const struct DBEntry *entry,
        int type,
        struct DNS_OutgoingResponse *response,
        int section,
        struct DomainPointer name,
        struct DomainPointer origin)
{
    const struct DBrrset *rrset;

    /* copy call matching RRsets (e.g. if type=ANY, then we'll copy all
     * RRsets) */
    for (rrset=rrset_first(entry, type); rrset; rrset = rrset_next(entry, type, rrset)) {
        response_copy_rrset_item(rrset, response, section, name, origin);
    }
}

/****************************************************************************
 * Given an RRset that presumably contains things like NS or CNAME records,
 * do a lookup on the contents of those RRsets and also add glue RRsets
 ****************************************************************************/
static void
response_add_glue(
        const struct DBrrset *rrset, 
        struct DNS_OutgoingResponse *response, 
        const struct DBZone *zone,
        const struct DBEntry *entry)
{
    //const struct DBEntry *glue;
    //struct DomainPointer name = {0,0};
    //static const struct DomainPointer origin = {0,0};

    /*glue = rrset_get_glue(zone, entry, rrset, &name);
    if (glue) {
        response_copy_rrsets(glue, TYPE_A, response, SECTION_ADDITIONAL, name, origin);
        response_copy_rrsets(glue, TYPE_AAAA, response, SECTION_ADDITIONAL, name, origin);
    }*/
}

/****************************************************************************
 * Initialize an "outgoing-response" prototype, given parsed 
 * "incoming-request" information, namely the QNAME and QTYPE.
 ****************************************************************************/
void
resolver_init(
        struct DNS_OutgoingResponse *response, 
        const unsigned char *query_name,
        unsigned query_name_length,
        int query_type,
        unsigned id,
        unsigned opcode)
{
    memset(response, 0, offsetof(struct DNS_OutgoingResponse, query_type));
    response->query_name.name = query_name;
    response->query_name.length = query_name_length;
    response->query_type = query_type;
    response->id = id;
    response->opcode = opcode;
    
}

/****************************************************************************
 ****************************************************************************
 ** THIS IS WHERE IT ALL HAPPENS !!!!
 **
 **     This is the central/core function of the entire DNS server. It's at
 **     this point that we take an incoming-request (mostly containing
 **     a QNAME/QTYPE) and from it generate an outgoing-response prototype.
 **
 **     Note the bunch of quirkiness. For example, the input is not the
 **     the DNS request packet itself, but a parsed version of the request.
 **     Likewise, we don't generate the response packet in this function,
 **     but only a "prototype" for the reponse packet.
 **
 ****************************************************************************
 ****************************************************************************/
void
resolver_algorithm(
        const struct Catalog *catalog,
        struct DNS_OutgoingResponse *response,
        const struct DNS_Incoming *request)
{
    struct DBZone *zone;
    const struct DBEntry *entry;
    struct DB_XDomain query_name_x[1];
    struct DomainPointer root = {0,0};
    struct DomainPointer query_name = response->query_name;
    int query_type = request->query_type;

    
    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
     * handle format errors
     * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
    if (request->is_formerr) {
        response->rcode = RCODE_FORMERR;
        return;
    }

    
    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
     * handle version.bind requests
     * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
    if (request->query_class == 3 
        && request->query_type == 16
        && request->query_name.length == 13
        && memcasecmp(request->query_name.name, 
                       "\x07" "version" "\x04" "bind" "\x00", 13) == 0) {
            response->is_version_bind = 1;
            return;
    } else {
        response->is_version_bind = 0;
    }


    xdomain_reverse2(query_name_x, query_name.name, query_name.length);


    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
     * clear recursion flag
     *  RFC 1034 4.3.2. 1.
     * This is (and always will be) an authorative-only server,
     * so the recursion bit is always clear
     * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
    response->ra = 0;


    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
     * find zone
     *  RFC 1034 4.3.2. 2.
     * Do a "longest suffix" match to find longest name that matches
     * the query name.
     * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
  	zone = catalog_lookup_zone(catalog, query_name_x);
    if (zone == NULL) {
        response->aa = 0;
        response->rcode = RCODE_REFUSED;
        return;
    }

    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
     * delegation/referral/cut
     *  RFC 1034 4.3.2. 3. b. 
     * A pointer to another zone "hides" everything else after it.
     * Thus, if we have an NS enry for "a.example.com." and a entry
     * for "c.b.a.example.com." then the server can never find that
     * entry, UNLESS it's part of glue.
     * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
    entry = zone_lookup_delegation(zone, query_name_x);
    if (entry != NULL) {
        const struct DBrrset *rrset;
        struct DomainPointer name;
        struct DomainPointer origin;

        /* TODO: reference for this? */
        response->aa = 0;

        /* don't have name in one piece, so splice it back together */
        zone_name_from_record(zone, entry, &name, &origin);

        /* copy all name-server records (and glue) into response */
        for (rrset=rrset_first(entry, TYPE_NS); rrset; rrset = rrset_next(entry, TYPE_NS, rrset)) {

            response_copy_rrset_item(rrset, response, SECTION_AUTHORITATIVE, name, origin);

            response_add_glue(rrset, response, zone, entry);
        }
        return;
    }

    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
     * exact match
     *  RFC 1034 4.3.2. 3. b.
     * Now try for an exact match, which takes precedence over wildcards.
     * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
    entry = zone_lookup_exact(zone, query_name_x);
    if (entry != NULL) {
        const struct DBrrset *rrset;
        unsigned count = 0;

        for (rrset=rrset_first(entry, query_type); rrset; rrset = rrset_next(entry, query_type, rrset)) {

            response_copy_rrset_item(rrset, response, SECTION_ANSWER, query_name, root);

            response_add_glue(rrset, response, zone, entry);

            count++;
        }

        if (count)
            return;
        else
            goto soa;
    }

    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
     * wildcard match
     *  RFC 1034 4.3.2. 3. c.
     * We haven't found what we are looking for, do a "longest suffix" search
     * for wildcard records. If found, we don't use the name in the wilcard,
     * but instead use the query-name as the psueod-name of the RRs.
     * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
    entry = zone_lookup_wildcard(zone, query_name_x);
    if (entry != NULL) {
        const struct DBrrset *rrset;
        unsigned count = 0;

        for (rrset=rrset_first(entry, query_type); rrset; rrset = rrset_next(entry, query_type, rrset)) {

            response_copy_rrset_item(rrset, response, SECTION_ANSWER, query_name, root);

            response_add_glue(rrset, response, zone, entry);

            count++;
        }

        if (count)
            return;
    }

    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
     * negative response (zone found, entry not found)
     *  RFC 1034 4.3.4
     * We found a zone, but not the entry within the zone. Therefore, we
     * should add our SOA entry with the MINIMUM TTL so that resolvers
     * know how long they can cache the negative response
     * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/
soa:
    {
        const struct DBrrset *rrset;
        struct DomainPointer name;
        struct DomainPointer origin;

        response->rcode = RCODE_NXDOMAIN;
        
        zone_name_from_record(zone, 0, &name, &origin);

        rrset = zone_get_soa_rr(zone);

        response_copy_rrset_item(rrset, response, SECTION_AUTHORITATIVE, name, origin);

        /* We don't add NS glue because we are really just returning the 
         * TTL and nothing else */
        return;
    }
}

