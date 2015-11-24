#include "conf-zone.h"
#include "configuration.h"
#include "conf-load.h"
#include "conf-parse.h"
#include "util-filename.h"
#include "conf-addrlist.h"
#include "util-realloc2.h"
#include "string_s.h"
#include <string.h>
#include <stdlib.h>

/****************************************************************************
 ****************************************************************************/
const struct Cfg_Zone *
conf_zone_lookup(const struct Configuration *cfg, const char *name)
{
    unsigned i;

    for (i=0; i<cfg->zones_length; i++) {
        const struct Cfg_Zone *zone = cfg->zones[i];

        if (strcasecmp(zone->name, name) == 0)
            return zone;
    }

    return 0;
}


/****************************************************************************
 ****************************************************************************/
struct Cfg_Zone *
conf_zone_create(const char *name, size_t name_length)
{
    struct Cfg_Zone *zone;

    zone = MALLOC2(sizeof(*zone));

    memset(zone, 0, sizeof(*zone));
    if (zone == NULL) {
        exit(1);
    }

    if (name_length) {
        zone->name = MALLOC2(name_length + 1);
        if (zone->name == NULL)
            exit(1);
        memcpy(zone->name, name, name_length + 1);
    }

    while (name_length && zone->name[name_length-1] == '.')
        zone->name[--name_length] = '\0';

    while (name_length && zone->name[0] == '.') {
        memmove(zone->name, zone->name+1, name_length);
        name_length--;
    }

    return zone;
}

/****************************************************************************
 ****************************************************************************/
void
conf_load_zone_item( struct Configuration *cfg, 
                const struct ConfParse *parse, 
                const struct CF_Child *parent,
                struct Cfg_Zone *zone
                )
{
    struct CF_Token token = confparse_node_gettoken(parse, parent, 0);
    struct CF_Token value = confparse_node_gettoken(parse, parent, 1);

    switch (lookup_token(&token)) {
    case S_TYPE:
        if (zone->type != 0)
            CONF_OPTION_DUPLICATE(parse, &token);
        switch (lookup_token(&value)) {
        case S_MASTER:
            zone->type = CFGZ_MASTER;
            break;
        case S_SLAVE:
            zone->type = CFGZ_SLAVE;
            break;
        default:
            CONF_VALUE_BAD(parse, &value);
        }
        break;
    case S_FILE:
        if (zone->file != 0) {
            CONF_OPTION_DUPLICATE(parse, &token);
            free(zone->file);
            zone->file = NULL;
        }
        if (value.name_length == 0) {
            CONF_VALUE_BAD(parse, &value);
        } else {
            zone->file = filename_combine(cfg->options.directory, value.name);

        }
        break;
    case S_ALLOW_NOTIFY:
        if (zone->allow_notify) {
            CONF_OPTION_DUPLICATE(parse, &token);
            conf_addrmatch_free(zone->allow_notify);
            zone->allow_notify = NULL;
        }
        zone->allow_notify = conf_load_addrlist(cfg, parse, parent, 0, 65536);
        break;
    case S_ALLOW_TRANSFER:
        if (zone->allow_transfer) {
            CONF_OPTION_DUPLICATE(parse, &token);
            conf_addrmatch_free(zone->allow_transfer);
            zone->allow_transfer = NULL;
        }
        zone->allow_transfer = conf_load_addrlist(cfg, parse, parent, 0, 65536);
        break;
    case S_ALSO_NOTIFY:
        if (zone->also_notify) {
            CONF_OPTION_DUPLICATE(parse, &token);
            conf_addrmatch_free(zone->also_notify);
            zone->also_notify = NULL;
        }
        zone->also_notify = conf_load_addrlist(cfg, parse, parent, 0, 65536);
        break;
    default:
        CONF_OPTION_UNKNOWN(parse, &token);
        break;
    }
}

void
conf_zone_append( struct Configuration *cfg, struct Cfg_Zone *zone)
{
    cfg->zones = REALLOC2(cfg->zones, sizeof(cfg->zones[0]), cfg->zones_length + 1);
    cfg->zones[cfg->zones_length++] = zone;
}

/****************************************************************************
 ****************************************************************************/
void
conf_load_zone( struct Configuration *cfg, 
                const struct ConfParse *parse, 
                const struct CF_Child *parent)
{
    struct CF_Token value = confparse_node_gettoken(parse, parent, 1);
    struct Cfg_Zone *zone;
    size_t i;

    if (value.name_length == 0) {
        CONF_VALUE_MISSING(parse, &value);
        return;
    }

    zone = conf_zone_create(value.name, value.name_length);

    /*
     * Parse all the options
     */
    for (i=0; i<parent->child_count; i++) {
        struct CF_Child child = confparse_node_getchild(parse, parent, i);

        conf_load_zone_item(cfg, parse, &child, zone);
    }

    /*
     * Add to our list of zones
     */
    conf_zone_append(cfg, zone);
}


/****************************************************************************
 ****************************************************************************/
void
cfg_add_zonefile(struct Configuration *cfg, const char *filename)
{
    struct Cfg_Zone *zone;

    /* Create an empty zone record -- we won't know the name of the zone
     * until we parse the file */
    zone = conf_zone_create(0, 0);

    /* Add in the zonefile name */
    zone->file = filename_combine(cfg->options.directory, filename);

    /*
     * Add to our list of zones
     */
    cfg->zones = REALLOC2(cfg->zones, sizeof(cfg->zones[0]), cfg->zones_length + 1);
    cfg->zones[cfg->zones_length++] = zone;
}
