#include "config.h"
#include <stdlib.h>
#include <string.h>


struct Conf_ZoneMaster
{
    unsigned address;
    unsigned port;
    unsigned dscp;

    struct Conf_ZoneMaster *next;
};



struct Conf_Zone *
conf_zone_add(struct Conf_ZoneList *x, struct String s)
{
    
    /* expand if necessary */
    if (x->count + 1 >= x->capacity) {
        x->capacity = x->capacity * 2 + 1;
        if (x->list) {
            x->list = realloc(x->list,
                              x->capacity * sizeof(x->list[0]));
        } else {
            x->list = malloc(x->capacity * sizeof(x->list[0]));
        }
    }
    
    memset(&x->list[x->count], 0, sizeof(x->list[0]));
    x->list[x->count].name.str = malloc(s.length + 1);
    memcpy(x->list[x->count].name.str, s.str, s.length + 1);
    return &x->list[x->count++];
}

struct Conf_Zone *
conf_zone_lookup(struct Conf_ZoneList *x, struct String s)
{
    size_t i;
    for (i=0; i<x->count; i++) {
        if (string_is_equal(x->list[i].name, s))
            return &x->list[i];
    }
    return NULL;
}


/******************************************************************************
 ******************************************************************************/
struct Conf_ZoneMaster *
conf_zone_masters_parse(struct Config *conf, struct Conf_Zone *zone, struct ConfText *t)
{
    struct Conf_ZoneMaster *result = 0;
    unsigned default_port = 53;
    unsigned default_dscp = 0;

/*masters [port ip_port] [dscp ip_dscp] { ( masters_list | ip_addr
[port ip_port]
[dscp ip_dscp]
[key key] ) ; [...] }; ]*/
    again:
    if (c__is_keyword(t, "port")) {
        c__next_keyword(t);
        if (!c__next_uint32(t, &default_port) || default_port >= 65536) {
            CONF_ERROR(t, "corrupt port number\n");
            return 0;
        }
        goto again;
    }
    if (c__is_keyword(t, "dscp")) {
        c__next_keyword(t);
        if (!c__next_uint32(t, &default_dscp) || default_port >= 64) {
            CONF_ERROR(t, "corrupt dscp number\n");
            return 0;
        }
        goto again;
    }

    if (!c__skip_brace(t))
        return 0;

    while (!c__is_endbrace(t)) {

        if (c__is_ipv4(t)) {
            unsigned address;
            unsigned prefix = 32;
            struct Conf_ZoneMaster *master;
            
            c__next_ipv4(t, &address, &prefix);

            master = calloc(1, sizeof(*master));

            master->address = address;
            master->dscp = default_dscp;
            master->port = default_port;
            master->next = result;
            result = master;


            again2:
            if (c__is_keyword(t, "port")) {
                c__next_keyword(t);
                if (!c__next_uint32(t, &master->port) || master->port >= 65536) {
                    CONF_ERROR(t, "corrupt port number\n");
                    return result;
                }
                goto again2;
            }
            if (c__is_keyword(t, "dscp")) {
                c__next_keyword(t);
                if (!c__next_uint32(t, &master->dscp) || master->dscp >= 64) {
                    CONF_ERROR(t, "corrupt dscp number\n");
                    return result;
                }
                goto again2;
            }

        } else {
            CONF_ERROR(t, "master unknown\n");
            return result;
        }

        c__skip_semicolon(t);
    }

    c__skip_endbrace(t);

    return result;
}



/******************************************************************************
 ******************************************************************************/
int
conf_zone_parse(struct Config *conf, struct ConfText *t)
{
    struct String s;
    struct Conf_Zone *zone;
    
    s = c__next_string(t);
    if (t->is_error)
        return -1;
    
    zone = conf_zone_lookup(&conf->zones, s);
    if (zone == NULL)
        zone = conf_zone_add(&conf->zones, s);
    
    if (!c__is_brace(t)) {
        struct Keyword kw = c__next_keyword(t);
        if (kw_is_equals(kw, "internet") || kw_is_equals(kw, "IN")) {
            zone->xclass = 1;
        } else if (kw_is_equals(kw, "chaos") || kw_is_equals(kw, "CH") || kw_is_equals(kw, "CHAOS")) {
            zone->xclass = 3;
        } else if (kw_is_equals(kw, "hesiod") || kw_is_equals(kw, "HS")) {
            zone->xclass = 3;
        } else if (kw_is_equals(kw, "in")) {
            zone->xclass = 3;
        } else
            return CONF_ERROR(t, "zone type unknown\n");
    }

    if (!c__skip_brace(t))
        return -1;
    
    while (t->offset < t->length && t->buf[t->offset] != '}' && !t->is_error) {
        struct Keyword kw = c__next_keyword(t);
        
        if (kw_is_equals(kw, "type")) {
            kw = c__next_keyword(t);
            if (kw_is_equals(kw, "master"))
                zone->type = Type_Master;
            else if (kw_is_equals(kw, "slave"))
                zone->type = Type_Slave;
            else if (kw_is_equals(kw, "hint"))
                zone->type = Type_Hint;
            else if (kw_is_equals(kw, "stub"))
                zone->type = Type_Stub;
            else if (kw_is_equals(kw, "static-stub"))
                zone->type = Type_StaticStub;
            else if (kw_is_equals(kw, "forward"))
                zone->type = Type_Forward;
            else if (kw_is_equals(kw, "redirect"))
                zone->type = Type_Redirect;
            else if (kw_is_equals(kw, "delegation-only"))
                zone->type = Type_DelegationOnly;
            else 
                return CONF_ERROR(t, "zone type unknown\n");
            
        } else if (kw_is_equals(kw, "file")) {
            string_free(&zone->filename);
            zone->filename = c__next_string(t);
            if (t->is_error)
                return CONF_ERROR(t, "zone file corrupt\n");
        } else if (kw_is_equals(kw, "notify")) {
            zone->is_notify = c__next_boolean(t);
        } else if (kw_is_equals(kw, "allow-transfer")) {
            struct Conf_AddressMatchList *addrs;
            addrs = parse_addr_match_list(conf, t, 0);
            zone->allow_transfer = addrs;
        } else if (kw_is_equals(kw, "also-notify")) {
            zone->also_notify = parse_addr_match_list(conf, t, 0);
        } else if (kw_is_equals(kw, "masters")) {
            zone->masters = conf_zone_masters_parse(conf, zone, t);
        } else {
            return CONF_ERROR(t, "zone unknown statement: %.*s\n", (unsigned)kw.length, kw.str);
        }
        
        if (!c__skip_semicolon(t))
            return CONF_ERROR(t, "expected semicolon\n");

    }
    
    if (!c__skip_endbrace(t))
        return CONF_ERROR(t, "expected end brace\n");
    c__skip_semicolon(t);
    return 0;
}
