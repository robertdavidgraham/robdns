/*

    addr-match-list

    The BNF for this is :

        address_match_list = element ; [ element; ... ]
        element = [!] (ip [/prefix] | key key-name | "acl_name" | { address_match_list } )

    The four predefined addr-match-list names are:
        
        "none" - matches no IP addresses
        "any" - matches all IP addresses, or 0.0.0.0/0 or ::/0
        "localhost" - 127.0.0.1 or ::1, only accessible from the localhost
        "localnets" - local networks (from address mask info for host's IP addresses)

    Some examples:

    # 
    # All 192.168.2.0/24, except 192.168.2.7
    #
    options {
      allow-transfer { !192.168.2.7; 192.168.2/24;}; 
    };

    # 
    # All 192.168.2.0/24, even 192.168.2.7 too
    #
    options {
      allow-transfer {192.168.2.3/24; !192.168.2.7;};
    };

    #
    # Example useing a named addr-match-list
    #
    acl "good-guys" {
      !192.169.2.5/28; // denies first 16 IPs
      192.168.2/24;    // allows rest of subnet
      localnets;       // allows our network
      2001:db8:0:1::/64; // allows this subnet only
    };
    options {
       allow-transfer {"good-guys";};
    };
*/
#include "configuration.h"
#include "conf-load.h"
#include "conf-parse.h"
#include "util-ipaddr.h"
#include "util-realloc2.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


/****************************************************************************
 ****************************************************************************/
void
conf_addrmatch_free(struct Cfg_AddrMatchList *list)
{
    size_t i;

    if (list == NULL)
        return;
    if (list->name)
        free(list->name);
    for (i=0; i<list->elements_count; i++) {
        struct Cfg_AddrMatchElement *element = &list->elements[i];
        if (element->key)
            free(element->key);
        /* don't have to free 'element->ip.other' since it's simply pointing
         * to a name elsewhere */
    }
    if (list->elements)
        free(list->elements);
}

/****************************************************************************
 ****************************************************************************/
void
addrmatchlist_add_ipv4(struct Cfg_AddrMatchList *list, unsigned ipv4, unsigned cidr, unsigned port, unsigned is_not)
{
    struct Cfg_AddrMatchElement *element;

    list->elements = REALLOC2(list->elements, sizeof(list->elements[0]), list->elements_count + 1);

    element = &list->elements[list->elements_count++];
    memset(element, 0, sizeof(*element));

    element->is_not = is_not;
    element->cidr = cidr;
    element->port = port;
    element->version = 4;
    element->ip.v4 = ipv4;
    element->key = 0;


}


/****************************************************************************
 ****************************************************************************/
void
addrmatchlist_add_ipv6(struct Cfg_AddrMatchList *list, const unsigned char *ipv6, unsigned cidr, unsigned port, unsigned is_not)
{
    struct Cfg_AddrMatchElement *element;

    list->elements = REALLOC2(list->elements, sizeof(list->elements[0]), list->elements_count + 1);

    element = &list->elements[list->elements_count++];
    memset(element, 0, sizeof(*element));

    element->is_not = is_not;
    element->cidr = cidr;
    element->port = port;
    element->version = 4;
    memcpy(element->ip.v6, ipv6, 16);
    element->key = 0;
}


/****************************************************************************
 ****************************************************************************/
void
addrmatchlist_add_other(struct Cfg_AddrMatchList *list, const struct Cfg_AddrMatchList *other, unsigned is_not)
{
    struct Cfg_AddrMatchElement *element;

    list->elements = REALLOC2(list->elements, sizeof(list->elements[0]), list->elements_count + 1);

    element = &list->elements[list->elements_count++];
    memset(element, 0, sizeof(*element));

    element->is_not = is_not;
    element->version = 1;
    element->ip.other = other;
}

/****************************************************************************
 ****************************************************************************/
static void
addrmatchlist_add_special(struct Cfg_AddrMatchList *list, int version, int is_not)
{
    struct Cfg_AddrMatchElement *element;

    list->elements = REALLOC2(list->elements, sizeof(list->elements[0]), list->elements_count + 1);

    element = &list->elements[list->elements_count++];
    memset(element, 0, sizeof(*element));

    element->is_not = is_not;
    element->version = version;
}


/****************************************************************************
 ****************************************************************************/
static int
is_number(const struct CF_Token *token)
{
    size_t i;
    if (token->name_length == 0)
        return 0;
    for (i=0; i<token->name_length; i++) {
        if (!isdigit(token->name[i]&0xFF))
            return 0;
    }
    return 1;
}

/****************************************************************************
 ****************************************************************************/
static unsigned
to_number(const struct CF_Token *token)
{
    size_t i;
    unsigned result = 0;

    for (i=0; i<token->name_length; i++) {
        result = result * 10 + token->name[i] - '0';
    }
    return result;
}

/****************************************************************************
 ****************************************************************************/
const struct Cfg_AddrMatchList *
cfg_addrlist_lookup(const struct Configuration *cfg, const char *name)
{
    size_t i;
    for (i=0; i<cfg->acls_length; i++) {
        if (strcmp(name, cfg->acls[i]->name) == 0)
            return cfg->acls[i];
    }
    return 0;
}

/****************************************************************************
 ****************************************************************************/
void
conf_load_addrlist2(const struct Configuration *cfg, 
                    const struct ConfParse *parse, 
                    const struct CF_Child *parent,
                    unsigned port,
                    struct Cfg_AddrMatchList *result)
{
    size_t i;

    for (i=0; i<parent->child_count; i++) {
        struct CF_Child child = confparse_node_getchild(parse, parent, i);
        struct ParsedIpAddress ip;
        struct CF_Token token = confparse_node_gettoken(parse, &child, 0);        
        unsigned offset = 0;
        unsigned j = 1;
        unsigned my_port = port;
        const char *my_keyname = 0;
        unsigned is_not = 0;

        /*
         * see if there are "port" or "key" keywords after the
         * IP adress
         */
        for (j = 1; j < child.token_count; ) {
            struct CF_Token value;

            value = confparse_node_gettoken(parse, &child, j++);
            switch (lookup_token(&value)) {
            case S_PORT:
                value = confparse_node_gettoken(parse, &child, j++);
                if (is_number(&value) && to_number(&value) < 65536) {
                    my_port = to_number(&value);
                } else
                    CONF_VALUE_BAD(parse, &value);
                break;
            case S_KEY:
                value = confparse_node_gettoken(parse, &child, j++);
                if (value.name_length) {
                    my_keyname = value.name;
                }
                break;
            default:
                CONF_OPTION_UNKNOWN(parse, &value);
            }
        }

        /*
         * See if there is a "!" (not) symbol in front
         */
        if (token.name_length && token.name[0] == '!') {
            is_not = 1;
            token.name++;
            token.name_length--;
        }

        /*
         * Parse the IP address
         */
        if (child.token_count == 0 && child.child_count > 0) {
            conf_load_addrlist2(cfg, parse, &child, port, result);
        } else if (token.name_length == 3 && strcmp(token.name, "any") == 0) {
            addrmatchlist_add_special(result, 2, is_not);
        } else if (token.name_length == 4 && strcmp(token.name, "none") == 0) {
            addrmatchlist_add_special(result, 3, is_not);
        } else if (parse_ip_address(token.name, &offset, token.name_length, &ip)) {
            char foo[64];
            format_ip_address(foo, sizeof(foo), ip.address, ip.version, ip.prefix_length);
            switch (ip.version) {
            case 4:
                {
                    unsigned ipv4 = ip.address[0]<<24 | ip.address[1]<<16 | ip.address[2]<<8 | ip.address[3];
                    addrmatchlist_add_ipv4(result, ipv4, ip.prefix_length, port, is_not);
                }
                break;
            case 6:
                addrmatchlist_add_ipv6(result, ip.address, ip.prefix_length, port, is_not);
                break;
            }
        } else {
            const struct Cfg_AddrMatchList *other;

            other = cfg_addrlist_lookup(cfg, token.name);
            if (other) {
                addrmatchlist_add_other(result, other, is_not);
            } else 
                CONF_VALUE_BAD(parse, &token);
        }


    }
}

/****************************************************************************
 ****************************************************************************/
struct Cfg_AddrMatchList *
conf_load_addrlist(const struct Configuration *cfg, 
                    const struct ConfParse *parse, 
                    const struct CF_Child *parent,
                    const char *name,
                    unsigned port)
{
    struct Cfg_AddrMatchList *result;
  
    result = MALLOC2(sizeof(*result));
    memset(result, 0, sizeof(*result));

    if (name) {
        result->name = MALLOC2(strlen(name) + 1);
        memcpy(result->name, name, strlen(name) + 1);
    }
    conf_load_addrlist2(cfg, parse, parent, port, result);

    return result;
}
