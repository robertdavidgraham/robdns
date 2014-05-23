#include "conf-addr-match.h"
#include <stdlib.h>

enum AddressMatchType {
    AddrMatch_None,
    AddrMatch_IPv4,
    AddrMatch_IPv6,
    AddrMatch_Key,
    AddrMatch_Name,
    AddrMatch_Unknown,
};

/******************************************************************************
address_match_list = address_match_list_element ;
[ address_match_list_element; ... ]
address_match_list_element = [ ! ] (ip_address [/length] |
key key_id | acl_name | { address_match_list } )
 ******************************************************************************/
struct Conf_AddressMatchList
{
    enum AddressMatchType type;
    unsigned is_not:1;
    union {
        struct {
            unsigned address;
            unsigned char prefix;
        } ipv4;
        struct {
            unsigned char address[16];
            unsigned char prefix;
        } ipv6;
        struct {
            struct String name;
        } key;
        struct {
            struct String name;
        } acl;
    } element;
    struct Conf_AddressMatchList *next;
};


/******************************************************************************
 ******************************************************************************/
struct Conf_AddressMatchList *
parse_addr_match_element(struct Config *conf, struct ConfText *t, bool is_not)
{
    if (c__is_brace(t))
        return parse_addr_match_list(conf, t, is_not);

    if (c__is_exclamation(t)) {
        is_not = !is_not;
        c__skip_exclamation(t);
    }

    if (c__is_ipv4(t)) {
        unsigned address;
        unsigned prefix;
        struct Conf_AddressMatchList *result;

        c__next_ipv4(t, &address, &prefix);
        result = calloc(1, sizeof(*result));
        result->type = AddrMatch_IPv4;
        result->is_not = is_not;
        result->element.ipv4.address = address;
        result->element.ipv4.prefix = (unsigned char)prefix;
        result->next = 0;
        c__skip_semicolon(t);
        return result;        
    } else {
        CONF_ERROR(t, "address match element type unknown\n");
        return 0;
    }
}

/******************************************************************************
 ******************************************************************************/
struct Conf_AddressMatchList *
parse_addr_match_list(struct Config *conf, struct ConfText *t, bool is_not)
{
    struct Conf_AddressMatchList *result = 0;

    if (c__is_brace(t)) {
        if (!c__skip_brace(t))
            return result;
        while (!c__is_endbrace(t)) {
            bool tmp_is_not = is_not;
            struct Conf_AddressMatchList *p;

            if (c__is_exclamation(t)) {
                c__skip_exclamation(t);
                tmp_is_not = !is_not;
            }

            p = parse_addr_match_element(conf, t, is_not);
            if (p) {
                p->next = result;
                result = p;
            } else
                return result;
        }
        if (!c__skip_endbrace(t)) {
            CONF_ERROR(t, "expected ending brace\n");
            return result;
        }
        //c__skip_semicolon(t);
        return result;
    } else
        return parse_addr_match_element(conf, t, is_not);
}
