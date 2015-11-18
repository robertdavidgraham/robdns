#include "configuration.h"
#include "conf-load.h"
#include "conf-parse.h"
#include "util-filename.h"
#include "util-ipaddr.h"
#include "util-realloc2.h"
#include "pixie-sockets.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <direct.h> /* getcwd */
#define getcwd _getcwd
#define strdup _strdup
#else
#include <unistd.h> /* getcwd, gethostname */
#endif

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
void
conf_load_adapter(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent)
{
}

/****************************************************************************
 ****************************************************************************/
int 
adapt_add_address(struct ConfigurationDataPlane *dp, int type, const void *v_addr, unsigned port)
{
    unsigned i;
    const unsigned char *addr = (const unsigned char *)v_addr;
    unsigned ipv4 = 0;

    if (v_addr)
       ipv4 = addr[0]<<24 | addr[1]<<16 | addr[2]<<8 | addr[3];

    /*
     * Discard duplicates
     */
    for (i=0; i<dp->adapter_count; i++) {
        if (dp->adapters[i].type != type)
            continue;
        if (dp->adapters[i].type != port)
            continue;
        switch (type) {
        case ST_Any:
            break;
        case ST_IPv4:
            if (dp->adapters[i].ip.v4 != ipv4)
                continue;
            break;
        case ST_IPv6:
            if (memcmp(dp->adapters[i].ip.v6, v_addr, 16) != 0)
                continue;
            break;
        default:
            return -1;
        }

        return -1;
    }

    if (dp->adapter_count >= sizeof(dp->adapters)/sizeof(dp->adapters[0]))
        return -2;

    {
        struct CoreSocketItem *adapt;

        adapt = &dp->adapters[dp->adapter_count++];
        memset(adapt, 0, sizeof(*adapt));

        adapt->type = type;
        adapt->port = port;

        switch (type) {
        case ST_Any:
            break;
        case ST_IPv4:
            adapt->ip.v4 = ipv4;
            break;
        case ST_IPv6:
            memcpy(adapt->ip.v6, v_addr, 16);
            break;
        default:
            return -1;
        }
    }

    return 0;
}

/****************************************************************************
 * listen-on { any; };
 *      Listens on any IPv4/IPv6 address. If IPv6 disabled, then only
 *      listens on IPv4.
 * listen-on-v6 { none; };
 *      Turns off listening on IPv6 addresses.
 ****************************************************************************/
void
conf_load_listen_on2(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent, unsigned port)
{
    unsigned i;

    /*
     * List of IPv4/IPv6 addresses, or keywords like "any" and "none"
     */
    for (i=0; i<parent->child_count; i++) {
        struct CF_Child child = confparse_node_getchild(parse, parent, i);
        struct ParsedIpAddress ip;
        struct CF_Token token = confparse_node_gettoken(parse, &child, 0);        
        unsigned offset = 0;
        unsigned j = 1;
        unsigned my_port = port;
        const char *my_keyname = 0;

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
         * Parse the IP address
         */
        if (child.token_count == 0 && child.child_count > 0) {
            conf_load_listen_on2(cfg, parse, &child, port);
        } else if (token.name_length == 3 && strcmp(token.name, "any") == 0) {
            adapt_add_address(&cfg->data_plane, ST_Any, NULL, my_port);
        } else if (token.name_length == 4 && strcmp(token.name, "none") == 0) {
            printf(".");
        } else if (parse_ip_address(token.name, &offset, token.name_length, &ip)) {
            char foo[64];
            format_ip_address(foo, sizeof(foo), ip.address, ip.version, ip.prefix_length);
            switch (ip.version) {
            case 4:
                adapt_add_address(&cfg->data_plane, ST_IPv4, ip.address, my_port);
                break;
            case 6:
                adapt_add_address(&cfg->data_plane, ST_IPv6, ip.address, my_port);
                break;
            default:
                CONF_VALUE_BAD(parse, &token);
            }
        } else {
            CONF_VALUE_BAD(parse, &token);
        }
    }
}

void
conf_load_listen_on(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent)
{
    unsigned j;
    unsigned port = 65536;
    
    /*
     * port
     */
    for (j = 1; j < parent->token_count; ) {
        struct CF_Token value;
        
        value = confparse_node_gettoken(parse, parent, j++);
        switch (lookup_token(&value)) {
        case S_PORT:
            value = confparse_node_gettoken(parse, parent, j++);
            if (is_number(&value) && to_number(&value) < 65536) {
                port = to_number(&value);
            } else
                CONF_VALUE_BAD(parse, &value);
            break;
        default:
            CONF_VALUE_BAD(parse, &value);
            break;
        }
    }

    conf_load_listen_on2(cfg, parse, parent, port);
}

/****************************************************************************
 ****************************************************************************/
void
conf_load_options(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent)
{
    struct ConfigurationOptions *options = &cfg->options;
    size_t i;

    for (i=0; i<parent->child_count; i++) {
        struct CF_Child child = confparse_node_getchild(parse, parent, i);
        struct CF_Token name;
        struct CF_Token value;
        
        name = confparse_node_gettoken(parse, &child, 0);
        value = confparse_node_gettoken(parse, &child, 1);

        switch (lookup_token(&name)) {
        case S_DIRECTORY:
            if (options->directory)
                free(options->directory);
            if (filename_is_absolute(value.name)) {
                options->directory = filename_combine(value.name, "");
            } else {
                char dir[2048];
                if (getcwd(dir, sizeof(dir)) == NULL) {
                    perror("getcwd");
                    exit(1);
                }
                options->directory = filename_combine(dir, value.name);
            }
            break;
        case S_PID_FILE:
            if (options->pid_file)
                free(options->pid_file);
            if (filename_is_absolute(value.name)) {
                options->pid_file = filename_combine(value.name, "");
                if (*options->pid_file && options->pid_file[strlen(options->pid_file)-1] == '/')
                    options->pid_file[strlen(options->pid_file)-1] = '\0';
            } else if (options->directory == NULL || strcmp(options->directory, ".") == 0) {
                char dir[2048];
                if (getcwd(dir, sizeof(dir)) == NULL) {
                    perror("getcwd");
                    exit(1);
                }
                options->pid_file = filename_combine(dir, value.name);
            } else
                options->pid_file = filename_combine(options->directory, value.name);
            break;
        case S_PORT:
            if (!is_number(&value))
                CONF_VALUE_BAD(parse, &value);
            else {
                unsigned n = to_number(&value);
                if (n > 65535)
                    CONF_VALUE_BAD(parse, &value);
                else
                    cfg->data_plane.port = n;
            }
            break;
        case S_LISTEN_ON:
        case S_LISTEN_ON_V6:
            conf_load_listen_on(cfg, parse, &child);
            break;
        case S_TRANSFER_SOURCE:
        case S_TRANSFER_SOURCE_V6:
        case S_ALT_TRANSFER_SOURCE:
        case S_ALT_TRANSFER_SOURCE_V6:
            break;
        case S_INTERFACE_INTERVAL:
            if (!is_number(&value))
                CONF_VALUE_BAD(parse, &value);
            else {
                unsigned n = to_number(&value);
                if (n > 40320)
                    CONF_VALUE_BAD(parse, &value);
                else
                    cfg->data_plane.interface_interval = n;
            }
            break;
        case S_VERSION:
            switch (lookup_token(&value)) {
            case S_NONE:
                if (options->version)
                    free(options->version);
                options->version = NULL;
                options->version_length = 0;
                break;
            default:
                if (options->version)
                    free(options->version);
                options->version = MALLOC2(value.name_length + 1);
                memcpy(options->version, value.name, value.name_length + 1);
                options->version_length = value.name_length;
                break;
            }
            break;
        case S_HOSTNAME:
            switch (lookup_token(&value)) {
            case S_NONE:
                if (options->hostname)
                    free(options->hostname);
                options->hostname = NULL;
                break;
            case S_HOSTNAME:
                if (options->hostname)
                    free(options->hostname);
                options->hostname = MALLOC2(130);
                if (gethostname(options->hostname, 130) != 0) {
                    perror("gethostname()");
                    free(options->hostname);
                    options->hostname = 0;
                }
                break;
            default:
                if (options->hostname)
                    free(options->hostname);
                options->hostname = MALLOC2(value.name_length + 1);
                memcpy(options->hostname, value.name, value.name_length + 1);
                break;
            }
            break;
        case S_SERVER_ID:
            switch (lookup_token(&value)) {
            case S_NONE:
                if (options->server_id)
                    free(options->server_id);
                options->server_id = NULL;
                options->server_id_length = 0;
                break;
            case S_HOSTNAME:
                if (options->server_id)
                    free(options->server_id);
                options->server_id = MALLOC2(130);
                if (gethostname(options->server_id, 130) != 0) {
                    perror("gethostname()");
                    free(options->server_id);
                    options->server_id = 0;
                    options->server_id_length = 0;
                } else
                    options->server_id_length = strlen(options->server_id);
                break;
            default:
                if (options->server_id)
                    free(options->server_id);
                options->server_id = MALLOC2(value.name_length + 1);
                memcpy(options->server_id, value.name, value.name_length + 1);
                options->server_id_length = value.name_length;
                break;
            }
            break;
        case S_ALLOW_NEW_ZONES:
            switch (lookup_token(&value)) {
            case S_YES:
                break;
            case S_NO:
                CONF_FEATURE_UNSUPPORTED(parse, &value);
                break;
            default:
                CONF_VALUE_BAD(parse, &value);
                break;
            }
            break;
        case S_RECURSION:
            switch (lookup_token(&value)) {
            case S_YES:
                CONF_FEATURE_UNSUPPORTED(parse, &value);
                break;
            case S_NO:
                //CONF_RECURSION_UNSUPPORTED(parse, &value);
                break;
            default:
                CONF_VALUE_BAD(parse, &value);
                break;
            }
            break;
        case S_AUTH_NXDOMAIN:
            switch (lookup_token(&value)) {
            case S_YES:
                CONF_FEATURE_UNSUPPORTED(parse, &value);
                break;
            case S_NO:
                break;
            default:
                CONF_VALUE_BAD(parse, &value);
                break;
            }
            break;
        case S_FORWARDERS:
            CONF_RECURSION_UNSUPPORTED(parse, &name);
            break;
        case S_DNSSEC_VALIDATION:
            CONF_FEATURE_UNSUPPORTED(parse, &name);
            break;
        default:
            CONF_OPTION_UNKNOWN(parse, &name);
            break;
        }
    }

}
