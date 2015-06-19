#define _CRT_SECURE_NO_WARNINGS
#include "conf-load.h"
#include "conf-parse.h"
#include "configuration.h"
#include "smack.h"
#include "util-filename.h"
#include "conf-addrlist.h"
#include "conf-keys.h"
#include "conf-zone.h"
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>

#ifdef WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h> /* gethostname */
#include <direct.h> /* getcwd */
#define getcwd _getcwd
#else
#include <unistd.h> /* getcwd, gethostname */
#endif

void parse_configuration(struct Core *core, const char *filename);

struct Token2Identifier {
    const char *name;
    int id;
};

const struct Token2Identifier tokens[] = {
    {"acl",             S_ACL},
    {"algorithm",       S_ALGORITHM},
    {"allow-new-zones", S_ALLOW_NEW_ZONES},
    {"allow-notify",    S_ALLOW_NOTIFY},
    {"allow-transfer",  S_ALLOW_TRANSFER},
    {"also-notify",     S_ALSO_NOTIFY},
    {"alt-transfer-source",       S_ALT_TRANSFER_SOURCE},
    {"alt-transfer-source-v6",    S_ALT_TRANSFER_SOURCE_V6},
    {"auth-nxdomain",   S_AUTH_NXDOMAIN},
    {"directory",       S_DIRECTORY},
    {"dnssec-validation",S_DNSSEC_VALIDATION},
    {"file",            S_FILE},
    {"forwarders",      S_FORWARDERS},
    {"hostname",        S_HOSTNAME},
    {"include",         S_INCLUDE},
    {"interface-interval",        S_INTERFACE_INTERVAL},
    {"key",             S_KEY},
    {"master",          S_MASTER},
    {"listen-on",       S_LISTEN_ON},
    {"listen-on-v6",    S_LISTEN_ON_V6},
    {"no",              S_NO},
    {"none",            S_NONE},
    {"options",         S_OPTIONS},
    {"pid-file",        S_PID_FILE},
    {"port",            S_PORT},
    {"recursion",       S_RECURSION},
    {"secret",          S_SECRET},
    {"server-id",       S_SERVER_ID},
    {"slave",           S_SLAVE},
    {"transfer-source", S_TRANSFER_SOURCE},
    {"transfer-source-v6",        S_TRANSFER_SOURCE_V6},
    {"type",            S_TYPE},
    {"version",         S_VERSION},
    {"yes",             S_YES},
    {"zone",            S_ZONE},
    {"zone-directory",  S_ZONE_DIRECTORY},

    {0,0}
};

const struct Token2Identifier tsigkeys[] = {
    {"HMAC-MD5.SIG-ALG.REG.INT", S_HMAC_MD5},
    {"HMAC-MD5",        S_HMAC_MD5},
    {"hmac-md5",        S_HMAC_MD5},
    {"hmac-sha1",       S_HMAC_SHA1},
    {"hmac-sha224",     S_HMAC_SHA224},
    {"hmac-sha256",     S_HMAC_SHA256},
    {"hmac-sha384",     S_HMAC_SHA384},
    {"hmac-sha512",     S_HMAC_SHA512},
    {0,0}
};


struct SMACK *statement_names;



/****************************************************************************
 ****************************************************************************/
void cfg_parser_init(void)
{
    size_t i;

    statement_names = smack_create("confload", SMACK_CASE_SENSITIVE);

    for (i=0; tokens[i].name; i++) {
        smack_add_pattern(
                    statement_names,
                    tokens[i].name,
                    (unsigned)strlen(tokens[i].name) + 1,
                    tokens[i].id,
                    SMACK_ANCHOR_BEGIN
                    );
    }

    for (i=0; tsigkeys[i].name; i++) {
        char *foo;
        size_t len;
        smack_add_pattern(
                    statement_names,
                    tsigkeys[i].name,
                    (unsigned)strlen(tsigkeys[i].name) + 1,
                    tsigkeys[i].id,
                    SMACK_ANCHOR_BEGIN
                    );
        
        /* for truncation, where an algorithm might
         * appear as "hmac-md5-80" instead of simply
         * "hmac-md5" */
        len = strlen(tsigkeys[i].name);
        foo = malloc(len + 2);
        memcpy(foo, tsigkeys[i].name, len+1);
        foo[len] = '-';
        foo[len+1] = '\0';

        smack_add_pattern(
                    statement_names,
                    foo,
                    (unsigned)len,
                    tsigkeys[i].id,
                    SMACK_ANCHOR_BEGIN
                    );
        free(foo);
    }

    smack_compile(statement_names);

}


/****************************************************************************
 ****************************************************************************/
static void
print_node(struct ConfParse *conf, FILE *fp, const struct CF_Child *node, unsigned depth)
{
    size_t i;

    /* indent */
    for (i=0; i < depth * 4; i++)
        fprintf(fp, " ");

    /* print all tokens */
    for (i = 0; i < node->token_count; i++) {
        struct CF_Token token;
        const char *space = " ";

        token = confparse_node_gettoken(conf, node, i);

        if (i + 1 == node->token_count)
            space = "";
        if (token.is_string)
            fprintf(fp, "\"%.*s\"%s", token.name_length, token.name, space);
        else
            fprintf(fp, "%.*s%s", token.name_length, token.name, space);
    }

    /* print all children */
    if (node->child_count) {
        fprintf(fp, " {\n");
        for (i = 0; i < node->child_count; i++) {
            struct CF_Child child;
            child = confparse_node_getchild(conf, node, i);
            print_node(conf, fp, &child, depth+1);
        }
        for (i=0; i < depth * 4; i++)
            fprintf(fp, " ");
        fprintf(fp, "};\n");
    } else
        fprintf(fp, ";\n");
}

/****************************************************************************
 ****************************************************************************/
size_t lookup_name(const struct CF_Child *node)
{
    unsigned offset = 0;
    unsigned state = 0;

    return smack_search_next(   statement_names, 
                                &state, 
                                node->name, 
                                &offset, 
                                (unsigned)node->name_length + 1);
}

/****************************************************************************
 ****************************************************************************/
size_t lookup_token(const struct CF_Token *token)
{
    unsigned offset = 0;
    unsigned state = 0;

    return smack_search_next(   statement_names, 
                                &state, 
                                token->name, 
                                &offset, 
                                (unsigned)token->name_length + 1);
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
static void
load_acl(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent)
{
    struct ConfigurationOptions *options = &cfg->options;
    struct CF_Token value = confparse_node_gettoken(parse, parent, 1);
    struct Cfg_AddrMatchList *acl;

    /* address-lists must be named when inside an "acl" statement */
    if (value.name_length == 0) {
        CONF_VALUE_MISSING(parse, &value);
        return;
    }

    /* parse the address-list */
    acl = conf_load_addrlist(cfg, parse, parent, &value, 65536);
    if (acl == NULL)
        return;

    /* make sure it has a name */
    acl->name = malloc(value.name_length + 1);
    memcpy(acl->name, value.name, value.name_length + 1);
    
    /*
     * Add to our named set of address-lists. This is so that later
     * configuration parameters can refer back to this list rather than
     * redefining their own
     */
    if (cfg->acls_length == 0)
        cfg->acls = malloc(sizeof(cfg->acls[0]));
    else
        cfg->acls = realloc(cfg->acls, sizeof(cfg->acls[0]) * (cfg->acls_length + 1));
    

    cfg->acls[cfg->acls_length++] = acl;

}

/****************************************************************************
 ****************************************************************************/
static void
load_options(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent)
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
                options->version = malloc(value.name_length + 1);
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
                options->hostname = malloc(130);
                if (gethostname(options->hostname, 130) != 0) {
                    perror("gethostname()");
                    free(options->hostname);
                    options->hostname = 0;
                }
                break;
            default:
                if (options->hostname)
                    free(options->hostname);
                options->hostname = malloc(value.name_length + 1);
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
                options->server_id = malloc(130);
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
                options->server_id = malloc(value.name_length + 1);
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

/****************************************************************************
 ****************************************************************************/
int
confload_toplevel(struct ConfParse *parse, void *data, const struct CF_Child *node)
{
    struct Configuration *cfg = (struct Configuration *)data;

    if (node->token_count == 0)
        return 0;

    switch (lookup_name(node)) {
    case S_ACL:
        load_acl(cfg, parse, node);
        break;
    case S_INCLUDE:
        {
            struct CF_Token token = confparse_node_gettoken(parse, node, 1);
            char *filename;
            
            if (filename_is_absolute(token.name))
                filename = filename_combine("", token.name);
            else
                filename = filename_combine(cfg->options.directory, token.name);
            token.name = filename;
            token.name_length = (unsigned)strlen(filename);
            confload_configuration(cfg, filename, &token);
            free(filename);
        }
        break;
    case S_KEY:
        conf_load_key(cfg, parse, node);
        break;
    case S_OPTIONS:
        load_options(cfg, parse, node);
        break;

    case S_ZONE:
        conf_load_zone(cfg, parse, node);
        break;
                    
    default:
        //print_node(parse, stdout, node, 0);
        {
            struct CF_Token value = confparse_node_gettoken(parse, node, 0);
            CONF_OPTION_UNKNOWN(parse, &value);
        }
        break;
    }

    return 0;
}

/****************************************************************************
 ****************************************************************************/
void
confload_configuration(struct Configuration *cfg, const char *filename, const struct CF_Token *token)
{
    unsigned char line[267];
    FILE *fp;
    struct ConfParse *conf = confparse_create(filename, confload_toplevel, cfg);

    /* If this is the first configuration file, then record it as the base
     * directory until it changes.
     * WARNING: BIND9 uses the current-working-directory as the initial
     * base, but I don't like that. Therefore, I'm going to use the
     * config file as the base
     */
    if (cfg->options.directory == 0) {
        cfg->options.directory = filename_get_directory(filename);
    }

    fp = fopen(filename, "rt");
    if (fp == NULL) {
        if (token)
            CONF_ERR(conf, token, "%s\n", strerror(errno));
        else
            perror(filename);
        return;
    }

    while (fgets((char*)line, sizeof(line), fp))
        confparse_parse(conf, line, strlen((char*)line));

    printf("\n\n");

    fclose(fp);
}

void
cfg_parse_file(struct Configuration *cfg, const char *filename)
{
    confload_configuration(cfg, filename, 0);
}

