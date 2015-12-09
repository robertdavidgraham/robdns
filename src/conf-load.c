#define _CRT_SECURE_NO_WARNINGS
#include "conf-load.h"
#include "conf-parse.h"
#include "configuration.h"
#include "conf-trackfile.h"
#include "logger.h"
#include "smack.h"
#include "util-filename.h"
#include "conf-addrlist.h"
#include "conf-keys.h"
#include "conf-zone.h"
#include "util-realloc2.h"
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

#ifdef WIN32
#include <direct.h> /* getcwd */
#define getcwd _getcwd
#define strdup _strdup
#else
#include <unistd.h> /* getcwd, gethostname */
#endif

//void parse_configuration(struct Core *core, const char *filename);

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
        foo = MALLOC2(len + 2);
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
void
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
static void
load_acl(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent)
{
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
    acl->name = MALLOC2(value.name_length + 1);
    memcpy(acl->name, value.name, value.name_length + 1);
    
    /*
     * Add to our named set of address-lists. This is so that later
     * configuration parameters can refer back to this list rather than
     * redefining their own
     */
    cfg->acls = REALLOC2(cfg->acls, sizeof(cfg->acls[0]), cfg->acls_length + 1);
    

    cfg->acls[cfg->acls_length++] = acl;

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
        conf_load_options(cfg, parse, node);
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
    struct ConfParse *conf;
    
    /* If this is the first configuration file, then record it as the base
     * directory until it changes.
     */
    if (cfg->options.directory == 0) {
        if (filename_is_absolute(filename)) {
            filename = strdup(filename);
        } else {
            char dir[512];
            if (getcwd(dir, sizeof(dir)) == 0)
                exit(1);
            filename = filename_combine(dir, filename);
        }
        cfg->options.directory = filename_get_directory(filename);
    } else {
        /*
         * If the filename isn't absolute, then prefix it with the current
         * directory
         */
        if (filename_is_absolute(filename))
            filename = strdup(filename);
        else
            filename = filename_combine(cfg->options.directory, filename);
    }

    LOG_INFO(C_CONFIG, "Loading conf: %s\n", filename);

    /* Create a parser to read in the file */
    conf = confparse_create(filename, confload_toplevel, cfg);

    /*
     * Record the fact that we loaded this configuration file. During
     * SIGHUP, we can quickly tell if any of the configuration has, or
     * has not changed. If configuration hasn't changed, then we'll
     * skip re-reading the configuration.
     */
    conf_trackfile_add(cfg->tf, filename);


    /* Open the file */
    fp = fopen(filename, "rt");
    if (fp == NULL) {
        if (token)
            CONF_ERR(conf, token, "%s\n", strerror(errno));
        else {
            LOG_ERR(C_CONFIG, "%s: %s\n", filename, strerror(errno));
        }
        return;
    }

    /*
     * Parse the configuration file chunk-by-chunk
     * TODO: this reads in line-by-line, but the parser doesn't
     * care about lines, so we should instead read a chunk at 
     * a time.
     */
    while (fgets((char*)line, sizeof(line), fp))
        confparse_parse(conf, line, strlen((char*)line));

    /*
     * Free up resources used by the parser
     */
    confparse_destroy(conf);

    /*
     * Close
     */
    fclose(fp);
}

void
cfg_load_string(struct Configuration *cfg, const char *string)
{
    struct ConfParse *conf;
    
    conf = confparse_create("<internal>", confload_toplevel, cfg);

    confparse_parse(conf, (const unsigned char *)string, strlen(string));

    confparse_destroy(conf);
}

/****************************************************************************
 ****************************************************************************/
void
cfg_parse_file(struct Configuration *cfg, const char *filename)
{
    confload_configuration(cfg, filename, 0);
}

