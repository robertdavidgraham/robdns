#ifndef CONF_LOAD_H
#define CONF_LOAD_H
#include <stddef.h>

struct CF_Token;
struct ConfParse;
struct CF_Child;
struct Configuration;

void confload_configuration(struct Configuration *cfg, const char *filename, const struct CF_Token *token);

int confload_toplevel(struct ConfParse *parse, void *data, const struct CF_Child *node);


void conf_load_options(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent);



/**
 * Translate a string to an integer, such as looking up the token
 * with the value of "options", returning an integer S_OPTIONS.
 * @token
 *      A string parsed from the configuration file.
 * @returns
 *      A integer enumeration ConfTokenId.
 */
size_t lookup_token(const struct CF_Token *token);

enum ConfTokenId {
    S_UNKNOWN,
    S_ACL,
    S_ALGORITHM,
    S_ALLOW_NEW_ZONES,
    S_ALLOW_NOTIFY,
    S_ALLOW_TRANSFER,
    S_ALSO_NOTIFY,
    S_ALT_TRANSFER_SOURCE,
    S_ALT_TRANSFER_SOURCE_V6,
    S_AUTH_NXDOMAIN,
    S_DIRECTORY,
    S_DNSSEC_VALIDATION,
    S_FILE,
    S_FORWARDERS,
    S_GSS_TSIG,
    S_HMAC_MD5,
    S_HMAC_SHA1,
    S_HMAC_SHA224,
    S_HMAC_SHA256,
    S_HMAC_SHA384,
    S_HMAC_SHA512,
    S_HOSTNAME,
    S_INCLUDE,
    S_INTERFACE_INTERVAL,
    S_KEY,
    S_LISTEN_ON,
    S_LISTEN_ON_V6,
    S_MASTER,
    S_NO,
    S_NONE,
    S_OPTIONS,
    S_PID_FILE,
    S_PORT,
    S_RECURSION,
    S_SECRET,
    S_SERVER_ID,
    S_SLAVE,
    S_TRANSFER_SOURCE,
    S_TRANSFER_SOURCE_V6,
    S_TYPE,
    S_VERSION,
    S_YES,
    S_ZONE,
    S_ZONE_DIRECTORY,
};

#endif
