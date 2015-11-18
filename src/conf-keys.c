#include "conf-parse.h"
#include "conf-load.h"
#include "conf-keys.h"
#include "configuration.h"
#include "crypto-base64.h"
#include "util-realloc2.h"
#include <string.h>
#include <stdlib.h>

/****************************************************************************
 ****************************************************************************/
const struct Cfg_Key *
cfg_key_lookup(const struct Configuration *cfg, const char *name)
{
    size_t i;
    for (i=0; i<cfg->keys_length; i++) {
        if (strcmp(name, cfg->keys[i]->name) == 0)
            return cfg->keys[i];
    }
    return 0;
}

/****************************************************************************
 ****************************************************************************/
void
conf_load_key(struct Configuration *cfg, const struct ConfParse *parse, const struct CF_Child *parent)
{
    struct CF_Token value = confparse_node_gettoken(parse, parent, 1);
    struct Cfg_Key *key;
    size_t i;

    /* key's must have a name */
    if (value.name_length == 0) {
        CONF_VALUE_MISSING(parse, &value);
        return;
    }

    key = MALLOC2(sizeof(*key));
    memset(key, 0, sizeof(*key));

    key->name = MALLOC2(value.name_length + 1);
    memcpy(key->name, value.name, value.name_length + 1);



    for (i=0; i<parent->child_count; i++) {
        struct CF_Child child = confparse_node_getchild(parse, parent, i);
        struct CF_Token token = confparse_node_gettoken(parse, &child, 0);
        
        value = confparse_node_gettoken(parse, &child, 1);

        switch (lookup_token(&token)) {
        case S_ALGORITHM:
            switch (lookup_token(&value)) {
            case S_HMAC_MD5:
            case S_HMAC_SHA256:
            case S_HMAC_SHA512:
                break;
            default:
                CONF_VALUE_BAD(parse, &value);
                break;
            }
            break;
        case S_SECRET:
            if (token.name_length == 0) {
                CONF_VALUE_MISSING(parse, &value);
            } else {
                unsigned char *secret;
                size_t secret_length = value.name_length;

                secret = MALLOC2(secret_length);

                secret_length = base64_decode(  secret,
                                                secret_length,
                                                value.name, 
                                                value.name_length);
                if (secret_length == 0) {
                    CONF_VALUE_BAD(parse, &value);
                    free(secret);
                } else {
                    if (key->secret) {
                        CONF_OPTION_DUPLICATE(parse, &value);
                        free(key->secret);
                    }
                    key->secret = secret;
                    key->secret_length = secret_length;
                }
            }

            break;
        default:
            CONF_OPTION_UNKNOWN(parse, &value);
            break;
        }
    }

    if (key->algorithm == 0)
        key->algorithm = S_HMAC_MD5;
    if (key->name == 0 || key->secret == 0) {
        if (key->name)
            free(key->name);
        if (key->secret)
            free(key->secret);
        free(key);
        return;
    }

    /*
     * Now add to our list of keys
     */
    cfg->keys = REALLOC2(cfg->keys, sizeof(cfg->keys[0]), cfg->keys_length + 1);
    
    cfg->keys[cfg->keys_length++] = key;

}
