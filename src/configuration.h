#ifndef CONFIGURATION_H
#define CONFIGURATION_H
#include <stddef.h>

struct Cfg_AddrMatchList;

struct Cfg_AddrMatchElement
{
    union {
        unsigned char v6[16];
        unsigned v4;
        const struct Cfg_AddrMatchList *other;
    } ip;
    char *key;
    unsigned is_not:1;
    unsigned version:4;
    unsigned cidr:8;
    unsigned short port;
};

struct Cfg_AddrMatchList
{
    char *name;
    unsigned port;
    struct Cfg_AddrMatchElement *elements;
    size_t elements_count;
};

struct Cfg_Key
{
    /* Each key has a "name" reference. Whenever this key is used,
     * that name is referenced */
    char *name;

    /* This is the (binary) secret used for TSIG authentication of
     * packets. While the original field is specified in base64, it's
     * stored here as the binary */
    unsigned char *secret;
    size_t secret_length;

    /* Each key has an algorithm. If that algorithm is non specified,
     * the the default is "HMAC-MD5" */
    int algorithm;

    /* Instead of sending the full sized number of bits, fewer bits
     * can be transmitted in order to save space in the packets. This
     * means sha-256 can be used, but instead of sending the full 256-bits,
     * only 128-bits can be sent, saving 16 bytes of the packet. This is
     * only used when sending packets, on receipt it uses whatever size
     * is specified (a minimum of 80 bits). The default value, 0, means
     * that no truncation will be performed. */
    unsigned truncate_bits;
};

enum {CFGZ_UNKNOWN, CFGZ_SLAVE, CFGZ_MASTER};
struct Cfg_Zone
{
    /* the domain name of the zone */
    char *name;

    /* Zones of type 'slave' read zonefiles once upon startup, but forever
     * after receive their updates via UPDATE/IXR/AXFR from a master, an
     * overwrite zonefiles with latest updates.
     * Zones of type 'master' read zonefiles upon startup, then reread them
     * every time they are changed by some other process.
     */
    int type;

    /* The zonefile which we read from at startup, reread for master zones,
     * and overwrite for slave zones */
    char *file;

    /* For 'slave' zones, in addition to masters, these servers can send us
     * NOTIFY packets. (allow incoming NOTIFYs) */
    struct Cfg_AddrMatchList *allow_notify;

    /* Send these slave server NOTIFY packes when the zone changes */
    struct Cfg_AddrMatchList *also_notify;

    /* These clients can request an AXFR for this zone (allow outgoing AXFRs)*/
    struct Cfg_AddrMatchList *allow_transfer;

    /* For 'slave' zones, these are the masters from which we get updates
     * via NOTIFY/IXFR, AXFR, and UPDATE packets */
    struct Cfg_AddrMatchList *masters;
};



struct ConfigurationOptions {

    /**
     * Directory from which all other file references are
     * relative to
     */
    char *directory;

    char *pid_file;

    char *hostname;

    char *server_id;
    size_t server_id_length;

    char *version;
    size_t version_length;

};

struct ConfigurationDataPlane {
    unsigned port;
    unsigned interface_interval;
};


struct Configuration
{
    struct Cfg_AddrMatchList **acls;
    size_t acls_length;

    struct Cfg_Key **keys;
    size_t keys_length;

    struct Cfg_Zone **zones;
    size_t zones_length;

    struct Cfg_Zone **zonedirs;
    size_t zonedirs_length;

    struct Cfg_Zone *zone_defaults;

    struct ConfigurationOptions options;
    struct ConfigurationDataPlane data_plane;
    struct ConfigurationDataPlane control_plane;

};

/**
 * This must be called once at process startup before any of the
 * other configuration functions are used.
 */
void cfg_parser_init(void);


struct Configuration *cfg_create(void);
void cfg_destroy(struct Configuration *cfg);


/**
 * Read a configuration file into the configuration structure.
 * The structure must have been first created by "cfg_create()".
 * Multiple sequential files can be read sequentially.
 */
void cfg_parse_file(struct Configuration *cfg, const char *filename);


/**
 * We maintain a list of "address-lists", usually specified in the
 * "acl" statement. Other statemetns can reference those lists instead
 * of redefining their own lists
 */
const struct Cfg_AddrMatchList *
cfg_addrlist_lookup(const struct Configuration *cfg, const char *name);

/**
 * We maintain a list of TSIG "keys", specified in the "key" statement.
 * Other statements, and address lists, can reference those keys
 */
const struct Cfg_Key *
cfg_key_lookup(const struct Configuration *cfg, const char *name);


#endif
