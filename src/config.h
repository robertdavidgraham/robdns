#ifndef XXCONFIG_H
#define XXCONFIG_H
#include <stdint.h>
#include <stdio.h>

#if defined(WIN32)
typedef int bool;
enum { false, true };
#else
#include <stdbool.h>
#endif

/******************************************************************************
 ******************************************************************************/
struct Config;
struct Conf_AddressMatchList;

/******************************************************************************
 ******************************************************************************/
struct String
{
    char *str;
    size_t length;
    size_t capacity;
};
void string_free(struct String *str);
bool string_is_equal(struct String lhs, struct String rhs);


/******************************************************************************
 ******************************************************************************/
struct Keyword
{
    const char *str;
    size_t length;
};
bool kw_is_equals(const struct Keyword lhs, const char *rhs);

/******************************************************************************
 ******************************************************************************/
struct ConfText {
    const char *buf;
    const char *filename;
    size_t offset;
    size_t length;
    unsigned line_number;
    unsigned is_error:1;
};

/******************************************************************************
 ******************************************************************************/
struct Filenames {
    char **list;
    size_t count;
    size_t capacity;
};




enum Conf_ZoneType {Type_Master, Type_Slave, Type_Stub, Type_StaticStub,
    Type_Forward, Type_Hint, Type_Redirect, Type_DelegationOnly};


struct Conf_Zone
{
    struct String name;
    struct String filename;
    enum Conf_ZoneType type;
    bool is_notify;
    unsigned xclass;
    struct Conf_AddressMatchList *allow_transfer;
    struct Conf_AddressMatchList *also_notify;
    struct Conf_ZoneMaster *masters;
};
struct Conf_ZoneList
{
    struct Conf_Zone *list;
    size_t count;
    size_t capacity;
};

int conf_zone_parse(struct Config *conf, struct ConfText *t);
int conf_options_parse(struct Config *conf, struct ConfText *t);

struct Conf_AddressMatchList *
parse_addr_match_list(struct Config *conf, struct ConfText *t, bool is_not);

/******************************************************************************
 ******************************************************************************/
struct Config
{
    /**
     * Working directory fo the server. Non-absolute pathnames in config
     * files are relative to this directory. Default location for most
     * output files are in this directory. Typical examples are 
     * "/var/robdns".
     */
    struct String working_directory;

    /**
     * Where the server writes it's process ID. Used by other processes to
     * send signals to this process. Defaults to "none".
     */
    struct String pid_filename;

    /**
     * Where the server appends statistics when instructed to do so while
     * running.
     */
    struct String statistics_filename;

    /**
     * The default port to listen on. This is normally 53, but for testing
     * purposes, it can be useful to set to a different port.
     */
    unsigned listen_port;

    /**
     * If set, then optional glue records won't be set in responses
     */
    unsigned is_minimal_responses:1;

    unsigned is_notify:1;
    unsigned is_notify_masters_only:1;
    unsigned is_notify_explicit:1;
    unsigned is_notify_soa:1;
    unsigned is_allow_update_forwarding:1;

    /* recursion isn't supported, but many will try to set it anyway
     * so we parse it and notfiy people of the problem */
    unsigned is_recursion:1;

    /**
     * These servers are allowed to notify us of zone changes.
     */
    struct Conf_AddressMatchList *allow_notify;
    
    struct Conf_AddressMatchList *allow_update;


    struct Filenames filenames;
    struct Conf_ZoneList zones;
};




/******************************************************************************
 ******************************************************************************/
bool c__is_brace(const struct ConfText *t);
bool c__is_endbrace(const struct ConfText *t);
bool c__is_semicolon(const struct ConfText *t);
bool c__is_exclamation(const struct ConfText *t);
bool c__is_ipv4(const struct ConfText *t);

bool c__is_keyword(const struct ConfText *t, const char *keyword);

bool c__skip_brace(struct ConfText *t);
bool c__skip_endbrace(struct ConfText *t);
bool c__skip_semicolon(struct ConfText *t);
bool c__skip_exclamation(struct ConfText *t);
int c__skip_whitespace(struct ConfText *t);
int CONF_ERROR(struct ConfText *t, const char *fmt, ...);
struct String c__next_string(struct ConfText *t);
struct Keyword c__next_keyword(struct ConfText *t);
bool c__next_ipv4(struct ConfText *t, unsigned *address, unsigned *prefix);
bool c__next_boolean(struct ConfText *t);
bool c__next_uint32(struct ConfText *t, unsigned *port);


#endif
