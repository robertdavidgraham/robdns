#include "config.h"
#include <stdlib.h>
#include <string.h>



/******************************************************************************
 ******************************************************************************/
int
conf_options_parse(struct Config *conf, struct ConfText *t)
{
    if (!c__skip_brace(t))
        return CONF_ERROR(t, "options expected brace\n");
        
    while (!c__is_endbrace(t) && !t->is_error) {
        struct Keyword kw;
        
        kw = c__next_keyword(t);
        
        if (kw_is_equals(kw, "directory")) {
            string_free(&conf->working_directory);
            conf->working_directory = c__next_string(t);
        } else if (kw_is_equals(kw, "pid-file")) {
            string_free(&conf->pid_filename);
            if (c__is_keyword(t, "none"))
                kw = c__next_keyword(t);
            else
                conf->pid_filename = c__next_string(t);
        } else if (kw_is_equals(kw, "statistics-file")) {
            string_free(&conf->statistics_filename);
            conf->statistics_filename = c__next_string(t);
        } else if (kw_is_equals(kw, "port")) {
            unsigned port = 53;
            if (!c__next_uint32(t, &port) || port >= 65536)
                return CONF_ERROR(t, "options port invalid\n");
            conf->listen_port = port;
        } else if (kw_is_equals(kw, "minimal-responses")) {
            conf->is_minimal_responses = c__next_boolean(t);
        } else if (kw_is_equals(kw, "notify")) {
            if (c__is_keyword(t, "master-only")) {
                c__next_keyword(t);
                conf->is_notify = true;
                conf->is_notify_masters_only = true;
            } else if (c__is_keyword(t, "explicit")) {
                c__next_keyword(t);
                conf->is_notify = true;
                conf->is_notify_explicit = true;
            } else
                conf->is_notify = c__next_boolean(t);
        } else if (kw_is_equals(kw, "notify-to-soa")) {
            conf->is_notify_soa = c__next_boolean(t);
        } else if (kw_is_equals(kw, "recursion")) {
            conf->is_recursion = c__next_boolean(t);
        } else if (kw_is_equals(kw, "allow-notify")) {
            conf->allow_notify = parse_addr_match_list(conf, t, 0);
        } else if (kw_is_equals(kw, "allow-update")) {
            conf->allow_update = parse_addr_match_list(conf, t, 0);
        } else {
            return CONF_ERROR(t, "option unknown statement: %.*s\n", (unsigned)kw.length, kw.str);
        }
        
        if (t->is_error)
            return CONF_ERROR(t, "options corrupt\n");
        c__skip_semicolon(t);
    }
    
    if (!c__skip_endbrace(t))
        return CONF_ERROR(t, "expected end brace\n");
    c__skip_semicolon(t);
    return 0;
}
