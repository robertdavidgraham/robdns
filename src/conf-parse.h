/*
    BIND9 named.conf parser

    This is a syntax-free parser for BIND9 configuration files.
    It doesn't understand any of the things it's parsing, 
    but instead just parses tokens, strings, and the hierarchical
    structure. It's up to the host program to process the
    strings in order to analyze the "statements" within the file.

    A named.conf file looks like the following:

        options {
            forwarders {
                192.168.1.1;
		        10.2.3.4;
            };
            statistics-file "/var/named/data/named_stats.txt";
            dump-file "/var/named/data/cache_dump.db";
            directory "/var/named";
        };
        zone "domain.com" {
            type slave;
            masters {
                192.168.1.1;
            };
        };

    The name at the root (in this case, "option" and "zone") is known
    as a "statement". When parsing the file, a callback function
    will be called for each complete statement (and all leaf nodes).

    This is for efficiency. One statement is "include", which the parser
    doesn't handle natively, but which the user code will have to handle
    explicitly, recursively calling the parser. Another important statement
    is "zone". A server might support a million zones. This can be very
    inefficient to load the entire configuration file, with all statements.
    It's much more efficient to process each statement one-at-a-time.


*/
#ifndef CONF_PARSE_H
#define CONF_PARSE_H
#include <stdio.h>
#include <stddef.h>
#include "conf-error.h"
struct ConfParse;
struct CF_Internals;

struct CF_Child
{
    char *name;
    size_t name_length;

    size_t token_count;
    size_t child_count;

    struct CF_Internals *internals;
};

struct CF_Token
{
    char *name;
    unsigned name_length;
    const char *filename;
    unsigned is_string:1;
    unsigned linenumber:31;
};

typedef int (*CONF_STATEMENT_CALLBACK)(struct ConfParse *conf, void *data, const struct CF_Child *node);


const char *confparse_err_file_line(const struct CF_Child *node, size_t *line_number);


/**
 * Enumerates the list of tokens at a node
 */
struct CF_Token confparse_node_gettoken(const struct ConfParse *conf, const struct CF_Child *node, size_t index);

/**
 * Enumerates child nodes in order to walk the configuration tree.
 */
struct CF_Child confparse_node_getchild(const struct ConfParse *conf, const struct CF_Child *node, size_t index);

/**
 * Create a BIND9 conf file parser
 */
struct ConfParse *confparse_create(const char *filename, CONF_STATEMENT_CALLBACK fn, void *data);

/**
 * Free/destory the memory from a parser
 */
void confparse_destroy(struct ConfParse *conf);

/**
 * Print the entire structure, for debugging purposes, or saving into a file
 */
void confparse_print_statement(struct ConfParse *conf, FILE *fp);

/**
 * Parse all the statements into one big structure
 */
void confparse_parse(struct ConfParse *conf, const unsigned char *data, size_t sizeof_data);



#endif
