const char test1[] = 
"# this is a test\n"
"// this is also a test\n"
"/* this is \n too a test */\n"
"\n"
"//defining acl's\n"
"// simple ip address acl\n"
"key marty { \n"
"    algorithm hmac-md5; \n"
"    secret \"dG9vIG1hbnkgc2VjcmV0cw==\";\n" 
"};\n"
"\n"
"acl \"someips\" {\n"
"  10.0.0.1; 192.168.23.1; 192.168.23.15;\n"
"};\n"
" // ip address acl with '/' format\n"
" acl \"moreips\" {\n"
"  10.0.0.1; \n"
"  192.168.23.128/25; // 128 IPs\n"
"};\n"
"// nested acl\n"
"acl \"allips\" {\n"
"  \"someips\"; \n"
"  \"moreips\";\n"
"};\n"
"// messy acl\n"
"acl \"complex\" {\n"
"  \"someips\"; \n"
"  10.0.15.0/24;\n"
"  !10.0.16.1/24; // negated\n"
"  {10.0.17.1;10.0.18.2;}; // nested\n"
" };\n"
"options {\n"
"   pid-file \"./named.pid\"; # comment \n"
"   directory \"/var/named\"; \n"
"   pid-file \"./named.pid\";\n"
"   port   /* testing */ 72 ; \n"
"   interface-interval  1234 ; // comment \n"
"   version \"this is a version\";"
"   version none;\n"
"   hostname \"test 1\";\n"
"   server-id \"test 2\";\n"
"};\n"
"\n"
"// using acl's\n"
"zone \"example.com\" {\n"
"  type slave;\n"
"  file \"slave.example.com\";\n"
"  allow-notify {\"complex\";}; \n"
"};\n"
"zone \"example.net\" {\n"
"  type slave;\n"
"  masters {192.168.2.3;192.168.2.4};\n"
"  file \"slave.example.net\";\n"
"  allow-transfer {\"none\";}; // this is a special acl\n"
"};\n"
;

/*
    CONF FILE PARSER SELF-TEST

    This is a small unit test to verify that the conf
    file parser is working correctly
*/
#include "configuration.h"
#include "conf-load.h"
#include "conf-parse.h"
#include <string.h>


/****************************************************************************
 ****************************************************************************/
int
conf_selftest(void)
{
    struct ConfParse *parse;
    struct Configuration *cfg = cfg_create();
    
    parse = confparse_create("<selftest>", confload_toplevel, cfg);
    confparse_parse(parse, (const unsigned char *)test1, sizeof(test1) - 1);
    confparse_destroy(parse);

    if (cfg->options.directory == 0 || strcmp(cfg->options.directory, "/var/named") != 0)
        return -1;

    if (cfg->options.pid_file == 0 || strcmp(cfg->options.pid_file, "/var/named/named.pid") != 0)
        return -1;

    if (cfg->options.hostname == 0 || strcmp(cfg->options.hostname, "test 1") != 0)
        return -1;
    if (cfg->options.server_id == 0 || strcmp(cfg->options.server_id, "test 2") != 0)
        return -1;

    if (cfg->data_plane.port != 72)
        return -1;

    if (cfg->options.version != NULL || cfg->options.version_length != 0)
        return -1;

    /*
     * key "name" {
     * };
     */
    {
        const struct Cfg_Key *key;

        key = cfg_key_lookup(cfg, "not-a-key");
        if (key != NULL)
            return -1;

        key = cfg_key_lookup(cfg, "marty");
        if (key == NULL)
            return -1;
        if (key->secret_length != strlen("too many secrets"))
            return -1;
        if (memcmp(key->secret, "too many secrets", strlen("too many secrets")) != 0)
            return -1;

    }

    return 0; /* success */
}

