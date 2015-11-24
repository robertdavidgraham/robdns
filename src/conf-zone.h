#ifndef CONF_ZONE_H
#define CONF_ZONE_H
#include <stdio.h>
struct Configuration;
struct ConfParse;
struct CF_Child;

void
conf_load_zone( struct Configuration *cfg, 
                const struct ConfParse *parse, 
                const struct CF_Child *parent);


const struct Cfg_Zone *conf_zone_lookup(const struct Configuration *cfg, const char *name);
void conf_zone_append( struct Configuration *cfg, struct Cfg_Zone *zone);
struct Cfg_Zone *conf_zone_create(const char *name, size_t name_length);

#endif
