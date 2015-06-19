#ifndef CONF_ZONE_H
#define CONF_ZONE_H

void
conf_load_zone( struct Configuration *cfg, 
                const struct ConfParse *parse, 
                const struct CF_Child *parent);

#endif
