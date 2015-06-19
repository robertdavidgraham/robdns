#ifndef CONF_ADDRMATCHLIST_H
#define CONF_ADDRMATCHLIST_H


struct Cfg_AddrMatchList *
conf_load_addrlist(const struct Configuration *cfg, 
                    const struct ConfParse *parse, 
                    const struct CF_Child *parent,
                    const struct CF_Token *name,
                    unsigned port);

void
conf_addrmatch_free(struct Cfg_AddrMatchList *cfg);

#endif
