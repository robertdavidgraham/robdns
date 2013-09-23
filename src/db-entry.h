#ifndef DB_RECORD_H
#define DB_RECORD_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <stdint.h>
#include "zonefile-rr.h"

struct DB_XDomain;
struct DBEntry;

void entry_create_self(struct DBEntry **p_record, const struct DB_XDomain *xdomain, unsigned zone_label_count, 
    int type, unsigned ttl, unsigned rdlength, const unsigned char *rdata);
const struct DBEntry *entry_find(const struct DBEntry *record, const struct DB_XDomain *xdomain, unsigned zone_label_count, unsigned name_label_count);

unsigned entry_chain_length(const struct DBEntry *record);

int entry_is_delegation(const struct DBEntry *record);

struct DomainPointer entry_name(const struct DBEntry *record);

#ifdef __cplusplus
}
#endif
#endif
