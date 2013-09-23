#ifndef DB_ENTRY_RR_H
#define DB_ENTRY_RR_H

struct DBrrset;
struct DB_XDomain;
struct DomainPointer;
struct Packet;
struct Compressor;
struct DBEntry;
struct DBZone;

const struct DBrrset *rrset_first(const struct DBEntry *record, int type);
const struct DBrrset *rrset_next(const struct DBEntry *record, int type, const struct DBrrset *rrset);
const struct DBEntry *rrset_get_glue(const struct DBZone *zone, const struct DBEntry *record, const struct DBrrset *rrset, struct DomainPointer *name);
void rrset_names_from_glue(const struct DBrrset *rrset, struct DomainPointer *name, struct DomainPointer *origin);
unsigned rrset_packet_append(const struct DBrrset *rrset, struct Packet *pkt, struct Compressor *compressor, struct DomainPointer name, struct DomainPointer origin);

#endif
