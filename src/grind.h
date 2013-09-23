#ifndef GRIND_H
#define GRIND_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include "success-failure.h"
#include "domainname.h"

struct Grind;
struct Domain;

struct Grind *grind_create();
void grind_destroy(struct Grind *grind);

int grind_load_zonefile(struct Grind *grind, const char *zonefilename, struct DomainPointer origin, uint64_t ttl);

int grind_load_configuration(struct Grind *grind, const char *filename);

struct Catalog *grind_get_catalog(struct Grind *grind);

#ifdef __cplusplus
}
#endif
#endif
