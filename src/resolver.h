#ifndef RESOLVER_H
#define RESOLVER_H
#include "domainname.h"


struct Thread;
struct Catalog;
struct DNS_OutgoingResponse;
struct DNS_Incoming;




void resolver_algorithm(struct Catalog *catalog, struct DNS_OutgoingResponse *response, const struct DNS_Incoming *request);
void resolver_init(struct DNS_OutgoingResponse *response, const unsigned char *query_name, unsigned query_name_length, int query_type);

#endif
