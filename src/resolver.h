#ifndef RESOLVER_H
#define RESOLVER_H
#include "domainname.h"


struct Thread;
struct Catalog;
struct DNS_OutgoingResponse;
struct DNS_Incoming;



/**
 * !!!!! IMPORTANT !!!!!!
 *
 * THIS IS THE CENTER OF THE PROGRAM, THE PARTS THAT TAKES AN INCOMING REQUEST
 * CAN RESOLVES INTO THE RESULT
 */
void resolver_algorithm(const struct Catalog *catalog, 
                        struct DNS_OutgoingResponse *response, 
                        const struct DNS_Incoming *request);

/**
 * Call this before calling 'resolver_algorithm' to initialize the
 * response structure
 */
void resolver_init(struct DNS_OutgoingResponse *response, 
                   const unsigned char *query_name, 
                   unsigned query_name_length, 
                   int query_type,
                   unsigned id,
                   unsigned opcode);

#endif
