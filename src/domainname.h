#ifndef DOMAINNAME_H
#define DOMAINNAME_H
#include "db-xdomain.h"
extern struct DomainPointer ROOT;

struct DomainPointer
{
    const unsigned char *name;
    unsigned length;
};
struct Domainasdfasf
{
	unsigned char length;
	unsigned char is_absolute;
	unsigned char label;
	unsigned char *name;
};

#endif
