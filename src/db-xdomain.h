#ifndef DB_XDOMAIN_H
#define DB_XDOMAIN_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
struct DomainPointer;

struct DB_XDomain
{
	uint64_t hash;
	unsigned label_count;
	struct {
		const unsigned char *name;
		uint64_t hash;
	} labels[127];
};


struct Domain;

int xdomain_is_equal(const struct DB_XDomain *lhs, const struct DomainPointer *rhs, unsigned max_labels);
void xdomain_copy(const struct DB_XDomain *lhs, struct DomainPointer *rhs);

void xdomain_reverse2(struct DB_XDomain *result, const unsigned char *name, unsigned length);
void xdomain_err(const struct DB_XDomain *domain, const char *fmt, ...);
int xdomain_is_wildcard(const struct DB_XDomain *domain);
uint64_t xdomain_label_hash(const struct DB_XDomain *xdomain, unsigned label_count);

void xdomain_reverse3(struct DB_XDomain *result, const struct DomainPointer *prefix, const struct DomainPointer *suffix);



#ifdef __cplusplus
}
#endif
#endif
