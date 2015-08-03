#ifndef THREAD_H
#define THREAD_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
struct Catalog;

struct Thread
{
    struct Catalog *catalog_run;
	unsigned ip_id;

	struct Statistics {
		uint64_t ip_bad_checksum;
		uint64_t icmp_bad_checksum;
		uint64_t icmp_bad_type;
	} stats;

    void *userdata;
};



#ifdef __cplusplus
}
#endif
#endif
