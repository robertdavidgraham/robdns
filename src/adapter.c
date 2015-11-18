#include "adapter.h"
#include "unusedparm.h"
#include "util-realloc2.h"
#include <stdlib.h>
#include <string.h>

enum {
    DRIVER_LIBPCAP=1,
    DRIVER_LINUXRING=2,
    DRIVER_BPF=4,
    DRIVER_PFRING=8,
    DRIVER_DPDKPOLL=16,
    DRIVER_BSDNETMAP=32,
};
struct AdapterListItem
{
    char *adapter_name;
    char mac_address[6*3];
    char *driver;
};

const struct AdapterListItem *
adapter_list(unsigned *r_count)
{
    static struct AdapterListItem list[64];
    static unsigned count;
    unsigned i;

    UNUSEDPARM(r_count);

    /* Free the old list */
    for (i=0; i<count; i++) {
        free(list[i].adapter_name);
        free(list[i].driver);
    }

    return 0;
}

void
adapter_add_ipv4(struct Adapter *adapter, unsigned ipv4_address, unsigned mask)
{
    if (adapter->ipv4_count < sizeof(adapter->ipv4)/sizeof(adapter->ipv4[0])) {
        unsigned i = adapter->ipv4_count++;
        adapter->ipv4[i].address = ipv4_address;
        adapter->ipv4[i].mask = mask;
    }
}

struct Adapter *
adapter_create(ALLOC_PACKET alloc_packet, XMIT_PACKET xmit_packet, void *userdata)
{
    struct Adapter *adapter;

    adapter = REALLOC2(0, 1, sizeof(adapter[0]));
    memset(&adapter[0], 0, sizeof(adapter[0]));

    adapter->alloc_packet = alloc_packet;
    adapter->xmit_packet = xmit_packet;
    adapter->userdata = userdata;

    return adapter;
}

void
adapter_destroy(struct Adapter *adapter)
{
    free(adapter);
}
