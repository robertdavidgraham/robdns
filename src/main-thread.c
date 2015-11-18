#include "main-thread.h"
#include "rawsock.h"
#include "network.h"
#include "thread.h"
#include "adapter.h"
#include "util-realloc2.h"
#include <stdlib.h>

#define PACKET_SIZE 1514


/******************************************************************************
 ******************************************************************************/
static struct Packet
alloc_packet(struct Adapter *adapter, struct Thread *thread)
{
    struct Packet pkt;
    pkt.buf = thread->userdata;
    pkt.offset = 0;
    pkt.max = PACKET_SIZE;
    pkt.fixup.network = 0;
    pkt.fixup.transport = 0;

    return pkt;
}



/******************************************************************************
 ******************************************************************************/
void main_thread(void *v)
{
    struct ThreadParms *parms = (struct ThreadParms *)v;
    struct Adapter *adapter = parms->adapter;
    struct Frame frame[1];
    struct Thread thread[1];

    memset(frame, 0, sizeof(frame[0]));
    
    /*
     * thread
     */
    memset(thread, 0, sizeof(thread[0]));
    thread->catalog_run = parms->catalog_run;
    thread->userdata = (char*)MALLOC2(PACKET_SIZE);

    adapter->alloc_packet = alloc_packet;
    adapter->xmit_packet = rawsock_send_packet;
    

    for (;;) {
        int err;
        unsigned length;
        unsigned secs;
        unsigned usecs;
        const unsigned char *px;

        err = rawsock_recv_packet(
                    adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);

        if (err != 0)
            continue;

        network_receive(
            frame,
            thread,
            adapter,
            secs,
            usecs,
			px,
            length);
    }
}

