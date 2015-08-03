#include "rawsock.h"
#include "adapter.h"
#include "rawsock-pfring.h"
#include "adapter-pcaplive.h"
#include "logger.h"

#define SENDQ_SIZE (65536 * 8)


/***************************************************************************
 * wrapper for libpcap's sendpacket
 *
 * PORTABILITY: WINDOWS and PF_RING
 * For performance, Windows and PF_RING can queue up multiple packets, then
 * transmit them all in a chunk. If we stop and wait for a bit, we need
 * to flush the queue to force packets to be transmitted immediately.
 ***************************************************************************/
void
rawsock_send_packet(struct Adapter *adapter, 
                        struct Thread *thread, 
                        struct Packet *pkt)
{
    const unsigned char *packet = pkt->buf;
    unsigned length = pkt->offset;
    unsigned flush = 1;

    if (adapter == 0)
        return;
    

    /* PF_RING */
    if (adapter->ring) {
        int err = PF_RING_ERROR_NO_TX_SLOT_AVAILABLE;

        while (err == PF_RING_ERROR_NO_TX_SLOT_AVAILABLE) {
            err = PFRING.send(adapter->ring, packet, length, (unsigned char)flush);
        }
        if (err < 0)
            LOG_ERR(C_NETWORK, "pfring:xmit: ERROR %d\n", err);
        return;
    }

    /* WINDOWS PCAP */
    if (adapter->sendq) {
        int err;
        struct pcap_pkthdr hdr;
        hdr.len = length;
        hdr.caplen = length;

        err = pcap.sendqueue_queue(adapter->sendq, &hdr, packet);
        if (err) {
            //printf("sendpacket() failed %d\n", x);
            //for (;;)
            pcap.sendqueue_transmit(adapter->pcap, adapter->sendq, 0);
            //printf("pcap_send_queue)() returned %u\n", x);
            pcap.sendqueue_destroy(adapter->sendq);
            adapter->sendq =  pcap.sendqueue_alloc(SENDQ_SIZE);
            pcap.sendqueue_queue(adapter->sendq, &hdr, packet);
            //("sendpacket() returned %d\n", x);
            //exit(1);
        } else
            ; //printf("+%u\n", count++);
        if (flush) {
            pcap.sendqueue_transmit(adapter->pcap, adapter->sendq, 0);

            /* Dude, I totally forget why this step is necessary. I vaguely
             * remember there's a good reason for it though */
            pcap.sendqueue_destroy(adapter->sendq);
            adapter->sendq =  pcap.sendqueue_alloc(SENDQ_SIZE);
        }
        return;
    }

    /* LIBPCAP */
    if (adapter->pcap)
        pcap.sendpacket(adapter->pcap, packet, length);

    return;
}

/***************************************************************************
 ***************************************************************************/
int rawsock_recv_packet(
    struct Adapter *adapter,
    unsigned *length,
    unsigned *secs,
    unsigned *usecs,
    const unsigned char **packet)
{
    if (adapter->ring) {
        struct pfring_pkthdr hdr;
        int err;

        again:
        err = PFRING.recv(adapter->ring,
                        (unsigned char**)packet,
                        0,  /* zero-copy */
                        &hdr,
                        0   /* return immediately */
                        );
        if (err == PF_RING_ERROR_NO_PKT_AVAILABLE || hdr.caplen == 0) {
            PFRING.poll(adapter->ring, 1);
            goto again;
        }
        if (err)
            return 1;

        *length = hdr.caplen;
        *secs = hdr.ts.tv_sec;
        *usecs = hdr.ts.tv_usec;

    } else if (adapter->pcap) {
        struct pcap_pkthdr hdr;


        *packet = pcap.next(adapter->pcap, &hdr);

        if (*packet == NULL)
            return 1;

        *length = hdr.caplen;
        *secs = hdr.ts.tv_sec;
        *usecs = hdr.ts.tv_usec;
    }
    

    return 0;
}


/***************************************************************************
 ***************************************************************************/
void
rawsock_init()
{
    /* Once-per-process: initialize 'libpcap' */
    pcaplive_init();

#if defined(__linux)
    PFRING_init();
#endif
    return;
}
