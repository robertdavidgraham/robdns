#include "main-conf.h"
#include "db.h"
#include "domainname.h"
#include "zonefile-parse.h"
#include "zonefile-load.h"
#include "zonefile-tracker.h"
#include "success-failure.h"
#include "util-ipaddr.h"
#include "pixie-nic.h"
#include "pixie.h"
#include "string_s.h"
#include "logger.h"
#include "adapter-pcaplive.h"
#include "adapter.h"
#include "rawsock-pfring.h"
#include "main-thread.h"
#include "unusedparm.h"
#include "adapter-pcapfile.h"
#include <ctype.h>

#if defined(WIN32)
#include <WinSock2.h>
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif
typedef int socklen_t;
#else
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#define WSAGetLastError() (errno)
#define SOCKET int
#endif

extern uint64_t entry_bytes;
extern uint64_t entry_count;
extern uint64_t total_chain_length;
static const struct DomainPointer root = {(const unsigned char*)"\0",1};
#define SENDQ_SIZE 65536 * 8


/******************************************************************************
 * This is the mail loop when running over sockets, receiving packets and
 * sending responses.
 ******************************************************************************/
static void
sockets_thread(struct Core *conf)
{
    int err;
    SOCKET fd;
    struct sockaddr_in sin;

    /*
     * This software obtains its speed by bypassing the operating system
     * stack. Thus, running on top of 'sockets' is going to be a lot 
     * slower
     */
    fprintf(stderr, "WARNING: running in slow 'sockets' mode\n");
    
    
    /*
     * Legacy Windows is legacy.
     */
#if defined(WIN32)
    {WSADATA x; WSAStartup(0x201, &x);}
#endif

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd <= 0) {
        LOG(0, "FAIL: couldn't create socket %u\n", WSAGetLastError());
        return;
    }


    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(53);
    err = bind(fd, (struct sockaddr*)&sin, sizeof(sin));
    if (err) {
        LOG(0, "FAIL: couldn't bind to port 53: %u\n", WSAGetLastError());
        return;
    }

    /*
     * Sit in loop processing incoming UDP packets
     */
    for (;;) {
        unsigned char buf[2048];
        int bytes_received;
        socklen_t sizeof_sin = sizeof(sin);


        bytes_received = recvfrom(fd, 
                                  (char*)buf, sizeof(buf),
                                  0, 
                                  (struct sockaddr*)&sin, &sizeof_sin);
        if (bytes_received == 0)
            continue;
       

       
    }
}


/******************************************************************************
 ******************************************************************************/
static int
is_numeric_index(const char *ifname)
{
    int result = 1;
    int i;

    /* emptry strings aren't numbers */
    if (ifname[0] == '\0')
        return 0;

    /* 'true' if all digits */
    for (i=0; ifname[i]; i++) {
        char c = ifname[i];

        if (c < '0' || '9' < c)
            result = 0;
    }

    return result;
}

/******************************************************************************
 ******************************************************************************/
static char *
adapter_from_index(unsigned index)
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int x;

    x = pcap.findalldevs(&alldevs, errbuf);
    if (x != -1) {
        pcap_if_t *d;

        if (alldevs == NULL) {
            fprintf(stderr, "ERR:libpcap:"
                            "no adapters found, are you sure you are root?\n");
        }
        /* Print the list */
        for(d=alldevs; d; d=d->next)
        {
            if (index-- == 0)
                return d->name;
        }
        return 0;
    } else {
        return 0;
    }
}

/***************************************************************************
 * Does the name look like a PF_RING DNA adapter? Common names are:
 * dna0
 * dna1
 * dna0@1
 *
 ***************************************************************************/
static int
is_pfring_dna(const char *name)
{
    if (strlen(name) < 4)
        return 0;
    if (memcmp(name, "dna", 3) != 0)
        return 0;

    name +=3;

    if (!isdigit(name[0]&0xFF))
        return 0;
    while (isdigit(name[0]&0xFF))
        name++;

    if (name[0] == '\0')
        return 1;

    if (name[0] != '@')
        return 0;
    else
        name++;

    if (!isdigit(name[0]&0xFF))
        return 0;
    while (isdigit(name[0]&0xFF))
        name++;

    if (name[0] == '\0')
        return 1;
    else
        return 0;
}

/***************************************************************************
 ***************************************************************************/
struct Adapter *
rawsock_init_adapter(const char *adapter_name, 
                     unsigned is_pfring, 
                     unsigned is_sendq,
                     unsigned is_packet_trace,
                     unsigned is_offline)
{
    struct Adapter *adapter;
    char errbuf[PCAP_ERRBUF_SIZE];

    adapter = (struct Adapter *)malloc(sizeof(*adapter));
    memset(adapter, 0, sizeof(*adapter));
    
    if (is_offline)
        return adapter;

    /*----------------------------------------------------------------
     * PORTABILITY: WINDOWS
     * If is all digits index, then look in indexed list
     *----------------------------------------------------------------*/
    if (is_numeric_index(adapter_name)) {
        const char *new_adapter_name;

        new_adapter_name = adapter_from_index(atoi(adapter_name));
        if (new_adapter_name == 0) {
            fprintf(stderr, "pcap_open_live(%s) error: bad index\n", 
                    adapter_name);
            return 0;
        } else
            adapter_name = new_adapter_name;
    }

    /*----------------------------------------------------------------
     * PORTABILITY: PF_RING
     *  If we've been told to use --pfring, then attempt to open the
     *  network adapter usign the PF_RING API rather than libpcap.
     *  Since a lot of things can go wrong, we do a lot of extra
     *  logging here.
     *----------------------------------------------------------------*/
    if (is_pfring || is_pfring_dna(adapter_name)) {
        int err;
        unsigned version;

        /*
         * Open
         *
         * TODO: Do we need the PF_RING_REENTRANT flag? We only have one
         * transmit and one receive thread, so I don't think we need it.
         * Also, this reduces performance in half, from 12-mpps to
         * 6-mpps.
         * NOTE: I don't think it needs the "re-entrant" flag, because it
         * transmit and receive are separate functions?
         */
        LOG(2, "pfring:'%s': opening...\n", adapter_name);
        adapter->ring = PFRING.open(adapter_name, 1500, 0);//PF_RING_REENTRANT);
        adapter->pcap = (struct pcap_t*)adapter->ring;
        if (adapter->ring == NULL) {
            LOG(0, "pfring:'%s': OPEN ERROR: %s\n", 
                adapter_name, strerror_x(errno));
            return 0;
        } else
            LOG(1, "pfring:'%s': successfully opened\n", adapter_name);

        /*
         * Housekeeping
         */
        PFRING.set_application_name(adapter->ring, "masscan");
        PFRING.version(adapter->ring, &version);
        LOG(1, "pfring: version %d.%d.%d\n",
                (version >> 16) & 0xFFFF,
                (version >> 8) & 0xFF,
                (version >> 0) & 0xFF);

        LOG(2, "pfring:'%s': setting direction\n", adapter_name);
        err = PFRING.set_direction(adapter->ring, rx_only_direction);
        if (err) {
            fprintf(stderr, "pfring:'%s': setdirection = %d\n", 
                    adapter_name, err);
        } else
            LOG(2, "pfring:'%s': direction success\n", adapter_name);

        /*
         * Activate
         *
         * PF_RING requires a separate activation step.
         */
        LOG(2, "pfring:'%s': activating\n", adapter_name);
        err = PFRING.enable_ring(adapter->ring);
        if (err != 0) {
                LOG(0, "pfring: '%s': ENABLE ERROR: %s\n", 
                    adapter_name, strerror_x(errno));
                PFRING.close(adapter->ring);
                adapter->ring = 0;
                return 0;
        } else
            LOG(1, "pfring:'%s': succesfully eenabled\n", adapter_name);

        return adapter;
    }

    /*----------------------------------------------------------------
     * PORTABILITY: LIBPCAP
     *
     * This is the stanard that should work everywhere.
     *----------------------------------------------------------------*/
    {
        LOG(1, "pcap: %s\n", pcap.lib_version());
        LOG(2, "pcap:'%s': opening...\n", adapter_name);
        adapter->pcap = pcap.open_live(
                    adapter_name,           /* interface name */
                    65536,                  /* max packet size */
                    8,                      /* promiscuous mode */
                    1000,                   /* read timeout in milliseconds */
                    errbuf);
        if (adapter->pcap == NULL) {
            LOG(0, "FAIL: %s\n", errbuf);
            if (strstr(errbuf, "perm")) {
                LOG(0, " [hint] need to sudo or run as root or something\n");
                LOG(0, " [hint] I've got some local priv escalation "
                        "0days that might work\n");
            }
            return 0;
        } else
            LOG(1, "pcap:'%s': successfully opened\n", adapter_name);
    }

    /*----------------------------------------------------------------
     * PORTABILITY: WINDOWS
     *
     * The transmit rate on Windows is really slow, like 40-kpps.
     * The speed can be increased by using the "sendqueue" feature
     * to roughly 300-kpps.
     *----------------------------------------------------------------*/
    adapter->sendq = 0;
#if defined(WIN32)
    if (is_sendq)
        adapter->sendq = pcap.sendqueue_alloc(SENDQ_SIZE);
#endif


    return adapter;
}

/***************************************************************************
 * Configure the socket to not capture transmitted packets. This is needed
 * because we transmit packets at a rate of millions per second, which will
 * overwhelm the receive thread.
 *
 * PORTABILITY: Windows doesn't seem to support this feature, so instead
 * what we do is apply a BPF filter to ignore the transmits, so that they
 * still get filtered at a low level.
 ***************************************************************************/
void
rawsock_ignore_transmits(struct Adapter *adapter, const unsigned char *adapter_mac)
{
    if (adapter->ring) {
        /* PORTABILITY: don't do anything for PF_RING, because it's
         * actually done when we create the adapter, because we can't
         * reconfigure the adapter after it's been activated. */
        return;
    }


#if !defined(WIN32)
    /* PORTABILITY: this is what we do on all systems except windows, because
     * Windows doesn't support this feature. */
    if (adapter->pcap) {
        int err;

        err = pcap.setdirection(adapter->pcap, PCAP_D_IN);
        if (err) {
            pcap.perror(adapter->pcap, "pcap_setdirection(IN)");
        }
    }
#else
    if (adapter->pcap) {
        int err;
        char filter[256];
        struct bpf_program prog;

        sprintf_s(filter, sizeof(filter), "not ether src %02x:%02X:%02X:%02X:%02X:%02X",
            adapter_mac[0], adapter_mac[1], adapter_mac[2],
            adapter_mac[3], adapter_mac[4], adapter_mac[5]);

        err = pcap.compile(
                    adapter->pcap,
                    &prog,          /* object code, output of compile */
                    filter,         /* source code */
                    1,              /* optimize to go fast */
                    0);

        if (err) {
            pcap.perror(adapter->pcap, "pcap_compile()");
            exit(1);
        }


        err = pcap.setfilter(adapter->pcap, &prog);
        if (err < 0) {
            pcap.perror(adapter->pcap, "pcap_setfilter");
            exit(1);
        }
    }
#endif


}


/******************************************************************************
 ******************************************************************************/
static int
initialize_adapter(
    struct Core *conf,
    unsigned index,
    unsigned *r_adapter_ip,
    unsigned char *adapter_mac
    )
{
    char *ifname;
    char ifname2[256];

    LOG(1, "initializing adapter\n");

    /*
     * ADAPTER/NETWORK-INTERFACE
     *
     * If no network interface was configured, we need to go hunt down
     * the best Interface to use. We do this by choosing the first
     * interface with a "default route" (aka. "gateway") defined
     */
    if (conf->nic[index].ifname && conf->nic[index].ifname[0])
        ifname = conf->nic[index].ifname;
    else {
        /* no adapter specified, so find a default one */
        int err;
		ifname2[0] = '\0';
        err = pixie_nic_get_default(ifname2, sizeof(ifname2));
        if (err || ifname2[0] == '\0') {
            fprintf(stderr, "FAIL: could not determine default interface\n");
            fprintf(stderr, "FAIL:... try \"--interface ethX\"\n");
            return -1;
        } else {
            LOG(2, "auto-detected: interface=%s\n", ifname2);
        }
        ifname = ifname2;

    }

    /*
     * IP ADDRESS
     *
     * We need to figure out that IP address to send packets from. This
     * is done by queryin the adapter (or configured by user). If the
     * adapter doesn't have one, then the user must configure one.
     */
    *r_adapter_ip = conf->nic[index].adapter_ip;
    if (*r_adapter_ip == 0) {
        *r_adapter_ip = pixie_nic_get_ipv4(ifname);
        LOG(2, "auto-detected: adapter-ip=%u.%u.%u.%u\n",
            (*r_adapter_ip>>24)&0xFF,
            (*r_adapter_ip>>16)&0xFF,
            (*r_adapter_ip>> 8)&0xFF,
            (*r_adapter_ip>> 0)&0xFF
            );
    }
    if (*r_adapter_ip == 0) {
        fprintf(stderr, "FAIL: failed to detect IP of interface \"%s\"\n", ifname);
        fprintf(stderr, " [hint] did you spell the name correctly?\n");
        fprintf(stderr, " [hint] if it has no IP address, manually set with \"--adapter-ip 192.168.100.5\"\n");
        return -1;
    }

    /*
     * MAC ADDRESS
     *
     * This is the address we send packets from. It actually doesn't really
     * matter what this address is, but to be a "responsible" citizen we
     * try to use the hardware address in the network card.
     */
    memcpy(adapter_mac, conf->nic[index].adapter_mac, 6);
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        pixie_nic_get_mac(ifname, adapter_mac);
        LOG(2, "auto-detected: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
            adapter_mac[0],
            adapter_mac[1],
            adapter_mac[2],
            adapter_mac[3],
            adapter_mac[4],
            adapter_mac[5]
            );
    }
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        fprintf(stderr, "FAIL: failed to detect MAC address of interface: \"%s\"\n", ifname);
        fprintf(stderr, " [hint] try something like \"--adapter-mac 00-11-22-33-44-55\"\n");
        return -1;
    }

    /*
     * START ADAPTER
     *
     * Once we've figured out which adapter to use, we now need to
     * turn it on.
     */
    conf->nic[index].adapter = rawsock_init_adapter(   
                                            ifname, 
                                            conf->is_pfring, 
                                            conf->is_sendq,
                                            conf->is_packet_trace,
                                            conf->is_offline);
    if (conf->nic[index].adapter == 0) {
        fprintf(stderr, "adapter[%s].init: failed\n", ifname);
        return -1;
    }
    LOG(3, "rawsock: ignoring transmits\n");
    rawsock_ignore_transmits(conf->nic[index].adapter, adapter_mac);
    LOG(3, "rawsock: initialization done\n");


    {
        struct Adapter *a = conf->nic[index].adapter;

        a->ipv4[a->ipv4_count].address = *r_adapter_ip;
        a->ipv4[a->ipv4_count].mask = 0xFFFFFFFF;
        a->ipv4_count++;

        memcpy(a->mac->address, adapter_mac, 6);
        a->frame_size = 1514;
        
    }

    LOG(1, "adapter initialization done.\n");
    return 0;
}




/******************************************************************************
 ******************************************************************************/
static void
pcap_thread(struct Core *conf)
{
    unsigned index;
    struct ThreadParms parms_array[8];


    for (index=0; index<conf->nic_count; index++) {
        struct ThreadParms *parms = &parms_array[index];
        int err;

        parms->nic_index = index;
        

        /*
         * Turn the adapter on, and get the running configuration
         */
        err = initialize_adapter(
                            conf,
                            index,
                            &parms->adapter_ip,
                            parms->adapter_mac
                            );
        if (err != 0)
            exit(1);
        parms->adapter = conf->nic[index].adapter;

        

        parms->catalog = conf->db;
        pixie_begin_thread(main_thread, 0, parms);
    }

    for (;;) {
        pixie_sleep(1000);
    }

    return;
}

/****************************************************************************
 ****************************************************************************/
int server(int argc, char *argv[])
{
    struct Core core[1];

    verbosity = 10;
    memset(core, 0, sizeof(core));
    core->nic_count = 1;

    //getcwd(core->working_directory, sizeof(core->working_directory));

    /*
     * Create an empty database
     */
    core->db = catalog_create();

    /*
     * Read the command-line 
     */
    conf_command_line(core, argc, argv);

    /*
     * If we don't have a zone-file, then error out
     */
    if (catalog_zone_count(core->db) == 0) {
        LOG(0, "FAIL: no zones specified\n");
        exit(1);
    }

    /*
     * Now start the network interface
     */
    if (core->nic_count == 0) {
        sockets_thread(core);
    } else {
        pcap_thread(core);
    }


    return 0;
}

/****************************************************************************
 ****************************************************************************/
int foreground(int argc, char *argv[])
{
    return server(argc, argv);
}
