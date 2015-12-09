#include "configuration.h"
#include "main-conf.h"

#include "adapter.h"
#include "adapter-pcapfile.h"
#include "adapter-pcaplive.h"
#include "db.h"
#include "domainname.h"
#include "conf-trackfile.h"
#include "conf-zone.h"
#include "logger.h"
#include "main-server-socket.h"
#include "main-thread.h"
#include "pixie.h"
#include "pixie-nic.h"
#include "pixie-threads.h"
#include "pixie-timer.h"
#include "pixie-sockets.h"
#include "rawsock-pfring.h"
#include "string_s.h"
#include "success-failure.h"
#include "unusedparm.h"
#include "util-ipaddr.h"        /* format IPv6 address */
#include "util-realloc2.h"
#include "zonefile-load.h"
#include "zonefile-parse.h"
#include "zonefile-tracker.h"
#include <ctype.h>

#ifdef WIN32
#define strdup _strdup
#endif

extern uint64_t entry_bytes;
extern uint64_t entry_count;
extern uint64_t total_chain_length;
static const struct DomainPointer root = {(const unsigned char*)"\0",1};
#define SENDQ_SIZE 65536 * 8


/******************************************************************************
 * Whether a network interface/adapter name is actually a numeric index, in
 * which case we need to look it up in a list of adapters to find the real
 * one. This is used on WinXP which doesn't have friendly names for adapters
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
                    const struct RawFlags *flags)
{
    struct Adapter *adapter;
    char errbuf[PCAP_ERRBUF_SIZE];

    errbuf[0] = '\0';
    adapter = REALLOC2(NULL, sizeof(*adapter), 1);
    memset(adapter, 0, sizeof(*adapter));
    
    if (flags->is_offline)
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
    if (flags->is_pfring || is_pfring_dna(adapter_name)) {
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
        LOG_INFO(C_NETWORK, "pfring:'%s': opening...\n", adapter_name);
        adapter->ring = PFRING.open(adapter_name, 1500, 0);//PF_RING_REENTRANT);
        adapter->pcap = (struct pcap_t*)adapter->ring;
        if (adapter->ring == NULL) {
            LOG_ERR(C_NETWORK, "pfring:'%s': OPEN ERROR: %s\n", 
                adapter_name, strerror_x(errno));
            return 0;
        } else
            LOG_INFO(C_NETWORK, "pfring:'%s': successfully opened\n", adapter_name);

        /*
         * Housekeeping
         */
        PFRING.set_application_name(adapter->ring, "masscan");
        PFRING.version(adapter->ring, &version);
        LOG_INFO(C_NETWORK, "pfring: version %d.%d.%d\n",
                (version >> 16) & 0xFFFF,
                (version >> 8) & 0xFF,
                (version >> 0) & 0xFF);

        LOG_INFO(C_NETWORK, "pfring:'%s': setting direction\n", adapter_name);
        err = PFRING.set_direction(adapter->ring, rx_only_direction);
        if (err) {
            LOG_ERR(C_NETWORK, "pfring:'%s': setdirection = %d\n", 
                    adapter_name, err);
        } else
            LOG_INFO(C_NETWORK, "pfring:'%s': direction success\n", adapter_name);

        /*
         * Activate
         *
         * PF_RING requires a separate activation step.
         */
        LOG_INFO(C_NETWORK, "pfring:'%s': activating\n", adapter_name);
        err = PFRING.enable_ring(adapter->ring);
        if (err != 0) {
                LOG_ERR(C_NETWORK, "pfring: '%s': ENABLE ERROR: %s\n", 
                    adapter_name, strerror_x(errno));
                PFRING.close(adapter->ring);
                adapter->ring = 0;
                return 0;
        } else
            LOG_INFO(C_NETWORK, "pfring:'%s': succesfully eenabled\n", adapter_name);

        return adapter;
    }

    /*----------------------------------------------------------------
     * PORTABILITY: LIBPCAP
     *
     * This is the stanard that should work everywhere.
     *----------------------------------------------------------------*/
    {
        LOG_INFO(C_NETWORK, "pcap: %s\n", pcap.lib_version());
        LOG_INFO(C_NETWORK, "pcap:'%s': opening...\n", adapter_name);
        adapter->pcap = pcap.open_live(
                    adapter_name,           /* interface name */
                    65536,                  /* max packet size */
                    8,                      /* promiscuous mode */
                    1000,                   /* read timeout in milliseconds */
                    errbuf);
        if (adapter->pcap == NULL) {
            LOG_ERR(C_NETWORK, "FAIL: %s\n", errbuf);
            if (strstr(errbuf, "perm")) {
                LOG_ERR(C_NETWORK, " [hint] need to sudo or run as root or something\n");
                LOG_ERR(C_NETWORK, " [hint] I've got some local priv escalation "
                        "0days that might work\n");
            }
            return 0;
        } else
            LOG_INFO(C_NETWORK, "pcap:'%s': successfully opened\n", adapter_name);
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
    if (flags->is_sendq)
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
struct Adapter *
initialize_adapter(
    //struct Core *conf,
    const char *in_ifname,
    //unsigned index,
    unsigned *r_adapter_ip,
    unsigned char *adapter_mac,
    const struct RawFlags *flags
    )
{
    char *ifname;
    char ifname2[256];
    struct Adapter *raw_adapter;

    LOG_ERR(C_NETWORK, "initializing adapter\n");

    /*
     * ADAPTER/NETWORK-INTERFACE
     *
     * If no network interface was configured, we need to go hunt down
     * the best Interface to use. We do this by choosing the first
     * interface with a "default route" (aka. "gateway") defined
     */
    if (in_ifname && in_ifname[0])
        ifname = strdup(in_ifname);
    else {
        /* no adapter specified, so find a default one */
        int err;
		ifname2[0] = '\0';
        err = pixie_nic_get_default(ifname2, sizeof(ifname2));
        if (err || ifname2[0] == '\0') {
            fprintf(stderr, "FAIL: could not determine default interface\n");
            fprintf(stderr, "FAIL:... try \"--interface ethX\"\n");
            return 0;
        } else {
            LOG_INFO(C_NETWORK, "auto-detected: interface=%s\n", ifname2);
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
    if (*r_adapter_ip == 0) {
        *r_adapter_ip = pixie_nic_get_ipv4(ifname);
        LOG_INFO(C_NETWORK, "auto-detected: adapter-ip=%u.%u.%u.%u\n",
            (*r_adapter_ip>>24)&0xFF,
            (*r_adapter_ip>>16)&0xFF,
            (*r_adapter_ip>> 8)&0xFF,
            (*r_adapter_ip>> 0)&0xFF
            );
    }
    if (*r_adapter_ip == 0) {
        LOG_ERR(C_NETWORK, "FAIL: failed to detect IP of interface \"%s\"\n", ifname);
        LOG_ERR(C_NETWORK, " [hint] did you spell the name correctly?\n");
        LOG_ERR(C_NETWORK, " [hint] if it has no IP address, manually set with \"--adapter-ip 192.168.100.5\"\n");
        return 0;
    }

    /*
     * MAC ADDRESS
     *
     * This is the address we send packets from. It actually doesn't really
     * matter what this address is, but to be a "responsible" citizen we
     * try to use the hardware address in the network card.
     */
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        pixie_nic_get_mac(ifname, adapter_mac);
        LOG_INFO(C_NETWORK, "auto-detected: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
            adapter_mac[0],
            adapter_mac[1],
            adapter_mac[2],
            adapter_mac[3],
            adapter_mac[4],
            adapter_mac[5]
            );
    }
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        LOG_ERR(C_NETWORK, "FAIL: failed to detect MAC address of interface: \"%s\"\n", ifname);
        LOG_ERR(C_NETWORK, " [hint] try something like \"--adapter-mac 00-11-22-33-44-55\"\n");
        return 0;
    }

    /*
     * START ADAPTER
     *
     * Once we've figured out which adapter to use, we now need to
     * turn it on.
     */
    raw_adapter = rawsock_init_adapter(ifname, flags);
    if (raw_adapter == 0) {
        fprintf(stderr, "adapter[%s].init: failed\n", ifname);
        return 0;
    }
    LOG_INFO(C_NETWORK, "rawsock: ignoring transmits\n");
    rawsock_ignore_transmits(raw_adapter, adapter_mac);
    LOG_INFO(C_NETWORK, "rawsock: initialization done\n");


    {
        struct Adapter *a = raw_adapter;

        a->ipv4[a->ipv4_count].address = *r_adapter_ip;
        a->ipv4[a->ipv4_count].mask = 0xFFFFFFFF;
        a->ipv4_count++;

        memcpy(a->mac->address, adapter_mac, 6);
        a->frame_size = 1514;
        
    }

    LOG_INFO(C_NETWORK, "adapter initialization done.\n");
    return raw_adapter;
}




/******************************************************************************
 ******************************************************************************/
void
pcap_thread(struct Core *conf)
{
#if 0
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

        

        parms->catalog_run = conf->db_run;
        pixie_begin_thread(main_thread, 0, parms);
    }

    for (;;) {
        pixie_sleep(1000);
    }
#endif
    return;
}

/****************************************************************************
 ****************************************************************************/
void change_logging(struct Core *core, struct Configuration *cfg_new, struct Configuration *cfg_old)
{
}


/****************************************************************************
 ****************************************************************************/
struct CoreSocketItem *
core_adapter_lookup(const struct CoreSocketSet *set, int type, void *addr, unsigned proto, unsigned port, const char *ifname)
{
    unsigned i;

    if (set == NULL)
        return 0;

    for (i=0; i<set->count; i++) {
        struct CoreSocketItem *item = &set->list[i];

        /* compare type */
        if (item->type != type)
            continue;

        if (item->proto != proto)
            continue;

        /* compare port */
        if (item->port != port)
            continue;

        /* compare address */
        switch (item->type) {
        case ST_IPv4:
            if (item->ip.v4 != *(unsigned*)addr)
                continue;
            break;
        case ST_IPv6:
            if (memcmp(item->ip.v6, addr, 16) != 0)
                continue;
            break;
        case ST_Raw:
            if (strcmp(item->ifname, ifname) != 0)
                continue;
            break;
        default:
            continue;
        }

        /* everything equal, so return */
        return item;
    }

    return 0;
}

/****************************************************************************
 ****************************************************************************/
struct CoreSocketItem *
core_adapter_add(struct CoreSocketSet *set, int type, 
        void *addr, 
        unsigned proto, 
        unsigned port, 
        const char *ifname)
{
    struct CoreSocketItem *item;

    set->count++;
    set->list = REALLOC2(set->list, sizeof(set->list[0]), set->count);

    item = &set->list[set->count - 1];
    memset(item, 0, sizeof(*item));

    item->type = type;
    item->proto = proto;
    item->port = port;
    item->fd = 0;

    if (ifname) {
        item->ifname = REALLOC2(0, strlen(ifname)+1, 1);
        memcpy(item->ifname, ifname, strlen(ifname)+1);
    }
    
    switch (item->type) {
    case ST_IPv4:
        item->ip.v4 = *(unsigned*)addr;
        break;
    case ST_IPv6:
        memcpy(item->ip.v6, addr, 16);
        break;
    default:
        memset(item->ip.v6, 0, 16);
        break;
    }

    return item;
}

int
sockitem_open(struct CoreSocketItem *adapt)
{
    int fd;
    int err;

    /*
     * Create a socket descriptor
     */
    switch (adapt->type) {
    case ST_Any:
    case ST_IPv6:
        /* By specifying IPv6, we allow both IPv4 and IPv6 on the same socket */
        fd = socket(AF_INET6, SOCK_DGRAM, 0);
        break;
    case ST_IPv4:
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        break;
    default:
        LOG_ERR(C_NETWORK, "impossible\n");
        return -1;
    }
    if (fd <= 0) {
        LOG_ERR(C_NETWORK, "couldn't create socket() %u\n", WSAGetLastError());
        return -1;
    }

    
    /*
     * Set 'reuse', otherwise we'd need to wait before restarting process 
     */
    {
        int on = 1;
        err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on,sizeof(on));
        if (err < 0)
            LOG_ERR(C_NETWORK, "fail: setsockopt(SO_REUSEADDR) %u\n", WSAGetLastError());
    }

    if (adapt->type == ST_Any) {
        /*
         * Enable both IPv4 and IPv6 to be used on the same sockets. This appears to
         * be needed for Windows, but not needed for Mac OS X.
         */
#ifdef IPV6_V6ONLY
        int on = 0;
        err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof(on));
        if (err < 0)
            LOG_ERR(C_NETWORK, "fail: setsockopt(IPV6_V6ONLY) %u\n", WSAGetLastError());
#endif
    }
    
    switch (adapt->type) {
    case ST_Any:
        /*
         * Listen on any IPv4 or IPv6 address in the system
         */
        {
            struct sockaddr_in6 sin;

            memset(&sin, 0, sizeof(sin));
            sin.sin6_family = AF_INET6;
            sin.sin6_addr = in6addr_any;
            sin.sin6_port = htons(adapt->port);
            err = bind(fd, (struct sockaddr*)&sin, sizeof(sin));
        }
        break;
    case ST_IPv6:
        /*
         * Listen on any IPv4 or IPv6 address in the system
         */
        {
            struct sockaddr_in6 sin;

            memset(&sin, 0, sizeof(sin));
            sin.sin6_family = AF_INET6;
            memcpy(&sin.sin6_addr, adapt->ip.v6, 16);
            sin.sin6_port = htons(adapt->port);
            err = bind(fd, (struct sockaddr*)&sin, sizeof(sin));
        }
        break;
    case ST_IPv4:
        {
            struct sockaddr_in sin;

            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = htonl(adapt->ip.v4);
            sin.sin_port = htons(adapt->port);
            err = bind(fd, (struct sockaddr*)&sin, sizeof(sin));
        }
        break;
    default:
        closesocket(fd);
        return -1;
    }

    if (err) {
        switch (WSAGetLastError()) {
            case WSA(EACCES):
                LOG_ERR(C_NETWORK, "FAIL: couldn't bind to port %u: %s\n", adapt->port, 
                    "access denied");
                if (adapt->port <= 1024)
                    LOG_ERR(C_NETWORK, "  hint... need to be root for ports below 1024\n");
                break;
            case WSA(EADDRINUSE):
                LOG_ERR(C_NETWORK, "FAIL: couldn't bind to port %u: %s\n", adapt->port, 
                    "address in use");
                LOG_ERR(C_NETWORK, "  hint... some other server is running on that port\n");
                break;
            default:
                LOG_ERR(C_NETWORK, "FAIL: couldn't bind to port %u: %u\n", adapt->port,
                    WSAGetLastError());
        }
        closesocket(fd);
        return -1;
    }


    /*
     * Now log a success message
     */
    switch (adapt->type) {
    case ST_Any:
        LOG_INFO(C_NETWORK, "Listening on any udp/%u\n", adapt->port);
        break;
    case ST_IPv4:
        LOG_INFO(C_NETWORK, "Listening on %u.%u.%u.%u udp/%u\n", 
            (adapt->ip.v4>>24)&0xFF, (adapt->ip.v4>>15)&0xFF, 
            (adapt->ip.v4>> 8)&0xFF, (adapt->ip.v4>> 0)&0xFF, 
            adapt->port);
        break;
    case ST_IPv6:
        {
            char text[64];
            
            format_ipv6_address(text, sizeof(text), adapt->ip.v6);

            LOG_INFO(C_NETWORK, "Listening on [%s] udp/%u\n",
                text,
                adapt->port);
        }
        break;
    default:
        LOG_ERR(C_NETWORK, "impossible\n");
        break;
    }

    /*
     * Set the file descriptor
     */
    adapt->fd = fd;
    return fd;
}



/****************************************************************************
 ****************************************************************************/
void change_network_adapters(struct Core *core, struct Configuration *cfg_load, struct Configuration *cfg_run)
{
    struct CoreSocketSet *socket_load;
    struct CoreSocketSet *socket_old;
    struct ConfigurationDataPlane *list;
    unsigned i;


    /*
     * Create a new sockets structure. We will first fill it with all the
     * adapters we are using, then swap it in for the resolver threads
     * to use.
     */
    socket_load = REALLOC2(NULL, sizeof(*socket_load), 1);
    memset(socket_load, 0, sizeof(*socket_load));

    /*
     * If no adapter exists, then create an "any" adapter by default
     */
    list = &cfg_load->data_plane;
    if (list == NULL || list->adapter_count == 0) {
        cfg_load_string(cfg_load, "options { listen-on { any; }; };");
        list = &cfg_load->data_plane;
    }

    /*
     * Cleanup/defaults
     */
    for (i=0; i<cfg_load->data_plane.adapter_count; i++) {
        struct CoreSocketItem *adapt = &cfg_load->data_plane.adapters[i];
        if (adapt->port >= 65536)
            adapt->port = cfg_load->data_plane.port;
    }

    /*
     * Add all the adapters to our 'load' list
     */
    for (i=0; i<list->adapter_count; i++) {
        struct CoreSocketItem *adapt_c = &list->adapters[i];
        struct CoreSocketItem *adapt_l;

        /* ignore duplicates */
        adapt_l = core_adapter_lookup(socket_load, 
                                        adapt_c->type, 
                                        &adapt_c->ip,
                                        adapt_c->proto,
                                        adapt_c->port,
                                        adapt_c->ifname);
        if (adapt_l)
            continue;

        /* add a new adapter */
        adapt_l = core_adapter_add(socket_load,
                            adapt_c->type,
                            &adapt_c->ip,
                            adapt_c->proto,
                            adapt_c->port,
                            adapt_c->ifname);

    }

    /*
     * Now open all the sockets -- if they aren't already open
     */
    for (i=0; i<socket_load->count; i++) {
        struct CoreSocketItem *adapt_l = &socket_load->list[i];
        struct CoreSocketItem *adapt_r;

        /* see if the  needs to be open */
        adapt_r = core_adapter_lookup((struct CoreSocketSet *)core->socket_run, 
                                        adapt_l->type, 
                                        &adapt_l->ip, 
                                        adapt_l->proto,
                                        adapt_l->port,
                                        adapt_l->ifname);
    
        /* If the socket is already open, then simply
         * copy the value here */
        if (adapt_r && adapt_r->fd) {
            adapt_l->fd = adapt_r->fd;
            continue;
        }
        
        /*
         * Now open the socket
         */
        sockitem_open(adapt_l);
        
    }


    /* [SYNCHRONIZATION POINT]
     * Set the new socket set. The resolver worker-threads should immediately
     * start using these new sockets
     */
    socket_old = (struct CoreSocketSet *)core->socket_run;
    core->socket_run = socket_load;
    for (i=0; i<core->workers_count; i++) {
        size_t loop_count;

        loop_count = core->workers[i]->loop_count;
        while (loop_count == core->workers[i]->loop_count)
            pixie_sleep(1);
    }

    /*
     * Cleanup the old sockets
     */
    if (socket_old)
    for (i=0; i<socket_old->count; i++) {
        struct CoreSocketItem *adapt_old = &socket_old->list[i];
        struct CoreSocketItem *adapt_run;

        /* ignore duplicates */
        adapt_run = core_adapter_lookup(socket_load, 
                                        adapt_old->type, 
                                        &adapt_old->ip,
                                        adapt_old->proto,
                                        adapt_old->port,
                                        adapt_old->ifname);
        
        /* If the OLD adapter isn't in the RUN set, then close it's
         * socket file-descriptior, because it's not used anywmore */
        if (adapt_run == NULL) {
            if (adapt_old->fd > 0)
                closesocket(adapt_old->fd);
        }

        if (adapt_old->ifname)
            free(adapt_old->ifname);

        memset(adapt_old, 0xa3, sizeof(*adapt_old));
    }
    free(socket_old);

}


/****************************************************************************
 ****************************************************************************/
int change_zones(struct Core *core, struct Configuration *cfg_load, const struct Configuration *cfg_run)
{
    unsigned i;
    int is_changed = 0;

    for (i=0; i<cfg_load->zones_length; i++) {
        struct Cfg_Zone *zone = cfg_load->zones[i];
        const struct Cfg_Zone *zone_run;

        zone_run = conf_zone_lookup(cfg_run, zone->name);

        /* If zone doesn't exist in the old configuration, we'll have
         * to create it */
        if (zone_run == NULL) {
            zone->action = CFGZ_Create;
            is_changed = 1;
            continue;
        }

        /* If the filename has changed, we'll have to update it */
        if (strcmp(zone_run->file, zone->file) != 0) {
            zone->action = CFGZ_Update;
            is_changed = 1;
        }
    }

    for (i=0; i<cfg_run->zones_length; i++) {
        struct Cfg_Zone *zone_run = cfg_run->zones[i];
        const struct Cfg_Zone *zone_load;

        zone_load = conf_zone_lookup(cfg_load, zone_run->name);

        /* If the old zone is not in the new configuration, then we need
         * to delete it. This requires creating a new record with
         * an action set to "delete" */
        if (zone_load == NULL) {
            struct Cfg_Zone *zone = conf_zone_create(zone_run->name, strlen(zone_run->name));
            zone->action = CFGZ_Delete;
            conf_zone_append(cfg_load, zone);
            is_changed = 1;
        }
    }

    return is_changed;
}

/****************************************************************************
 * Checks the timestamps on all the files in order to see if a zone
 * has changed.
 ****************************************************************************/
int
zones_have_changed(const struct Catalog *db, const struct Configuration *cfg)
{

    return 0;
}

/****************************************************************************
 ****************************************************************************/
int server(int argc, char *argv[])
{
    struct Configuration *cfg_run = cfg_create();
    struct Core core[1];
    uint64_t start, stop;
    uint64_t total_files=0, total_bytes=0;

    /*
     * Legacy Windows is legacy.
     */
#if defined(WIN32)
    {WSADATA x; if (WSAStartup(0x201, &x)) exit(1);}
#endif

    /*
     * We want to track how long it takes to fully initialize the
     * server, since because DNS is infrastructure, restarting
     * quickly after a failure is important, so we want to benchmark
     * how fast those startups happen
     */
    start = pixie_gettime();

    /*
     * Initialie the core structure structure. We don't have globals,
     * so instead anything 'global' will either hang off this
     * 'core' variable.
     */
    core_init(core);

    /*
     * Now sit in a loop waiting for configuration/zonefile changes to
     * happen
     */
    for (;;) {
        int is_zones_changed = 0;

        /*
         * If none of the configuration files have changed, then skip any
         * reconfiguration events. If configuration has changed, then we'll need
         * to apply each change one-by-one. Note that we track if configuration
         * changes purely by whether the timestamps have changed.
         */
        if (conf_trackfile_has_changed(cfg_run->tf)) {
            struct Configuration *cfg_load;

            /*
             * Create a temporary configuration structure for reading in new/changed
             * configuration information. Changes will be then be moved over (in
             * a thread-safe manner) into the running configuration instance (cfg_run).
             * (Similar how db_load/db_run works)
             */
            cfg_load = cfg_create();

            /*
             * Re-read the command-line. This in turn will cause the system to read
             * the master 'named.conf' file, plus additional  files through 'include'.
             * All configuration is loaded into the "cfg_load" instance, but not
             * the zonefiles/databases (which happens at a later step below).
             */
            conf_command_line(cfg_load, argc, argv);

            /* 
             * We apply logging changes first. That's because everything else after
             * this point can cause errors/warnings that need to be logged correctly.
             * Note: At startup, logging both defautls to <stderr>, but in ADDITION
             * the first megabyte of output text is buffered, and printed to the
             * new logging channels.
             */
            change_logging(core, cfg_load, cfg_run);
            /* todo: output buffered logging here */

            /*
             * Change the number of resolver threads. By default, at startup this
             * will create resolver threads for each CPU on the system. The code
             * is thread-scalable, so likes lots of threads on massive numbers of
             * CPUs.
             */
            change_resolver_threads(core, cfg_load);

            /*
             * Change the network adapter configuration. It's at this stage that
             * we'll open/close sockets.
             */
            change_network_adapters(core, cfg_load, cfg_run);

            /*
             * Detect if zone information has changed
             */
            is_zones_changed = change_zones(core, cfg_load, cfg_run);

            /*
             * Now change swap the two configurations. Note that there is
             * synchronization step, as the running system doesn't consult
             * the configuration object while running, but imports
             * new configuration information in the "change_xxx()" functions
             * right above this.
             */
            {
                struct Configuration *cfg_old;

                cfg_old = cfg_run;
                cfg_run = cfg_load;

                cfg_destroy(cfg_old);
            }
        }

        if (is_zones_changed || zones_have_changed(core->db_run, cfg_run)) {

            /*
             * If we have lots of zones, then adjust the size of the hash table
             * to make lookups efficient.
             */
            if (cfg_run->zones_length + cfg_run->zonedirs_filecount > 200) {
                catalog_reset_zonecount(core->db_load, (unsigned)(cfg_run->zones_length + cfg_run->zonedirs_filecount) * 2);
            }

            /*
             * Load the zonefiles
             */
            conf_zonefiles_parse(core->db_load, cfg_run, &total_files, &total_bytes);

            /*
             * If we don't have a zone-file, then error out
             */
            if (catalog_zone_count(core->db_load) == 0) {
                LOG_INFO(C_CONFIG, "FAIL: no zones specified\n");
                exit(1);
            }

            /*
             * Benchmark
             */
            stop = pixie_gettime();
            {
                double elapsed = (stop - start) * 1.0;
                double rate = (1.0*(total_bytes))/elapsed;

                printf("elapsed: %u.%02u seconds\n",
                    (unsigned)(((stop-start)/(1000000))),
                    (unsigned)(((stop-start)/(10000))%100)
                    );
                printf("zone size: %" PRIu64 " bytes\n", total_bytes);
                printf("zone files: %" PRIu64 " files\n", total_files);
                printf("speed: %5.3f-megabytes/second parsing zonefile\n", rate);
            }


        }

        for (;;) {
            pixie_sleep(100);
        }
    }

    return 0;
}

/****************************************************************************
 ****************************************************************************/
int foreground(int argc, char *argv[])
{
    return server(argc, argv);
}
