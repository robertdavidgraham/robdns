#include "main-conf.h"
#include "conf-trackfile.h"
#include "configuration.h"
#include "db.h"
#include "domainname.h"
#include "zonefile-parse.h"
#include "zonefile-load.h"
#include "zonefile-tracker.h"
#include "success-failure.h"
#include "util-ipaddr.h"
#include "pixie-nic.h"
#include "pixie.h"
#include "pixie-timer.h"
#include "pixie-threads.h"
#include "string_s.h"
#include "logger.h"
#include "adapter-pcaplive.h"
#include "adapter.h"
#include "rawsock-pfring.h"
#include "main-thread.h"
#include "unusedparm.h"
#include "adapter-pcapfile.h"
#include "main-server-socket.h"
#include <ctype.h>

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

    adapter = (struct Adapter *)malloc(sizeof(*adapter));
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
static struct Adapter *
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
        ifname = _strdup(in_ifname);
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
static void
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
int server(int argc, char *argv[])
{
    struct Configuration *cfg_new;
    struct Configuration *cfg_old = cfg_create();
    struct Core core[1];
    uint64_t start, stop;
    uint64_t total_files=0, total_bytes=0;

    start = pixie_gettime();

    /*
     * Initialie the core structure structure
     */
    core_init(core);

    /*
     * Create an empty database
     */
    core->db_load = catalog_create();
    core->db_run = catalog_create();


    /*
     * Create a new configuration instance
     */
    cfg_new = cfg_create();

    /*
     * Read the command-line 
     */
    conf_command_line(cfg_new, argc, argv);

    /*
     * Test to see if the configuration has changed
     */
    if (conf_trackfile_has_changed(cfg_new->tf, cfg_old->tf)) {
        unsigned count = conf_trackfile_count(cfg_new->tf);
        unsigned i;

        /* Read in the new configuration */
        for (i=0; i<count; i++) {
            const char *filename = conf_trackfile_filename(cfg_new->tf, i);
            cfg_parse_file(cfg_new, filename);
        }

        /* Apply the changes */
        change_logging(core, cfg_new, cfg_old);
        change_worker_threads(core, cfg_new, cfg_old);

    }








    /*
     * If we have lots of zones, then adjust the size of the hash table
     * to make lookups efficient.
     */
    if (cfg->zones_length + cfg->zonedirs_filecount > 200) {
        catalog_reset_zonecount(core->db_load, (unsigned)(cfg->zones_length + cfg->zonedirs_filecount) * 2);
    }

    /*
     * Load the zonefiles
     */
    conf_zonefiles_parse(core->db_load, cfg, &total_files, &total_bytes);

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
        printf("zone size: %llu bytes\n", total_bytes);
        printf("zone files: %llu files\n", total_files);
        printf("speed: %5.3f-megabytes/second parsing zonefile\n", rate);
    }


    /*
     * Now start the network interface
     */
    sockets_thread(core);


    return 0;
}

/****************************************************************************
 ****************************************************************************/
int foreground(int argc, char *argv[])
{
    return server(argc, argv);
}
