#ifndef MAIN_CONF_H
#define MAIN_CONF_H
#include <stdint.h>
#include "adapter.h"
#include "configuration-adapter.h"

struct Configuration;

struct CoreSocketSet
{
    struct CoreSocketItem *list;
    size_t count;
};

struct RawFlags
{
    unsigned is_pfring:1;
    unsigned is_sendq:1;
    unsigned is_packet_trace:1;
    unsigned is_offline:1;
};

struct RawItem 
{
    char ifname[256];
    struct Adapter *adapter;
    unsigned adapter_ip;
    unsigned char adapter_ipv6[16];
    unsigned adapter_port;
    unsigned char adapter_mac[6];
    unsigned char router_mac[6];
};

struct RawSet
{
    struct RawItem *list;
    size_t count;
};


struct CoreWorkerThread
{
    /* [SYNCHRONIZATION POINT]
     */
    volatile size_t loop_count;

    /** Pointer back to the parent system */
    struct Core *core;

    /** A number starting at zero up to the number of threads we have in
     * the system. This is so that we can do specific things to threads,
     * such as forcing a thread with a certain index to run on a certain
     * CPU core. */
    unsigned index;

    /** This is the operating-system handle for this thread. This
     * will be used by the "join" function to wait for thread 
     * termination */
    size_t handle;

    /**
     * Set by the config-thread telling this worker-thread that it's
     * time to cleanup and exit */
    volatile unsigned should_end;
    
};

struct Core
{
    /** We are loading changes/updates to zone information in the
     * control-plane. */
    struct Catalog *db_load;

    /** Where we are serving queries from the data-plane. Changes
     * can only be replaced from the control-threads using the RCU
     * method */
    struct Catalog *db_run;


    /**
     * the set of raw-sockets that the data-plane threads are using
     */
    volatile struct RawSet *raw_run;

    /**
     * The set of Sockets that the data-plane run threads are using.
     * During a reconfiguration event, these sockets can change
     */
    volatile struct CoreSocketSet *socket_run;

    /**
     * These are the data-plane worker-threads that process queries from
     * the network. Note that there are other types of worker threads for
     * parsing zonefiles and inserting records into databases, but this 
     * is the classic 'worker' for DNS servers, so we use that name here. */
    struct CoreWorkerThread **workers;
    unsigned workers_count;


    unsigned is_pfring:1;
    unsigned is_sendq:1;
    unsigned is_offline:1;
    unsigned is_packet_trace:1;
    unsigned is_zonefile_check:1;
};

/**
 * Initialize a configuration structure
 */
void core_init(struct Core *conf);

/**
 * Read configuration information from a file
 */
void conf_read_config_file(struct Core *conf, const char *filename);

/**
 * Read configuration information from the command-line
 */
void conf_command_line(struct Configuration *cfg, int argc, char *argv[]);

/**
 * Once all configuration information has been read, then
 * read in all the zonefiles
 */
enum SuccessFailure
conf_zonefiles_parse(   struct Catalog *db_load,
                        struct Configuration *cfg,
                        uint64_t *total_files,
                        uint64_t *total_bytes);


/**
 * Change the number of data-plane worker-threads
 */
void change_resolver_threads(struct Core *core, struct Configuration *cfg_new);


/**
 * Chagne the data-plane sockets
 */
void change_worker_sockets(struct Core *core, struct Configuration *cfg_new, struct Configuration *cfg_old);

#endif
