#include "main-regression.h"
#include "pixie.h"
#include "grind.h"
#include "adapter.h"
#include "adapter-pcapfile.h"
#include "thread.h"
#include "util-filename.h"
#include "network.h"
#include "grind.h"
#include "unusedparm.h"
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>


/****************************************************************************
 * Look for suffixes to strings, especially looking for file types like
 * ".conf" or ".zone" or ".pcap".
 * @return 1 if the string has that suffix, or 0 otherwise.
 ****************************************************************************/
static int
ends_with(const char *string, const char *suffix)
{
    size_t string_length = strlen(string);
    size_t suffix_length = strlen(suffix);

    if (suffix_length > string_length)
        return 0;

    return memcmp(string+string_length-suffix_length, suffix, suffix_length) == 0;
}


/****************************************************************************
 ****************************************************************************/
static int
regression_load_configuration(struct Grind *grind, const char *directory_name)
{
    void *directory;
    int is_configuration_loaded = 0;

	directory = pixie_opendir(directory_name);
	if (directory == NULL)
        return Success; /* no problems so far */

    for (;;) {
        const char *filename;

        /* read next filename */
        filename = pixie_readdir(directory);
        if (filename == 0)
            break;

        /* look for .conf extension for configuration files */
        if (!ends_with(filename, ".conf"))
            continue;

        /* make sure we don't load more than one configuration file */
        if (is_configuration_loaded) {
            fprintf(stderr, "%s:fail: more than one configuration file found\n", filename);
            return Failure;
        } else
            is_configuration_loaded = 1;

        /* load the configuration */
        if (grind_load_configuration(grind, filename) == 0) {
            fprintf(stdout, "%s:fail: error reading configuration file\n", filename);
            return Failure;
        }
    }

    pixie_closedir(directory);
    return Success; /* no problems so far */
}

/****************************************************************************
 ****************************************************************************/
static int
regression_load_zonefile(struct Grind *grind, const char *directory_name)
{
    void *directory;

	directory = pixie_opendir(directory_name);
	if (directory == NULL)
        return Failure; /* must have at least one zonefile */

    for (;;) {
        const char *filename;
        char *tmp;

        /* read next filename */
        filename = pixie_readdir(directory);
        if (filename == 0)
            break;

        /* look for .zone extension for zone-files */
        if (!ends_with(filename, ".zone"))
            continue;

        /* load the zone-file */
        tmp = filename_combine(directory_name, filename);
        if (grind_load_zonefile(grind, tmp, ROOT, 0) == 0) {
            free(tmp);
            fprintf(stdout, "%s:fail: error reading zonefile file\n", filename);
            return Failure;
        }
        free(tmp);
    }

    pixie_closedir(directory);
    return Success; /* success so far */
}

static struct Packet
regression_alloc_packet(struct Adapter *adapter, struct Thread *thread)
{
    struct Packet result;
    static unsigned char buf[65536];

    UNUSEDPARM(thread);
    UNUSEDPARM(adapter);

    memset(buf, 0xa3, sizeof(buf));
    result.max = 1514;
    result.buf = buf;
    result.offset = 0;
    result.fixup.network = 0;
    result.fixup.transport = 0;

    return result;
}


static void
regression_xmit_packet(struct Adapter *adapter, struct Thread *thread, struct Packet *pkt)
{
    struct PcapFile *writefile = (struct PcapFile *)adapter->userdata;

    UNUSEDPARM(thread);

    pcapfile_writeframe(
                    writefile,
                    pkt->buf,
                    pkt->max,
                    pkt->max,
                    0,
                    0);
}


/****************************************************************************
 ****************************************************************************/
static int
regression_test_pcap(struct Grind *grind, const char *filename)
{
    struct PcapFile *pcapfile;
    struct Thread thread[1];
    struct Adapter adapter[1];
    struct PcapFile *writefile;

    writefile = pcapfile_openwrite("foo.pcap", 1);

    /*
     * Normally, we have multiple threads receving packets, but for these
     * regression tests, we have only a single thread. So we need to create
     * pseudo-thread object
     */
    memset(&adapter, 0, sizeof(adapter[0]));
    adapter->alloc_packet = regression_alloc_packet;
    adapter->xmit_packet = regression_xmit_packet;
    adapter->userdata = writefile;

    adapter->ipv4_count = 1;
    adapter->ipv6_count = 1;

    memset(&thread, 0, sizeof(thread[0]));
    thread->catalog_run = grind_get_catalog(grind);
    
    
    
    /*
     * Open the tcpdump packet capture file 
     */
    pcapfile = pcapfile_openread(filename);
    if (pcapfile == NULL) {
        fprintf(stdout, "%s:fail: could not open pcap file\n", filename);
        return Failure;
    }

    /*
     * Read all frames
     */
    for (;;) {
        int x;
        unsigned time_secs;
        unsigned time_usecs;
        unsigned original_length;
        unsigned captured_length;
        unsigned char buf[65536];
        
        /* read next packet from file */
        x = pcapfile_readframe(
                    pcapfile,
                    &time_secs,
                    &time_usecs,
                    &original_length,
                    &captured_length,
                    buf,
                    sizeof(buf)
                    );
        if (!x)
            break;

    
        /* process the packet */
        {
            uint64_t j;
            struct Frame frame[1];
            //clock_t start = clock();
            //uint64_t last_j = 0;

            for (j=0; j<1; j++) {
                network_receive(
                        frame,
                        thread,
                        adapter,
                        time_secs,
                        time_usecs,
                        buf,
                        captured_length);
                /*if ((j & 0xFFFFF) == 0) {
                    clock_t now = clock();
                    double elapsed = ((now-start)*1.0)/CLOCKS_PER_SEC;
                    unsigned rate = (unsigned)((j - last_j)/elapsed);
                    printf("%12u\b\b\b\b\b\b\b\b\b\b\b\b", rate);
                    last_j = j;
                    start = now;
                }*/
            }
        }
        printf(".");
    }

    /*
     * Done, so close the file
     */
    pcapfile_close(pcapfile);
    pcapfile_close(writefile);

    return Success;
}


/****************************************************************************
 ****************************************************************************/
static int
regression_test_pcaps(struct Grind *grind, const char *directory_name)
{
    void *directory;
    int status = Success;
    char *tmp;
    unsigned files_tested = 0;

	directory = pixie_opendir(directory_name);
	if (directory == NULL)
        return Failure; /* regression failed, must have at least one zonefile */

    for (;;) {
        const char *filename;
        int x;

        /* read next filename */
        filename = pixie_readdir(directory);
        if (filename == 0)
            break;

        /* look for .pcap extension for tcpdump/libpcap files */
        if (!ends_with(filename, ".pcap"))
            continue;
        
        /* Test the individual packet capture */
        tmp = filename_combine(directory_name, filename);
        x = regression_test_pcap(grind, tmp);
        free(tmp);
        files_tested++;
        if (x == Failure)
            status = Failure;

    }

    pixie_closedir(directory);
    if (files_tested == 0) {
        fprintf(stdout, "%s:fail: no .pcap files found\n", directory_name);
        return Failure;
    }
    return status; /* if any fail, the entire regression fails */
}

/****************************************************************************
 ****************************************************************************/
int
regression_test(const char *directory_name)
{
    int x;
    struct Grind *grind;

    /*
     * Create an instance for this regression test
     */
    grind = grind_create();

    /*
     * Load configuration, if there is one.
     */
    x = regression_load_configuration(grind, directory_name);
    if (x == Failure)
        return x;

    /*
     * Load all zone files. Note that GRIND automatically ignores
     * redudent attempts to load the same zonefile, so it's safe
     * for zonefiles to include each other.
     */
    x = regression_load_zonefile(grind, directory_name);
    if (x == Failure)
        return x;
    
    /*
     * Load all the packet captures, one by one, and test them.
     * If any of the PCAPS fail, then the entire test fails.
     */
    x = regression_test_pcaps(grind, directory_name);
    if (x == Failure)
        return x;

    /*
     * Destroy this instance. Note that if we are doing many
     * regression tests, the next call will create a new instance.
     */
    grind_destroy(grind);

    return Success; /* regression test succeeded */
}
