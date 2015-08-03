#include "grind.h"
#include "logger.h"
#include "main-regression.h"
#include "selftest.h"
#include "adapter-pcaplive.h"
#include "zonefile-parse.h"
#include "rawsock.h"
#include "configuration.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


int is_verbose;

const char *version = "robdns/0.2";

/* temporary
 * These globals are for printing debug messages. They are global for now, but
 * I'll get rid of them eventually
 */
uint64_t entry_bytes;
uint64_t entry_count;
uint64_t total_chain_length;


int checkconf(int argc, char *argv[]);
int checkzone(int argc, char *argv[]);
int listif(int argc, char *argv[]);
int foreground(int argc, char *argv[]);
int pcap2zone(int argc, char *argv[]);
int selftest2(int argc, char *argv[]);
int perftest(int argc, char *argv[]);

/****************************************************************************
 ****************************************************************************/
struct {
    const char *name;
    int (*func)(int argc, char *argv[]);
} commands[] = {

    {"selftest", selftest},
    {"--selftest", selftest},
    {"perftest", perftest},
    {"--perftest", perftest},
    {"regress", selftest},
    {"--regress", selftest},
    {"selftest2", selftest2},
    {"checkzone", checkzone},
    {"--checkzone", checkzone},
    {"checkconf", checkconf},
    {"--checkconf", checkconf},
    {"listif", listif},
    {"foreground", foreground},
    {"pcap2zone", pcap2zone},
    {0,0}
};


/****************************************************************************
 ****************************************************************************/
int 
main(int argc, char *argv[])
{
    int i;

  	LOG_INFO(C_GENERAL, "--- Rob's DNS server v0.2 ----\n");

    /*
     * Initialize various things that are process-wide.
     */
    zonefile_parser_init();
    cfg_parser_init();
    rawsock_init();
    
    /*
     * If nothing on command-line, print usage, then self-test for good
     * measure, then exit
     */
    if (argc <= 1) {
        int return_code;
        
        /* first self-test, for the heck of it */
        return_code = selftest(argc, argv);

        fprintf(stderr, "error: no command-line parameters specified\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "usage:\n");
        fprintf(stderr, " robdns <zone-file> <conf-file>\n");
        fprintf(stderr, "where:\n");
        fprintf(stderr, " <zone-file> contains DNs zone data (like \"example.zone\")\n");
        fprintf(stderr, " <conf-file> is a configuration file (like \"named.conf\")\n");
        
        return return_code;
    }


    /*
     * Look for a specific "command". This runs the program in a special way
     * that focuses on a particular area. For example, the "dig" command
     * behaves a lot like the BIND9 "dig" utility, but using our paradigm.
     */
    for (i=0; commands[i].name; i++) {
        if (strcmp(commands[i].name, argv[1]) == 0) {
            int result;
            result = commands[i].func(argc, argv);
            if (result == Success)
                return 0;
            else
                return 1;
        }
    }


    /*
     * If no specific command was given, then run in the default mode as
     * a DNS server. This runs in the 'foreground' printing to stdout/stderr,
     * some other tool is needed to launch this as a service.
     */
    foreground(argc, argv);

    return 0;


    /*
     * Temporary: check hash efficiency
     */
#if 0
    check_chain_lengths(grind);
#endif


#if 0
	struct Thread thread[1];
	pcap_t *h;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *if_name = name_from_address(argv[1]);


	memset(thread, 0, sizeof(thread[0]));
	thread->grind = grind;

	grind->ip_address = 0x0a141e0f;
	memcpy(grind->mac_address, "\x00\x11\x11\x22\x22\x22", 6);
	
	fprintf(stderr, "IP: %u.%u.%u.%u\n", 
		(unsigned char)(grind->ip_address>>24),
		(unsigned char)(grind->ip_address>>16),
		(unsigned char)(grind->ip_address>> 8),
		(unsigned char)(grind->ip_address>> 0)
		);
	fprintf(stderr, "MAC: %02x-%02x-%02x-%02x-%02x-%02x\n", 
		grind->mac_address[0],
		grind->mac_address[1],
		grind->mac_address[2],
		grind->mac_address[3],
		grind->mac_address[4],
		grind->mac_address[5]
		);


	/*
	 * Open the PCAP adapter
	 */
	h = pcap_open_live(	if_name,	/* interface name */
						2048,		/* packet size (snap length) = 2048 bytes */
						0,			/* not promiscuous mode */
						1,			/* 1-millisecond read timeout */
						errbuf		/* where to store error msgs */
						);
	if (h == NULL) {
		fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
		return 0;
	} else {
		fprintf(stderr, "Adapter: %s\n", if_name);
		grind->adapter = h;
	}

	for (;;) {
		int x;

		x = pcap_dispatch(
			h, 
			1, 
			stack_receive,
			(unsigned char *)thread);

		if (x == -1)
			break;
	}
#endif
}

