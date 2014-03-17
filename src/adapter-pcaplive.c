/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	PCAPLIVE

  This code links the 'libpcap' module at RUNTIME rather than LOADTIME.
  This allows us to:
  (a) run this program on capture files without needing libpcap installed.
  (b) give more user friendly diagnostic to the users who don't realize
      that they need to install libpcap separately.

  On Windows, this uses the LoadLibrary/GetProcAddress functions to
  load the library.

  On Linux, this uses the dlopen/dlsym functions to do essentially
  the same thing.
*/


#if _MSC_VER==1200
#pragma warning(disable:4115 4201)
#include <winerror.h>
#endif
#include "adapter-pcaplive.h"

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef UNUSEDPARM
#if defined(_MSC_VER)
#define UNUSEDPARM(x) x
#elif defined(__GNUC__)
#define UNUSEDPARM(x)
#endif
#endif

struct PCAPLIVE pcap;

static void 
seterr(char *errbuf, const char *msg)
{
	size_t length = strlen(msg);

	if (length > PCAP_ERRBUF_SIZE-1)
		length = PCAP_ERRBUF_SIZE-1;
	memcpy(errbuf, msg, length);
	errbuf[length] = '\0';
}

static void null_PCAP_CLOSE(void *hPcap)
{
#ifdef STATICPCAP
	pcap_close(hPcap);
	return;
#endif
	UNUSEDPARM(hPcap);
}


static unsigned null_PCAP_DATALINK(void *hPcap)
{
#ifdef STATICPCAP
	return pcap_datalink(hPcap);
#endif
	UNUSEDPARM(hPcap);
	return 0;
}


static unsigned null_PCAP_DISPATCH(void *hPcap, unsigned how_many_packets, PCAP_HANDLE_PACKET handler, void *handle_data)
{
#ifdef STATICPCAP
	return pcap_dispatch(hPcap, how_many_packets, handler, handle_data);
#endif
	UNUSEDPARM(hPcap);UNUSEDPARM(how_many_packets);UNUSEDPARM(handler);UNUSEDPARM(handle_data);
	return 0;
}


static int null_PCAP_FINDALLDEVS(pcap_if_t **alldevs, char *errbuf)
{
#ifdef STATICPCAP
	return pcap_findalldevs(alldevs, errbuf);
#endif
	*alldevs = 0;
	seterr(errbuf, "libpcap not loaded");
	return -1;
}


static void null_PCAP_FREEALLDEVS(pcap_if_t *alldevs)
{
#ifdef STATICPCAP
	return pcap_freealldevs(alldevs);
#endif
	UNUSEDPARM(alldevs);
	return;
}


static char *null_PCAP_LOOKUPDEV(char *errbuf)
{
#ifdef STATICPCAP
	return pcap_lookupdev(errbuf);
#endif
	seterr(errbuf, "libpcap not loaded");
	return "";
}


static void * null_PCAP_OPEN_LIVE(const char *devicename, unsigned snap_length, unsigned is_promiscuous, unsigned read_timeout, char *errbuf)
{
#ifdef STATICPCAP
	return pcap_open_live(devicename, snap_length, is_promiscuous, read_timeout, errbuf);
#endif
	seterr(errbuf, "libpcap not loaded");
	UNUSEDPARM(devicename);UNUSEDPARM(snap_length);UNUSEDPARM(is_promiscuous);UNUSEDPARM(read_timeout);
	return NULL;
}

static int null_PCAP_MAJOR_VERSION(void *p)
{
#ifdef STATICPCAP
	return pcap_major_version(p);
#endif
	UNUSEDPARM(p);
	return 0;
}


static int null_PCAP_MINOR_VERSION(void *p)
{
#ifdef STATICPCAP
	return pcap_minor_version(p);
#endif
	UNUSEDPARM(p);
	return 0;
}

static const char *null_PCAP_LIB_VERSION(void)
{
#ifdef STATICPCAP
	return pcap_lib_version();
#endif

	return "stub/0.0";
}

#ifdef WIN32
static void *null_PCAP_GET_AIRPCAP_HANDLE(void *p)
{
	UNUSEDPARM(p);
	return NULL;
}
#endif

#ifdef WIN32
static unsigned null_AIRPCAP_SET_DEVICE_CHANNEL(void *p, unsigned channel)
{
	UNUSEDPARM(p);UNUSEDPARM(channel);

	return 0; /*0=failure, 1=success*/
}
#endif


static unsigned null_CAN_TRANSMIT(const char *devicename)
{
#if WIN32
	struct DeviceCapabilities {
		unsigned AdapterId;		/* An Id that identifies the adapter model.*/
		char AdapterModelName;	/* String containing a printable adapter model.*/
		unsigned AdapterBus;	/* The type of bus the adapter is plugged to. */
		unsigned CanTransmit;	/* TRUE if the adapter is able to perform frame injection.*/
		unsigned CanSetTransmitPower; /* TRUE if the adapter's transmit power is can be specified by the user application.*/
		unsigned ExternalAntennaPlug; /* TRUE if the adapter supports plugging one or more external antennas.*/
		unsigned SupportedMedia;
		unsigned SupportedBands;
	} caps;
	void * (*myopen)(const char *devicename, char *errbuf);
	void (*myclose)(void *h);
	unsigned (*mycapabilities)(void *h, struct DeviceCapabilities *caps);

	unsigned result = 0;
	void *hAirpcap;
	
	
	hAirpcap = LoadLibraryA("airpcap.dll");
	if (hAirpcap == NULL)
		return 0;

	
	myopen = (void * (*)(const char *, char*))GetProcAddress(hAirpcap, "AirpcapOpen");
	myclose = (void (*)(void*))GetProcAddress(hAirpcap, "AirpcapClose");
	mycapabilities = (unsigned (*)(void*, struct DeviceCapabilities *))GetProcAddress(hAirpcap, "AirpcapGetDeviceCapabilities");
	if (myopen && mycapabilities && myclose ) {
		void *h = myopen(devicename, NULL);
		if (h) {
			if (mycapabilities(h, &caps)) {
				result = caps.CanTransmit;
			}
			myclose(h);
		}
	}

	FreeLibrary(hAirpcap);
	return result;
#elif defined(__linux__)
	return 1;
#elif defined(__APPLE__)
    return 0;
#endif
}

PCAP_COMPILE        null_PCAP_COMPILE;
PCAP_PERROR         null_PCAP_PERROR;
PCAP_SETFILTER      null_PCAP_SETFILTER;
PCAP_NEXT           null_PCAP_NEXT;
PCAP_SENDPACKET         null_PCAP_SENDPACKET;
PCAP_SENDQUEUE_ALLOC    null_PCAP_SENDQUEUE_ALLOC;
PCAP_SENDQUEUE_DESTROY  null_PCAP_SENDQUEUE_DESTROY;
PCAP_SENDQUEUE_QUEUE    null_PCAP_SENDQUEUE_QUEUE;
PCAP_SENDQUEUE_TRANSMIT null_PCAP_SENDQUEUE_TRANSMIT;
PCAP_SETDIRECTION       null_PCAP_SETDIRECTION;


/**
 * Runtime-load the libpcap shared-object or the winpcap DLL. We
 * load at runtime rather than loadtime to allow this program to 
 * be used to process offline content, and to provide more helpful
 * messages to people who don't realize they need to install PCAP.
 */
void pcaplive_init()
{
    struct PCAPLIVE *pl = &pcap;
#ifdef WIN32
	HMODULE hPacket;
	HMODULE hLibpcap;
	HMODULE hAirpcap;

	pl->is_available = 0;
	pl->is_printing_debug = 1;

	/* Look for the Packet.dll */
	hPacket = LoadLibraryA("Packet.dll");
	if (hPacket == NULL) {
		if (pl->is_printing_debug)
		switch (GetLastError()) {
		case ERROR_MOD_NOT_FOUND:
			fprintf(stderr, "%s: not found\n", "Packet.dll");
			fprintf(stderr, "%s: with WinPcap not install or 32/64 bit error\n", "Packet.dll");
			return;
		default:
			fprintf(stderr, "%s: couldn't load %d\n", "Packet.dll", (int)GetLastError());
			fprintf(stderr, "%s: with WinPcap not install or 32/64 bit error\n", "Packet.dll");
			return;
		}
	}

	/* Look for the Packet.dll */
	hLibpcap = LoadLibraryA("wpcap.dll");
	if (hLibpcap == NULL) {
		if (pl->is_printing_debug)
			fprintf(stderr, "%s: couldn't load %d\n", "wpcap.dll", (int)GetLastError());
		return;
	}

	/* Look for the Packet.dll */
	hAirpcap = LoadLibraryA("airpcap.dll");
	if (hLibpcap == NULL) {
		if (pl->is_printing_debug)
			fprintf(stderr, "%s: couldn't load %d\n", "airpcap.dll", (int)GetLastError());
		return;
	}

#define DOLINK(PCAP_DATALINK, datalink) \
	pl->datalink = (PCAP_DATALINK)GetProcAddress(hLibpcap, "pcap_"#datalink); \
	if (pl->datalink == NULL) pl->func_err=1, pl->datalink = null_##PCAP_DATALINK;
#endif


#ifndef WIN32
#ifndef STATICPCAP
	void *hLibpcap;
	unsigned initial_failure=0;

	pl->is_available = 0;
	pl->is_printing_debug = 1;

#if defined(__APPLE__)
    hLibpcap = dlopen("libpcap.dylib", RTLD_LAZY);
#else
	hLibpcap = dlopen("libpcap.so", RTLD_LAZY);
#endif
	if (hLibpcap == NULL) {
		fprintf(stderr, "%s: %s\n", "libpcap.so", dlerror());
		fprintf(stderr, "Searching elsewhere for libpcap\n");
		initial_failure = 1;
	}

	if (hLibpcap==NULL)
		hLibpcap = dlopen("libpcap.so.0.9.5", RTLD_LAZY);
	if (hLibpcap==NULL)
		hLibpcap = dlopen("libpcap.so.0.9.4", RTLD_LAZY);
	if (hLibpcap==NULL)
		hLibpcap = dlopen("libpcap.so.0.8", RTLD_LAZY);
	if (hLibpcap == NULL) {
		if (pl->is_printing_debug) {
			fprintf(stderr, "%s: couldn't load %d (%s)\n", "libpcap.so", errno, strerror(errno));
		}
	} else if (initial_failure) {
		fprintf(stderr, "Found libpcap\n");
	}

#define DOLINK(PCAP_DATALINK, datalink) \
	pl->datalink = (PCAP_DATALINK)dlsym(hLibpcap, "pcap_"#datalink); \
	if (pl->datalink == NULL) pl->func_err=1, pl->datalink = null_##PCAP_DATALINK;
#else
#define DOLINK(PCAP_DATALINK, datalink) \
	pl->func_err=0, pl->datalink = null_##PCAP_DATALINK;
#endif
#endif

#ifdef WIN32
	DOLINK(PCAP_GET_AIRPCAP_HANDLE, get_airpcap_handle);
	if (pl->func_err) {
		pl->func_err = 0;
	}
	if (hAirpcap) {
		pl->airpcap_set_device_channel = (AIRPCAP_SET_DEVICE_CHANNEL)GetProcAddress(hAirpcap, "AirpcapSetDeviceChannel");
		if (pl->airpcap_set_device_channel == NULL)
			pl->airpcap_set_device_channel = null_AIRPCAP_SET_DEVICE_CHANNEL;
	}
#endif
	


	DOLINK(PCAP_CLOSE			, close);
	DOLINK(PCAP_DATALINK		, datalink);
	DOLINK(PCAP_DISPATCH		, dispatch);
	DOLINK(PCAP_FINDALLDEVS		, findalldevs);
	DOLINK(PCAP_FREEALLDEVS		, freealldevs);
	DOLINK(PCAP_LIB_VERSION		, lib_version);
	DOLINK(PCAP_LOOKUPDEV		, lookupdev);
	DOLINK(PCAP_MAJOR_VERSION	, major_version);
	DOLINK(PCAP_MINOR_VERSION	, minor_version);
	DOLINK(PCAP_OPEN_LIVE		, open_live);
    DOLINK(PCAP_COMPILE         , compile);
    DOLINK(PCAP_PERROR          , perror);
    DOLINK(PCAP_SETFILTER       , setfilter);
    DOLINK(PCAP_NEXT            , next);
    DOLINK(PCAP_SENDPACKET         , sendpacket);
    DOLINK(PCAP_SENDQUEUE_ALLOC    , sendqueue_alloc);
    DOLINK(PCAP_SENDQUEUE_DESTROY  , sendqueue_destroy);
    DOLINK(PCAP_SENDQUEUE_QUEUE    , sendqueue_queue);
    DOLINK(PCAP_SENDQUEUE_TRANSMIT , sendqueue_transmit);
    DOLINK(PCAP_SETDIRECTION       , setdirection);
                               


	pl->can_transmit = null_CAN_TRANSMIT;

	if (!pl->func_err)
		pl->is_available = 1;
	else
		pl->is_available = 0;
}

