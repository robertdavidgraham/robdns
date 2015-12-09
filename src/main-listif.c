#define _CRT_SECURE_NO_WARNINGS
#include "network.h"
#include "adapter-pcaplive.h"
#include "unusedparm.h"
#include "string_s.h"
#include "pixie-sockets.h"
#include "util-realloc2.h"
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef WIN32
#if defined(_MSC_VER)
#pragma comment(lib, "iphlpapi.lib")
#include <ws2ipdef.h>
#endif
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#elif defined(__linux__) || defined(__APPLE__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#endif

/****************************************************************************
 ****************************************************************************/
#if defined(WIN32)

int win32_list_interfaces()
{
// Declare and initialize variables
    PIP_INTERFACE_INFO pInfo = NULL;
    DWORD ulOutBufLen = 0;

    DWORD dwRetVal = 0;
    int iReturn = 1;

    int i;

    // Make an initial call to GetInterfaceInfo to get
    // the necessary size in the ulOutBufLen variable
    dwRetVal = GetInterfaceInfo(NULL, &ulOutBufLen);
    if (dwRetVal != ERROR_INSUFFICIENT_BUFFER) {
        fprintf(stderr, "listif: unexpected condition\n");
        return 1;
    }

    pInfo = MALLOC2(ulOutBufLen);

    // Make a second call to GetInterfaceInfo to get
    // the actual data we need
    dwRetVal = GetInterfaceInfo(pInfo, &ulOutBufLen);
    if (dwRetVal == NO_ERROR) {
        printf("Number of Adapters: %ld\n\n", pInfo->NumAdapters);
        for (i = 0; i < pInfo->NumAdapters; i++) {
            printf("Adapter Index[%d]: %ld\n", i,
                   pInfo->Adapter[i].Index);
            printf("Adapter Name[%d]: %ws\n\n", i,
                   pInfo->Adapter[i].Name);
        }
        iReturn = 0;
    } else if (dwRetVal == ERROR_NO_DATA) {
        printf
            ("There are no network adapters with IPv4 enabled on the local system\n");
        iReturn = 0;
    } else {
        printf("GetInterfaceInfo failed with error: %u\n", (unsigned)dwRetVal);
        iReturn = 1;
    }

    free(pInfo);
    return (iReturn);
}


    /* Declare and initialize variables */

// It is possible for an adapter to have multiple
// IPv4 addresses, gateways, and secondary WINS servers
// assigned to the adapter. 
//
// Note that this sample code only prints out the 
// first entry for the IP address/mask, and gateway, and
// the primary and secondary WINS server for each adapter. 
int win32_list_adapters()
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    UINT i;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);

    pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC2(sizeof (IP_ADAPTER_INFO));
// Make an initial call to GetAdaptersInfo to get
// the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC2(ulOutBufLen);
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            printf("\tComboIndex: \t%u\n", (unsigned)pAdapter->ComboIndex);
            printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
            printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
            printf("\tAdapter Addr: \t");
            for (i = 0; i < pAdapter->AddressLength; i++) {
                if (i == (pAdapter->AddressLength - 1))
                    printf("%.2X\n", (int) pAdapter->Address[i]);
                else
                    printf("%.2X-", (int) pAdapter->Address[i]);
            }
            printf("\tIndex: \t%u\n", (unsigned)pAdapter->Index);
            printf("\tType: \t");
            switch (pAdapter->Type) {
            case MIB_IF_TYPE_OTHER:
                printf("Other\n");
                break;
            case MIB_IF_TYPE_ETHERNET:
                printf("Ethernet\n");
                break;
            case MIB_IF_TYPE_TOKENRING:
                printf("Token Ring\n");
                break;
            case MIB_IF_TYPE_FDDI:
                printf("FDDI\n");
                break;
            case MIB_IF_TYPE_PPP:
                printf("PPP\n");
                break;
            case MIB_IF_TYPE_LOOPBACK:
                printf("Lookback\n");
                break;
            case MIB_IF_TYPE_SLIP:
                printf("Slip\n");
                break;
            default:
                printf("Unknown type %u\n", (unsigned)pAdapter->Type);
                break;
            }

            printf("\tIP Address: \t%s\n",
                   pAdapter->IpAddressList.IpAddress.String);
            printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);

            printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
            printf("\t***\n");


            pAdapter = pAdapter->Next;
        }
    } else {
        printf("GetAdaptersInfo failed with error: %u\n", (unsigned)dwRetVal);

    }
    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
}

#if 0
int win32_getifentry()
{

    // Declare and initialize variables.

    // Declare and initialize variables.
    DWORD dwRetVal = 0;

    unsigned int i;

    MIB_IF_TABLE2 *pIfTable;
    MIB_IF_ROW2 *pIfRow;

    dwRetVal = GetIfTable2(&pIfTable);
    if (dwRetVal != NO_ERROR)
        return 0;
    if (pIfTable->NumEntries == 0)
        return 0;


    printf("\tNum Entries: %ld\n\n", pIfTable->NumEntries);
    for (i = 0; i < pIfTable->NumEntries; i++) {
        pIfRow = &pIfTable->Table[i];

        
        //printf("\tIndex:\t %ld\n", pIfRow->InterfaceIndex);
        printf("[%d]:\t ", pIfRow->InterfaceIndex);
        printf("%ws", pIfRow->Alias);
        
        printf("   \t(%ws)", pIfRow->Description);
        printf("\n");

#if 0
        printf("\tIndex[%d]:\t\t %d\n", i, pIfRow->dwIndex);
        printf("\tType[%d]:\t\t ", i);
        switch (pIfRow->dwType) {
        case IF_TYPE_OTHER:
            printf("Other\n");
            break;
        case IF_TYPE_ETHERNET_CSMACD:
            printf("Ethernet\n");
            break;
        case IF_TYPE_ISO88025_TOKENRING:
            printf("Token Ring\n");
            break;
        case IF_TYPE_PPP:
            printf("PPP\n");
            break;
        case IF_TYPE_SOFTWARE_LOOPBACK:
            printf("Software Lookback\n");
            break;
        case IF_TYPE_ATM:
            printf("ATM\n");
            break;
        case IF_TYPE_IEEE80211:
            printf("IEEE 802.11 Wireless\n");
            break;
        case IF_TYPE_TUNNEL:
            printf("Tunnel type encapsulation\n");
            break;
        case IF_TYPE_IEEE1394:
            printf("IEEE 1394 Firewire\n");
            break;
        default:
            printf("Unknown type %ld\n", pIfRow->dwType);
            break;
        }

        printf("\tMtu[%d]:\t\t %ld\n", i, pIfRow->dwMtu);

        printf("\tSpeed[%d]:\t\t %ld\n", i, pIfRow->dwSpeed);

        printf("\tPhysical Addr:\t\t ");
        if (pIfRow->dwPhysAddrLen == 0)
            printf("\n");
//                    for (j = 0; j < (int) pIfRow->dwPhysAddrLen; j++) {
        for (j = 0; j < pIfRow->dwPhysAddrLen; j++) {
            if (j == (pIfRow->dwPhysAddrLen - 1))
                printf("%.2X\n", (int) pIfRow->bPhysAddr[j]);
            else
                printf("%.2X-", (int) pIfRow->bPhysAddr[j]);
        }
        printf("\tAdmin Status[%d]:\t %ld\n", i,
                pIfRow->dwAdminStatus);

        printf("\tOper Status[%d]:\t ", i);
        switch (pIfRow->dwOperStatus) {
        case IF_OPER_STATUS_NON_OPERATIONAL:
            printf("Non Operational\n");
            break;
        case IF_OPER_STATUS_UNREACHABLE:
            printf("Unreasonable\n");
            break;
        case IF_OPER_STATUS_DISCONNECTED:
            printf("Disconnected\n");
            break;
        case IF_OPER_STATUS_CONNECTING:
            printf("Connecting\n");
            break;
        case IF_OPER_STATUS_CONNECTED:
            printf("Connected\n");
            break;
        case IF_OPER_STATUS_OPERATIONAL:
            printf("Operational\n");
            break;
        default:
            printf("Unknown status %ld\n", 
                pIfRow->dwAdminStatus);
            break;
        }
        printf("\n");
#endif
    }
    return 0;
}
#endif
#endif

#ifdef WIN32
static unsigned char hexval(const char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    return 0;
}

GUID
name_to_guid(const char *in_name)
{
    GUID result;
    char *name = (char*)in_name;
    unsigned i;
    if (memcasecmp(name, "\\Device\\NPF_{", 13) == 0)
        name += 13;

    result.Data1 = strtoul(name, &name, 16);
    if (*name == '-')
        name++;
    result.Data2 = (unsigned short)strtoul(name, &name, 16);
    if (*name == '-')
        name++;
    result.Data3 = (unsigned short)strtoul(name, &name, 16);
    if (*name == '-')
        name++;
    for (i=0; i<8; i++) {
        if (*name == '-')
            name++;
        if (isxdigit(name[0]&0xFF)) {
            result.Data4[i] = hexval(*name)<<4;
            name++;
        }
        if (isxdigit(name[0]&0xFF)) {
            unsigned char x = hexval(*name);
            result.Data4[i] |= x;
            name++;
        }
    }

    return result;
}

#if defined(WIN32) && defined(_MSC_VER)
unsigned
win32_index(MIB_IF_TABLE2 *pIfTable, const char *name)
{
    unsigned i;
    GUID guid = name_to_guid(name);

    for (i=0; i<pIfTable->NumEntries; i++) {
        MIB_IF_ROW2 *row = &pIfTable->Table[i];

        if (memcmp(&row->InterfaceGuid, &guid, sizeof(guid)) == 0) {
            return row->InterfaceIndex;
        }
    }
    return 0;
}
void
win32_name(MIB_IF_TABLE2 *pIfTable, const char *name, char *namebuf, size_t sizeof_namebuf)
{
    unsigned i;
    GUID guid = name_to_guid(name);

    for (i=0; i<pIfTable->NumEntries; i++) {
        MIB_IF_ROW2 *row = &pIfTable->Table[i];

        if (memcmp(&row->InterfaceGuid, &guid, sizeof(guid)) == 0) {
            unsigned j;
            for (j=0; row->Alias[j] && j < sizeof_namebuf-1; j++) 
                namebuf[j] = (char)row->Alias[j];
            namebuf[j] = '\0';
        }
    }
}
#endif
#endif

/*
 * Print list of adapters
 */
int listif(int argc, char *argv[])
{
	int x;
	pcap_if_t *alldevs = 0;
	pcap_if_t *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;
#if defined(WIN32) && defined(_MSC_VER)
    MIB_IF_TABLE2 *pIfTable = 0;
#endif
    
#if defined(WIN32) && defined(_MSC_VER)
    GetIfTable2(&pIfTable);
#endif

    UNUSEDPARM(argc);
    UNUSEDPARM(argv);



    //win32_getifentry();
    //win32_list_interfaces();
    //win32_list_adapters();

	x = pcap.findalldevs(&alldevs, errbuf);
	if (x == -1) {
		fprintf(stderr, "pcap: findalldevs failed: %s\n", errbuf);
		return 0;
	}

	for (dev=alldevs; dev; dev = dev->next) {
#if defined(WIN32) && defined(_MSC_VER)
        char namebuf[64];
#endif
        unsigned index = ++i;
        const char *name = dev->name;
		struct pcap_addr *address = (struct pcap_addr*)dev->addresses;

#if defined(WIN32) && defined(_MSC_VER)
        {
            index = win32_index(pIfTable, name);
            win32_name(pIfTable, name, namebuf, sizeof(namebuf));
            name = namebuf;
        }
#endif


		printf("%d. \"%s\" (%s)\n", index, name, dev->description);
        printf("    ");
		for ( ;address; address = address->next) {
			switch (address->addr->sa_family) {
			case AF_INET:
                {
                    struct sockaddr_in *sin = (struct sockaddr_in*)address->addr;
				    printf("%u.%u.%u.%u  ",
                        (unsigned char)(sin->sin_addr.s_addr>> 0)&0xFF,
                        (unsigned char)(sin->sin_addr.s_addr>> 8)&0xFF,
                        (unsigned char)(sin->sin_addr.s_addr>>16)&0xFF,
                        (unsigned char)(sin->sin_addr.s_addr>>24)&0xFF
				    );
                }
				break;
			case AF_INET6:
                {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)address->addr;
                    unsigned char *px = (unsigned char*)&sin6->sin6_addr;
                    unsigned j;
                    for (j=0; j<8; j++) {
                        unsigned xx = px[0]<<8 | px[1];

                        if (j==0 && xx == 0xfe80)
                            break;
                        px += 2;
                        printf("%x%s", xx, (j==7)?"  ":":");
                    }
                }
				break;
			default:
				printf("Family: %d ", address->addr->sa_family);
			}
		}
		printf("\n");
	}

	pcap.freealldevs(alldevs);
    return 0;
}

/****************************************************************************
 ****************************************************************************/
const char *name_from_address(const char *ip_address)
{
	int x;
	pcap_if_t *alldevs = NULL;
	pcap_if_t *dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	x = pcap.findalldevs(&alldevs, errbuf);
	if (x == -1) {
		fprintf(stderr, "pcap: findalldevs failed: %s\n", errbuf);
		return 0;
	}

	for (dev=alldevs; dev; dev = dev->next) {
		struct pcap_addr *address = dev->addresses;
		char string[64];


		while (address) {
			switch (address->addr->sa_family) {
			case 2:
				sprintf_s(string, sizeof(string), "%u.%u.%u.%u",
					address->addr->sa_data[2]&0xFF, 
					address->addr->sa_data[3]&0xFF, 
					address->addr->sa_data[4]&0xFF, 
					address->addr->sa_data[5]&0xFF
				);
				if (strcmp(string, ip_address) == 0)
					return dev->name;
				break;
			case 23:
				break;
			default:
				;
			}
			address = address->next;
		}
	}

	return 0;
}

