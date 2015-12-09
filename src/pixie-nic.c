#include "pixie-nic.h"
#include "string_s.h"
#include "util-ipaddr.h"
#include "util-realloc2.h"
#include "adapter-pcaplive.h"

unsigned pixie_nic_exists(const char *ifname)
{
    return 0;
}


/*****************************************************************************
 *****************************************************************************/
#if defined(__linux__)
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/types.h>
#include <unistd.h>



struct route_info {
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

static int read_netlink(int fd, char *bufPtr, size_t sizeof_buffer, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

 do {
        /* Recieve response from the kernel */
        if ((readLen = recv(fd, bufPtr, sizeof_buffer - msgLen, 0)) < 0) {
            perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *) bufPtr;

        /* Check if the header is valid */
        if ((NLMSG_OK(nlHdr, readLen) == 0)
            || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            perror("Error in recieved packet");
            return -1;
        }

        /* Check if the its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        } else {
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

        /* Check if its a multi part message */
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            /* return if its not */
            break;
        }
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

/* For parsing the route info returned */
static int parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen = 0;

    rtMsg = (struct rtmsg *) NLMSG_DATA(nlHdr);

    /* This must be an IPv4 (AF_INET) route */
    if (rtMsg->rtm_family != AF_INET)
        return 1;

    /* This must be in main routing table */
    if (rtMsg->rtm_table != RT_TABLE_MAIN)
        return 1;

    /* Attributes field*/
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            if_indextoname(*(int *) RTA_DATA(rtAttr), rtInfo->ifName);
            break;
        case RTA_GATEWAY:
            rtInfo->gateWay.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr .s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        }
    }

    return 0;
}


int rawsock_get_default_gateway(const char *ifname, unsigned *ipv4)
{
    int fd;
    struct nlmsghdr *nlMsg;
    char msgBuf[16384];
    int len;
    int msgSeq = 0;

    /*
     * Set to zero, in case we cannot find it
     */
    *ipv4 = 0;

    /*
     * Create 'netlink' socket to query kernel
     */
    fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) {
        fprintf(stderr, "%s:%d: socket(NETLINK_ROUTE): %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }

    /*
     * format the netlink buffer
     */
    memset(msgBuf, 0, sizeof(msgBuf));
    nlMsg = (struct nlmsghdr *)msgBuf;

    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlMsg->nlmsg_type = RTM_GETROUTE;
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    /*
     * send first request to kernel
     */
    if (send(fd, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
        fprintf(stderr, "%s:%d: send(NETLINK_ROUTE): %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }

    /*
     * Now read all the responses
     */
    len = read_netlink(fd, msgBuf, sizeof(msgBuf), msgSeq, getpid());
    if (len <= 0) {
        fprintf(stderr, "%s:%d: read_netlink: %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }


    /*
     * Parse the response
     */
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        struct route_info rtInfo[1];
        int err;

        memset(rtInfo, 0, sizeof(struct route_info));

        err = parseRoutes(nlMsg, rtInfo);
        if (err != 0)
            continue;

        /* make sure we match the desired network interface */
        if (ifname && strcmp(rtInfo->ifName, ifname) != 0)
            continue;

        /* make sure destination = 0.0.0.0 for "default route" */
        if (rtInfo->dstAddr.s_addr != 0)
            continue;

        /* found the gateway! */
        *ipv4 = ntohl(rtInfo->gateWay.s_addr);
    }

    close(fd);

    return 0;
}

unsigned
pixie_nic_get_mac(const char *ifname, unsigned char *mac)
{
    int fd;
    int x;
    struct ifreq ifr;


    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){
        perror("socket");
        goto end;
    }

    strcpy_s(ifr.ifr_name, IFNAMSIZ, ifname);
    x = ioctl(fd, SIOCGIFHWADDR, (char *)&ifr);
    if (x < 0) {
        perror("ioctl");
        goto end;
    }

    memcpy(mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

end:
    close(fd);
    return 0;
}




unsigned
pixie_nic_get_default(char *ifname, size_t sizeof_ifname)
{
    int fd;
    struct nlmsghdr *nlMsg;
    char msgBuf[16384];
    int len;
    int msgSeq = 0;
    unsigned ipv4 = 0;


    /*
     * Create 'netlink' socket to query kernel
     */
    fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) {
        fprintf(stderr, "%s:%d: socket(NETLINK_ROUTE): %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }

    /*
     * format the netlink buffer
     */
    memset(msgBuf, 0, sizeof(msgBuf));
    nlMsg = (struct nlmsghdr *)msgBuf;

    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlMsg->nlmsg_type = RTM_GETROUTE;
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    /*
     * send first request to kernel
     */
    if (send(fd, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
        fprintf(stderr, "%s:%d: send(NETLINK_ROUTE): %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }

    /*
     * Now read all the responses
     */
    len = read_netlink(fd, msgBuf, sizeof(msgBuf), msgSeq, getpid());
    if (len <= 0) {
        fprintf(stderr, "%s:%d: read_netlink: %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }


    /*
     * Parse the response
     */
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        struct route_info rtInfo[1];
        int err;

        memset(rtInfo, 0, sizeof(struct route_info));

        err = parseRoutes(nlMsg, rtInfo);
        if (err != 0)
            continue;


        /* make sure destination = 0.0.0.0 for "default route" */
        if (rtInfo->dstAddr.s_addr != 0)
            continue;

        /* found the gateway! */
        ipv4 = ntohl(rtInfo->gateWay.s_addr);
        if (ipv4 == 0)
            continue;

        strcpy_s(ifname, sizeof_ifname, rtInfo->ifName);
    }

    close(fd);

    return 0;
}

unsigned
pixie_nic_get_ipv4(const char *ifname)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    int x;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy_s(ifr.ifr_name, IFNAMSIZ, ifname);

    x = ioctl(fd, SIOCGIFADDR, &ifr);
    if (x < 0) {
        fprintf(stderr, "ERROR:'%s': %s\n", ifname, strerror(errno));
        //fprintf(stderr, "ERROR:'%s': couldn't discover IP address of network interface\n", ifname);
        close(fd);
        return 0;
    }

    close(fd);

    sa = &ifr.ifr_addr;
    sin = (struct sockaddr_in *)sa;
    return ntohl(sin->sin_addr.s_addr);
}

/*****************************************************************************
 *****************************************************************************/
#elif defined(WIN32)
#include <winsock2.h>
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "IPHLPAPI.lib")
#endif

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

int
rawsock_is_adapter_names_equal(const char *lhs, const char *rhs)
{
    if (memcmp(lhs, "\\Device\\NPF_", 12) == 0)
        lhs += 12;
    if (memcmp(rhs, "\\Device\\NPF_", 12) == 0)
        rhs += 12;
    return strcmp(lhs, rhs) == 0;
}

/***************************************************************************
 ***************************************************************************/
static char *adapter_from_index(unsigned index)
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int x;

    x = pcap.findalldevs(&alldevs, errbuf);
    if (x != -1) {
        pcap_if_t *d;

        if (alldevs == NULL) {
            fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
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
 * Used on Windows: if the adpter name is a numeric index, convert it to
 * the full name.
 ***************************************************************************/
const char *
rawsock_win_name(const char *ifname)
{
    if (is_numeric_index(ifname)) {
        const char *new_adapter_name;

        new_adapter_name = adapter_from_index(atoi(ifname));
        if (new_adapter_name)
            return new_adapter_name;
    }

    return ifname;
}

unsigned
pixie_nic_gateway(const char *ifname, unsigned *ipv4)
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD err;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);

    /*
     * Translate numeric index (if it exists) to real name
     */
    ifname = rawsock_win_name(ifname);
    //printf("------ %s -----\n", ifname);

    /*
     * Allocate a proper sized buffer
     */
    pAdapterInfo = MALLOC2(sizeof (IP_ADAPTER_INFO));

    /*
     * Query the adapter info. If the buffer is not big enough, loop around
     * and try again
     */
again:
    err = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (err == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC2(ulOutBufLen);
        goto again;
    }
    if (err != NO_ERROR) {
        fprintf(stderr, "GetAdaptersInfo failed with error: %u\n", (unsigned)err);
        return EFAULT;
    }

    /*
     * loop through all adapters looking for ours
     */
    for (   pAdapter = pAdapterInfo;
            pAdapter;
            pAdapter = pAdapter->Next) {
        if (rawsock_is_adapter_names_equal(pAdapter->AdapterName, ifname))
            break;
    }

    if (pAdapter) {
        //printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
        //printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
        //printf("\tAdapter Desc: \t%s\n", pAdapter->Description);


        //printf("\tAdapter Addr: \t");
        /*for (i = 0; i < pAdapter->AddressLength; i++) {
            if (i == (pAdapter->AddressLength - 1))
                printf("%.2X\n", (int) pAdapter->Address[i]);
            else
                printf("%.2X-", (int) pAdapter->Address[i]);
        }*/
        //printf("\tIndex: \t%d\n", pAdapter->Index);
        //printf("\tType: \t");
        switch (pAdapter->Type) {
        case MIB_IF_TYPE_OTHER:
            //printf("Other\n");
            break;
        case MIB_IF_TYPE_ETHERNET:
            //printf("Ethernet\n");
            break;
        case MIB_IF_TYPE_TOKENRING:
            //printf("Token Ring\n");
            break;
        case MIB_IF_TYPE_FDDI:
            //printf("FDDI\n");
            break;
        case MIB_IF_TYPE_PPP:
            //printf("PPP\n");
            break;
        case MIB_IF_TYPE_LOOPBACK:
            //printf("Lookback\n");
            break;
        case MIB_IF_TYPE_SLIP:
            //printf("Slip\n");
            break;
        default:
            //printf("Unknown type %ld\n", pAdapter->Type);
            break;
        }

        //printf("\tIP Address: \t%s\n", pAdapter->IpAddressList.IpAddress.String);
        //printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);

/*typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;*/

        {
            const IP_ADDR_STRING *addr;

            for (addr = &pAdapter->GatewayList; addr; addr = addr->Next) {
                unsigned offset;
                struct ParsedIpAddress ipx;


                err = parse_ipv4_address(addr->IpAddress.String,
                                         &offset,
                                         strlen(addr->IpAddress.String),
                                         &ipx);
                if (err && ipx.version == 4)
                    *ipv4 =  ipx.address[0]<<24 | ipx.address[1]<<16 | ipx.address[2]<<8 | ipx.address[3];
            }
       }


        //printf("\n");
    }
    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
}



unsigned
pixie_nic_get_mac(const char *ifname, unsigned char *mac)
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD err;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);

    /*
     * Allocate a proper sized buffer
     */
    pAdapterInfo = MALLOC2(sizeof (IP_ADAPTER_INFO));

    /*
     * Query the adapter info. If the buffer is not big enough, loop around
     * and try again
     */
again:
    err = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (err == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC2(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            fprintf(stderr, "Error allocating memory needed to call GetAdaptersinfo\n");
            return EFAULT;
        }
        goto again;
    }
    if (err != NO_ERROR) {
        fprintf(stderr, "GetAdaptersInfo failed with error: %u\n", (unsigned)err);
        return EFAULT;
    }

    /*
     * loop through all adapters looking for ours
     */
    for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
        if (rawsock_is_adapter_names_equal(pAdapter->AdapterName, ifname))
            break;
    }

    if (pAdapter) {
        if (pAdapter->AddressLength != 6)
            return EFAULT;
        memcpy(mac, pAdapter->Address, 6);
    }

    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
}



unsigned
pixie_nic_get_ipv4(const char *ifname)
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD err;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    unsigned x_index;

    if (is_numeric_index(ifname))
        x_index = strtoul(ifname, 0, 0);
    else
        x_index = (unsigned)-1;


    /*
     * Allocate a proper sized buffer
     */
    pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC2(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        fprintf(stderr, "error:malloc(): for GetAdaptersinfo\n");
        return 0;
    }

    /*
     * Query the adapter info. If the buffer is not big enough, loop around
     * and try again
     */
again:
    err = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (err == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC2(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            fprintf(stderr, "error:malloc(): for GetAdaptersinfo\n");
            return 0;
        }
        goto again;
    }
    if (err != NO_ERROR) {
        fprintf(stderr, "GetAdaptersInfo failed with error: %u\n", (unsigned)err);
        return 0;
    }

    /*
     * loop through all adapters looking for ours
     */
    for (   pAdapter = pAdapterInfo;
            pAdapter;
            pAdapter = pAdapter->Next) {
        if (rawsock_is_adapter_names_equal(pAdapter->AdapterName, ifname) ||
            x_index == pAdapter->ComboIndex || x_index == pAdapter->Index)
            break;
    }

    if (pAdapter) {
        const IP_ADDR_STRING *addr;

        for (addr = &pAdapter->IpAddressList; addr; addr = addr->Next) {
            struct ParsedIpAddress ipx;


            err = parse_ipv4_address(addr->IpAddress.String,
                                     0,
                                     0,
                                     &ipx);
            if (err && ipx.version == 4)
                return ipx.address[0]<<24 | ipx.address[1]<<16 | ipx.address[2]<<8 | ipx.address[3];
        }
    }

    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
}



unsigned
pixie_nic_get_default(char *ifname, size_t sizeof_ifname)
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD err;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    const IP_ADDR_STRING *addr;

    /*
     * Allocate a proper sized buffer
     */
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        fprintf(stderr, "Error allocating memory needed to call GetAdaptersinfo\n");
        return EFAULT;
    }

    /*
     * Query the adapter info. If the buffer is not big enough, loop around
     * and try again
     */
again:
    err = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (err == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            fprintf(stderr, "Error allocating memory needed to call GetAdaptersinfo\n");
            return EFAULT;
        }
        goto again;
    }
    if (err != NO_ERROR) {
        fprintf(stderr, "GetAdaptersInfo failed with error: %u\n", (unsigned)err);
        return EFAULT;
    }

    /*
     * loop through all adapters looking for ours
     */
    for (   pAdapter = pAdapterInfo;
            pAdapter;
            pAdapter = pAdapter->Next) {
        unsigned ipv4 = 0;

        if (pAdapter->Type != MIB_IF_TYPE_ETHERNET
			&& pAdapter->Type != 71)
            continue;


        /* See if this adapter has a default-route/gateway configured */
        for (addr = &pAdapter->GatewayList; addr; addr = addr->Next) {
            struct ParsedIpAddress ipx;


            err = parse_ipv4_address(addr->IpAddress.String,
                                     0,
                                     0,
                                     &ipx);
            if (err) {
                ipv4 = ipx.address[0]<<24
                    | ipx.address[1]<<16
                    | ipx.address[2]<<8
                    | ipx.address[3];
                break;
            }

        }

        /*
         * When we reach the first adapter with an IP address, then
         * we'll use that one
         */
        if (ipv4) {
            sprintf_s(ifname, sizeof_ifname, "\\Device\\NPF_%s", pAdapter->AdapterName);
            break;
        }
    }

    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
}


/*****************************************************************************
 *****************************************************************************/
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <ctype.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <ctype.h>


#ifdef AF_LINK
#   include <net/if_dl.h>
#endif
#ifdef AF_PACKET
#   include <netpacket/packet.h>
#endif


unsigned
pixie_nic_get_mac(const char *ifname, unsigned char *mac)
{
    int err;
    struct ifaddrs *ifap;
    struct ifaddrs *p;
    
    
    /* Get the list of all network adapters */
    err = getifaddrs(&ifap);
    if (err != 0) {
        perror("getifaddrs");
        return 1;
    }
    
    /* Look through the list until we get our adapter */
    for (p = ifap; p; p = p->ifa_next) {
        if (strcmp(ifname, p->ifa_name) == 0
            && p->ifa_addr
            && p->ifa_addr->sa_family == AF_LINK)
            break;
    }
    if (p == NULL)
        goto error; /* not found */
    
    
    /* Return the address */
    {
        size_t len = 6;        
        struct sockaddr_dl *link;
        
        link = (struct sockaddr_dl *)p->ifa_addr;
        if (len > link->sdl_alen) {
            memset(mac, 0, 6);
            len = link->sdl_alen;
        }
        
        memcpy(     mac,
               link->sdl_data + link->sdl_nlen,
               len);
        
    }
    
    freeifaddrs(ifap);
    return 0;
error:
    freeifaddrs(ifap);
    return -1;
}


#define ROUNDUP(a)							\
((a) > 0 ? (1 + (((a) - 1) | (sizeof(int) - 1))) : sizeof(int))

static struct sockaddr *
get_rt_address(struct rt_msghdr *rtm, int desired)
{
    int i;
    int bitmask = rtm->rtm_addrs;
    struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
    
    for (i = 0; i < RTAX_MAX; i++) {
        if (bitmask & (1 << i)) {
            if ((1<<i) == desired)
                return sa;
            sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
        } else
            ;
    }
    return NULL;
    
}


unsigned
pixie_nic_get_default(char *ifname, size_t sizeof_ifname)
{
    int fd;
    int seq = time(0);
    int err;
    struct rt_msghdr *rtm;
    size_t sizeof_buffer;
    
    
    /*
     * Requests/responses from the kernel are done with an "rt_msghdr"
     * structure followed by an array of "sockaddr" structures.
     */
    sizeof_buffer = sizeof(*rtm) + sizeof(struct sockaddr_in)*16;
    rtm = (struct rt_msghdr *)malloc(sizeof_buffer);
    
    
    /*
     * Create a socket for querying the kernel
     */
    fd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (fd <= 0) {
        perror("socket(PF_ROUTE)");
        free(rtm);
        return errno;
    }
    
    
    /*
     * Format and send request to kernel
     */
    memset(rtm, 0, sizeof_buffer);
    rtm->rtm_msglen = sizeof_buffer;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_flags = RTF_UP | RTF_GATEWAY;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_seq = seq;
    rtm->rtm_addrs = RTA_DST | RTA_NETMASK | RTA_GATEWAY | RTA_IFP;
    
    err = write(fd, (char *)rtm, sizeof_buffer);
    if (err < 0 || err != sizeof_buffer) {
        perror("write(RTM_GET)");
        printf("----%u %u\n", err, (unsigned)sizeof_buffer);
        close(fd);
        free(rtm);
        return -1;
    }
    
    /*
     * Read responses until we find one that belongs to us
     */
    for (;;) {
        err = read(fd, (char *)rtm, sizeof_buffer);
        if (err <= 0)
            break;
        if (rtm->rtm_seq != seq) {
            printf("seq: %u %u\n", rtm->rtm_seq, seq);
            continue;
        }
        if (rtm->rtm_pid != getpid()) {
            printf("pid: %u %u\n", rtm->rtm_pid, getpid());
            continue;
        }
        break;
    }
    close(fd);
    
    //hexdump(rtm+1, err-sizeof(*rtm));
    //dump_rt_addresses(rtm);
    
    /*
     * Parse our data
     */
    {
        //struct sockaddr_in *sin;
        struct sockaddr_dl *sdl;
        
        sdl = (struct sockaddr_dl *)get_rt_address(rtm, RTA_IFP);
        if (sdl) {
            size_t len = sdl->sdl_nlen;
            if (len > sizeof_ifname-1)
                len = sizeof_ifname-1;
            memcpy(ifname, sdl->sdl_data, len);
            ifname[len] = 0;
            return 0;
        }

        /*sin = (struct sockaddr_in *)get_rt_address(rtm, RTA_GATEWAY);
        if (sin) {
            *ipv4 = ntohl(sin->sin_addr.s_addr);
            free(rtm);
            return 0;
        }*/
        
    }
    
    free(rtm);
    return -1;
}

unsigned
pixie_nic_get_ipv4(const char *ifname)
{
    int err;
    struct ifaddrs *ifap;
    struct ifaddrs *p;
    unsigned ip;
    
    
    /* Get the list of all network adapters */
    err = getifaddrs(&ifap);
    if (err != 0) {
        perror("getifaddrs");
        return 0;
    }
    
    /* Look through the list until we get our adapter */
    for (p = ifap; p; p = p->ifa_next) {
        if (strcmp(ifname, p->ifa_name) == 0
            && p->ifa_addr
            && p->ifa_addr->sa_family == AF_INET)
            break;
    }
    if (p == NULL)
        goto error; /* not found */
    
    /* Return the address */
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
        
        ip = ntohl(sin->sin_addr.s_addr);
    }

    freeifaddrs(ifap);
    return ip;
error:
    freeifaddrs(ifap);
    return 0;
}

static void
hexdump(const void *v, size_t len)
{
    const unsigned char *p = (const unsigned char *)v;
    size_t i;
    
    
    for (i=0; i<len; i += 16) {
        size_t j;
        
        for (j=i; j<i+16 && j<len; j++)
            printf("%02x ", p[j]);
        for (;j<i+16; j++)
            printf("   ");
        printf("  ");
        for (j=i; j<i+16 && j<len; j++)
            if (isprint(p[j]) && !isspace(p[j]))
                printf("%c", p[j]);
            else
                printf(".");
        printf("\n");
    }
}

#if 0
#define RTA_DST         0x1     /* destination sockaddr present */
#define RTA_GATEWAY     0x2     /* gateway sockaddr present */
#define RTA_NETMASK     0x4     /* netmask sockaddr present */
#define RTA_GENMASK     0x8     /* cloning mask sockaddr present */
#define RTA_IFP         0x10    /* interface name sockaddr present */
#define RTA_IFA         0x20    /* interface addr sockaddr present */
#define RTA_AUTHOR      0x40    /* sockaddr for author of redirect */
#define RTA_BRD         0x80    /* for NEWADDR, broadcast or p-p dest addr */
#endif

void
dump_rt_addresses(struct rt_msghdr *rtm)
{
    int i;
    int bitmask = rtm->rtm_addrs;
    struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
    
    for (i = 0; i < RTAX_MAX; i++) {
        if (bitmask & (1 << i)) {
            printf("b=%u fam=%u len=%u\n", (1<<i), sa->sa_family, sa->sa_len);
            hexdump(sa, sa->sa_len + sizeof(sa->sa_family));
            sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
        } else
            ;
    }
}

int rawsock_get_default_gateway(const char *ifname, unsigned *ipv4)
{
    int fd;
    int seq = time(0);
    int err;
    struct rt_msghdr *rtm;
    size_t sizeof_buffer;


    /*
     * Requests/responses from the kernel are done with an "rt_msghdr"
     * structure followed by an array of "sockaddr" structures.
     */
    sizeof_buffer = sizeof(*rtm) + sizeof(struct sockaddr_in)*16;
    rtm = (struct rt_msghdr *)malloc(sizeof_buffer);


    /*
     * Create a socket for querying the kernel
     */
    fd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (fd <= 0) {
        perror("socket(PF_ROUTE)");
        free(rtm);
        return errno;
    }


    /*
     * Format and send request to kernel
     */
    memset(rtm, 0, sizeof_buffer);
    rtm->rtm_msglen = sizeof_buffer;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_flags = RTF_UP | RTF_GATEWAY;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_seq = seq;
    rtm->rtm_addrs = RTA_DST | RTA_NETMASK | RTA_GATEWAY | RTA_IFP;

    err = write(fd, (char *)rtm, sizeof_buffer);
    if (err < 0 || err != sizeof_buffer) {
        perror("write(RTM_GET)");
        printf("----%u %u\n", err, (unsigned)sizeof_buffer);
        close(fd);
        free(rtm);
        return -1;
    }

    /*
     * Read responses until we find one that belongs to us
     */
    for (;;) {
        err = read(fd, (char *)rtm, sizeof_buffer);
        if (err <= 0)
            break;
        if (rtm->rtm_seq != seq) {
            printf("seq: %u %u\n", rtm->rtm_seq, seq);
            continue;
        }
        if (rtm->rtm_pid != getpid()) {
            printf("pid: %u %u\n", rtm->rtm_pid, getpid());
            continue;
        }
        break;
    }
    close(fd);

    //hexdump(rtm+1, err-sizeof(*rtm));
    //dump_rt_addresses(rtm);
    
    /*
     * Parse our data
     */
    {
        struct sockaddr_in *sin;
        struct sockaddr_dl *sdl;
        
        sdl = (struct sockaddr_dl *)get_rt_address(rtm, RTA_IFP);
        if (sdl) {
            //hexdump(sdl, sdl->sdl_len);
            //printf("%.*s\n", sdl->sdl_nlen, sdl->sdl_data);
            if (memcmp(ifname, sdl->sdl_data, sdl->sdl_nlen) != 0) {
                fprintf(stderr, "ERROR: ROUTE DOESN'T MATCH INTERFACE\n");
                fprintf(stderr, "YOU'LL HAVE TO SET --router-mac MANUALLY\n");
                exit(1);
            }
        }
        
        sin = (struct sockaddr_in *)get_rt_address(rtm, RTA_GATEWAY);
        if (sin) {
            *ipv4 = ntohl(sin->sin_addr.s_addr);
            free(rtm);
            return 0;
        }
        
    }

    free(rtm);
    return -1;
}

#endif

