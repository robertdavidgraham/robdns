#include "main-conf.h"
#include "db.h"
#include "logger.h"
#include "main-server-socket.h"
#include "proto-dns.h"
#include <stdio.h>
#include <errno.h>
#include "string_s.h"
#include "proto-dns-compressor.h"
#include "proto-dns-formatter.h"
#include "resolver.h"

#if defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
#define WSA(err) WSA##err
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
#define WSA(err) (err)
#endif

/******************************************************************************
 * This is the mail loop when running over sockets, receiving packets and
 * sending responses.
 ******************************************************************************/
void
sockets_thread(struct Core *conf)
{
    int err;
    SOCKET fd;
    struct sockaddr_in6 sin;
    static const unsigned port = 5333;
    
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
    
    /*
     * Create a socket for incoming UDP packets. By specifying IPv6, we are
     * actually going to allow both IPv4 and IPv6.
     */
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd <= 0) {
        LOG(0, "FAIL: couldn't create socket %u\n", WSAGetLastError());
        return;
    }
    
    /*
     * Set the 'reuse' feature of the socket, otherwise restarting the process
     * requires a wait before binding back to the same port number
     */
    {
        int on = 1;
        err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on,sizeof(on));
        if (err < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            exit(1); 
        }
    }

    /*
     * Enable both IPv4 and IPv6 to be used on the same sockets. This appears to
     * be needed for Windows, but not needed for Mac OS X.
     */
    {
        int on = 0;
        err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof(on)); 
        if (err < 0) {
            perror("setsockopt(IPV6_V6ONLY) failed");
            exit(1); 
        }
    }
    
    
    /*
     * Listen on any IPv4 or IPv6 address in the system
     */
    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    sin.sin6_addr = in6addr_any;
    sin.sin6_port = htons(port);
    err = bind(fd, (struct sockaddr*)&sin, sizeof(sin));
    if (err) {
        switch (WSAGetLastError()) {
            case WSA(EACCES):
                LOG(0, "FAIL: couldn't bind to port %u: %s\n", port, 
                    "access denied");
                if (port <= 1024)
                    LOG(0, "  hint... need to be root for ports below 1024\n");
                break;
            case WSA(EADDRINUSE):
                LOG(0, "FAIL: couldn't bind to port %u: %s\n", port, 
                    "address in use");
                LOG(0, "  hint... some other server is running on that port\n");
                break;
            default:
                LOG(0, "FAIL: couldn't bind to port %u: %u\n", port,
                    WSAGetLastError());
        }
        exit(1);
    } else {
        fprintf(stderr, "UDP port: %u\n", port);
    }
    
    /*
     * Sit in loop processing incoming UDP packets
     */
    for (;;) {
        unsigned char buf[2048];
        int bytes_received;
        socklen_t sizeof_sin = sizeof(sin);
        struct DNS_Incoming request[1];
        struct DNS_OutgoingResponse response[1];
        struct Packet pkt;
        unsigned char buf2[2048];
        
        /*
         * 1. receive 'packet'
         */
        bytes_received = recvfrom(fd, 
                                  (char*)buf, sizeof(buf),
                                  0, 
                                  (struct sockaddr*)&sin, &sizeof_sin);
        if (bytes_received == 0)
            continue;

        
        /*
         * 2. parse 'packet' into a 'request'
         */
        proto_dns_parse(request, buf, 0, bytes_received);
        if (!request->is_valid)
            continue;


        /*
         * 3. resolve 'request' into a 'repsonse'
         */
        resolver_init(response, 
                      request->query_name.name, 
                      request->query_name.length, 
                      request->query_type,
                      request->id,
                      request->opcode);
            
        resolver_algorithm(conf->db, response, request);
            

        /*
         * 4. format the 'response' into a 'packet'
         */
        pkt.buf = buf2;
        pkt.max = sizeof(buf2);
        pkt.offset = 0;
        dns_format_response(response, &pkt);
            
        /*
         * 5. Transmit the 'packet'
         */
        if (pkt.offset < pkt.max) {
            sendto(fd, 
                   (char*)pkt.buf, pkt.offset, 0,
                   (struct sockaddr*)&sin,
                   sizeof_sin);
        }
    }
}


