#ifndef PIXIE_SOCKETS_H
#define PIXIE_SOCKETS_H

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


#endif
