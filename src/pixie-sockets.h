#ifndef PIXIE_SOCKETS_H
#define PIXIE_SOCKETS_H
#if defined(_MSC_VER)
#pragma warning(disable:6386)
#endif

#if defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
#define WSA(err) WSA##err
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4389)
#pragma warning(disable:4127)
#endif
typedef int socklen_t;
#else
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#define WSAGetLastError() (errno)
#define SOCKET int
#define WSA(err) (err)
#define closesocket(fd) close(fd)
#endif


#endif
