// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#if defined(HAVE_BITCOIN_CONFIG_H)
#include <bitcoin-config.h>
#endif

#include <type_traits>

#ifdef WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifdef FD_SETSIZE
#undef FD_SETSIZE // prevent redefinition compiler warning
#endif
#define FD_SETSIZE 1024 // max number of fds in fd_set

#include <winsock2.h> // Must be included before mswsock.h and windows.h

#include <mswsock.h>
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <climits>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef WIN32
using SOCKET = unsigned int;
#include <errno.h>
#define WSAGetLastError() errno
#define WSAEINVAL EINVAL
#define WSAEALREADY EALREADY
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAEMSGSIZE EMSGSIZE
#define WSAEINTR EINTR
#define WSAEINPROGRESS EINPROGRESS
#define WSAEADDRINUSE EADDRINUSE
#define WSAENOTSOCK EBADF
#define INVALID_SOCKET (SOCKET)(~0)
#define SOCKET_ERROR -1
#endif

#ifdef WIN32
#ifndef S_IRUSR
#define S_IRUSR 0400
#define S_IWUSR 0200
#endif
#else
#define MAX_PATH 1024
#endif

#ifndef WIN32
using sockopt_arg_type = void *;
#else
using sockopt_arg_type = char *;
#endif

inline bool IsSelectableSocket(const SOCKET &s [[maybe_unused]]) {
#ifdef WIN32
    return true;
#else
    return s < FD_SETSIZE;
#endif
}
