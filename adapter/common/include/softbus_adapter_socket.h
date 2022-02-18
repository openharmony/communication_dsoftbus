/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SOFTBUS_ADAPTER_SOCKET_H
#define SOFTBUS_ADAPTER_SOCKET_H

#include <stdint.h>
#include <sys/select.h>
#include <unistd.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SA_DATA_SIZE (14)
#define ADDR_IN_RESER_SIZE (8)

/* sys/socket.h */
#define SOFTBUS_PF_INET (2)
#define SOFTBUS_AF_INET SOFTBUS_PF_INET

#define SOFTBUS_SOCK_STREAM (1)
#define SOFTBUS_SOCK_DGRAM (2)

#define SOFTBUS_SOCK_CLOEXEC (02000000)
#define SOFTBUS_SOCK_NONBLOCK (04000)

#define SOFTBUS_SOL_SOCKET (1)

#define SOFTBUS_SO_REUSEADDR (2)
#define SOFTBUS_SO_KEEPALIVE (9)
#define SOFTBUS_SO_REUSEPORT (15)

#define SOFTBUS_TCP_KEEPIDLE (4)
#define SOFTBUS_TCP_KEEPINTVL (5)
#define SOFTBUS_TCP_KEEPCNT (6)

#define SOFTBUS_SHUT_RD (0)
#define SOFTBUS_SHUT_WR (1)
#define SOFTBUS_SHUT_RDWR (2)

/* netinet/in.h */
#define SOFTBUS_IPPROTO_IP (0)
#define SOFTBUS_IPPROTO_TCP (6)

#define SOFTBUS_IP_TOS (1)

/* netinet/tcp.h */
#define SOFTBUS_TCP_NODELAY (1)

/* fcntl.h */
#define SOFTBUS_F_GETFL (3)
#define SOFTBUS_F_SETFL (4)

#define SOFTBUS_O_NONBLOCK (04000)

/* select.h */
/* linux support 1024, liteos support 640 */
#define SOFTBUS_FD_SETSIZE (1024)

/* netinet/in.h */
typedef struct {
    unsigned short saFamily; /* address family */
    char saData[SA_DATA_SIZE];
} SoftBusSockAddr;

typedef struct {
    unsigned long sAddr;
} SoftBusInAddr;

typedef struct {
    unsigned short sinFamily; /* address family */
    unsigned short sinPort; /* Port number */
    SoftBusInAddr sinAddr; /* Internet address */
    unsigned char sinZero[ADDR_IN_RESER_SIZE]; /* Same size as struct sockaddr */
} SoftBusSockAddrIn;

typedef struct {
    uint32_t fdsCount;
    unsigned long fdsBits[SOFTBUS_FD_SETSIZE / 8 / sizeof(long)];
} SoftBusFdSet;

int32_t SoftBusSocketCreate(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd);
int32_t SoftBusSocketSetOpt(int32_t socketFd, int32_t level, int32_t optName,  const void *optVal, int32_t optLen);
int32_t SoftBusSocketGetOpt(int32_t socketFd, int32_t level, int32_t optName,  void *optVal, int32_t *optLen);
int32_t SoftBusSocketGetLocalName(int32_t socketFd, SoftBusSockAddr *addr, int32_t *addrLen);
int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr, int32_t *addrLen);

int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen);
int32_t SoftBusSocketListen(int32_t socketFd, int32_t backLog);
int32_t SoftBusSocketAccept(int32_t socketFd, SoftBusSockAddr *addr, int32_t *addrLen,
    int32_t *acceptFd);
int32_t SoftBusSocketConnect(int32_t socketFd, const SoftBusSockAddr *addr, int32_t addrLen);

void SoftBusSocketFdZero(SoftBusFdSet *set);
void SoftBusSocketFdSet(int32_t socketFd, SoftBusFdSet *set);
void SoftBusSocketFdClr(int32_t socketFd, SoftBusFdSet *set);
int32_t SoftBusSocketFdIsset(int32_t socketFd, SoftBusFdSet *set);

int32_t SoftBusSocketSelect(int32_t nfds, SoftBusFdSet *readFds, SoftBusFdSet *writeFds, SoftBusFdSet
    *exceptFds, struct timeval *timeOut);
int32_t SoftBusSocketIoctl(int32_t socketFd, long cmd, void *argp);
int32_t SoftBusSocketFcntl(int32_t socketFd, long cmd, long flag);

int32_t SoftBusSocketSend(int32_t socketFd, const void *buf, uint32_t len, int32_t flags);
int32_t SoftBusSocketSendTo(int32_t socketFd, const void *buf, uint32_t len, int32_t flags, const SoftBusSockAddr
    *toAddr, int32_t toAddrLen);

int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, uint32_t len, int32_t flags);
int32_t SoftBusSocketRecvFrom(int32_t socketFd, void *buf, uint32_t len, int32_t flags, SoftBusSockAddr
    *fromAddr, int32_t *fromAddrLen);


int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how);
int32_t SoftBusSocketClose(int32_t socketFd);

int32_t SoftBusInetPtoN(int32_t af, const char *src, void *dst);
const char *SoftBusInetNtoP(int32_t af, const void* src, char *dst, int32_t size);

uint32_t SoftBusHtoNl(uint32_t hostlong);
uint16_t SoftBusHtoNs(uint16_t hostshort);
uint32_t SoftBusNtoHl(uint32_t netlong);
uint16_t SoftBusNtoHs(uint16_t netshort);

uint32_t SoftBusInetAddr(const char *cp);

int32_t SoftBusSocketGetError(int32_t socketFd);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
