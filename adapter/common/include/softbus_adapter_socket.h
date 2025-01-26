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
#include "softbus_adapter_define.h"
#include "softbus_adapter_timer.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SA_DATA_SIZE (26)
#define ADDR_IN6_8_SIZE (16)
#define ADDR_IN6_16_SIZE (8)
#define ADDR_IN6_32_SIZE (4)
#define IF_NAME_SIZE (16)

#if defined(__aarch64__) || defined(__x86_64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define ADDR_IN_RESER_SIZE (4)
#else
#define ADDR_IN_RESER_SIZE (8)
#endif

/* sys/socket.h */
#define SOFTBUS_PF_UNSPEC SOFTBUS_PF_UNSPEC_
#define SOFTBUS_AF_UNSPEC SOFTBUS_AF_UNSPEC_

#define SOFTBUS_PF_INET SOFTBUS_PF_INET_
#define SOFTBUS_AF_INET SOFTBUS_AF_INET_

#define SOFTBUS_PF_INET6 SOFTBUS_PF_INET6_
#define SOFTBUS_AF_INET6 SOFTBUS_AF_INET6_

#define SOFTBUS_PF_NETLINK SOFTBUS_PF_NETLINK_
#define SOFTBUS_AF_NETLINK SOFTBUS_AF_NETLINK_

#define SOFTBUS_SOCK_STREAM SOFTBUS_SOCK_STREAM_
#define SOFTBUS_SOCK_DGRAM SOFTBUS_SOCK_DGRAM_
#define SOFTBUS_SOCK_RAW SOFTBUS_SOCK_RAW_

#define SOFTBUS_SOCK_CLOEXEC SOFTBUS_SOCK_CLOEXEC_
#define SOFTBUS_SOCK_NONBLOCK SOFTBUS_SOCK_NONBLOCK_

#define SOFTBUS_SOL_SOCKET SOFTBUS_SOL_SOCKET_

#define SOFTBUS_SO_REUSEADDR SOFTBUS_SO_REUSEADDR_
#define SOFTBUS_SO_RCVBUF SOFTBUS_SO_RCVBUF_
#define SOFTBUS_SO_SNDBUF SOFTBUS_SO_SNDBUF_
#define SOFTBUS_SO_KEEPALIVE SOFTBUS_SO_KEEPALIVE_
#define SOFTBUS_SO_REUSEPORT SOFTBUS_SO_REUSEPORT_
#define SOFTBUS_SO_RCVBUFFORCE SOFTBUS_SO_RCVBUFFORCE_
#define SOFTBUS_SO_BINDTODEVICE SOFTBUS_SO_BINDTODEVICE_

#define SOFTBUS_TCP_KEEPIDLE SOFTBUS_TCP_KEEPIDLE_
#define SOFTBUS_TCP_KEEPINTVL SOFTBUS_TCP_KEEPINTVL_
#define SOFTBUS_TCP_KEEPCNT SOFTBUS_TCP_KEEPCNT_
#define SOFTBUS_TCP_USER_TIMEOUT SOFTBUS_TCP_USER_TIMEOUT_

#define SOFTBUS_SHUT_RD SOFTBUS_SHUT_RD_
#define SOFTBUS_SHUT_WR SOFTBUS_SHUT_WR_
#define SOFTBUS_SHUT_RDWR SOFTBUS_SHUT_RDWR_

/* netinet/in.h */
#define SOFTBUS_IPPROTO_IP SOFTBUS_IPPROTO_IP_
#define SOFTBUS_IPPROTO_TCP SOFTBUS_IPPROTO_TCP_

#define SOFTBUS_IP_TOS SOFTBUS_IP_TOS_

/* netinet/tcp.h */
#define SOFTBUS_TCP_NODELAY SOFTBUS_TCP_NODELAY_

/* fcntl.h */
#define SOFTBUS_F_GETFL SOFTBUS_F_GETFL_
#define SOFTBUS_F_SETFL SOFTBUS_F_SETFL_

#define SOFTBUS_O_NONBLOCK SOFTBUS_O_NONBLOCK_

/* select.h */
/* linux support 1024, liteos support 640 */
#define SOFTBUS_FD_SETSIZE SOFTBUS_FD_SETSIZE_

typedef SoftBusSysTime SoftBusSockTimeOut;
/* netinet/in.h */
typedef struct {
    uint16_t saFamily; /* address family */
    char saData[SA_DATA_SIZE];
} SoftBusSockAddr;

#pragma pack (1)
typedef struct {
    unsigned long sAddr;
} SoftBusInAddr;

typedef struct {
    uint16_t sinFamily; /* address family */
    uint16_t sinPort; /* Port number */
    SoftBusInAddr sinAddr; /* Internet address */
    unsigned char sinZero[ADDR_IN_RESER_SIZE]; /* Same size as struct sockaddr */
} SoftBusSockAddrIn;

typedef struct {
    union {
        uint8_t sA6ddr8[ADDR_IN6_8_SIZE];
        uint8_t sA6ddr16[ADDR_IN6_16_SIZE];
        uint8_t sA6ddr32[ADDR_IN6_32_SIZE];
    } sA6ddr;
} SoftBusIn6Addr;

typedef struct {
    uint16_t sin6Family; /* Ipv6 address family */
    uint16_t sin6Port; /* Ipv6 Port number */
    uint32_t sin6FlowInfo; /* Ipv6 flow info */
    SoftBusIn6Addr sin6Addr; /* Ipv6 address */
    uint32_t sin6ScopeId; /* Ipv6 scope id */
} SoftBusSockAddrIn6;
#pragma pack ()

typedef struct {
    uint32_t fdsCount;
    unsigned long fdsBits[SOFTBUS_FD_SETSIZE / 8 / sizeof(long)];
} SoftBusFdSet;

int32_t SoftBusSocketCreate(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd);
int32_t SoftBusSocketSetOpt(int32_t socketFd, int32_t level, int32_t optName,  const void *optVal, int32_t optLen);
int32_t SoftBusSocketGetOpt(int32_t socketFd, int32_t level, int32_t optName,  void *optVal, int32_t *optLen);
int32_t SoftBusSocketGetLocalName(int32_t socketFd, SoftBusSockAddr *addr);
int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr);

int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen);
int32_t SoftBusSocketListen(int32_t socketFd, int32_t backLog);
int32_t SoftBusSocketAccept(int32_t socketFd, SoftBusSockAddr *addr, int32_t *acceptFd);
int32_t SoftBusSocketConnect(int32_t socketFd, const SoftBusSockAddr *addr, int32_t addrLen);

void SoftBusSocketFdZero(SoftBusFdSet *set);
void SoftBusSocketFdSet(int32_t socketFd, SoftBusFdSet *set);
void SoftBusSocketFdClr(int32_t socketFd, SoftBusFdSet *set);
int32_t SoftBusSocketFdIsset(int32_t socketFd, SoftBusFdSet *set);

int32_t SoftBusSocketSelect(int32_t nfds, SoftBusFdSet *readFds, SoftBusFdSet *writeFds, SoftBusFdSet *exceptFds,
    SoftBusSockTimeOut *timeOut);
int32_t SoftBusSocketIoctl(int32_t socketFd, long cmd, void *argp);
int32_t SoftBusSocketFcntl(int32_t socketFd, long cmd, long flag);

int32_t SoftBusSocketSend(int32_t socketFd, const void *buf, uint32_t len, uint32_t flags);
int32_t SoftBusSocketSendTo(int32_t socketFd, const void *buf, uint32_t len, int32_t flags,
    const SoftBusSockAddr *toAddr, int32_t toAddrLen);

int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, uint32_t len, int32_t flags);
int32_t SoftBusSocketRecvFrom(int32_t socketFd, void *buf, uint32_t len, int32_t flags, SoftBusSockAddr *fromAddr,
    int32_t *fromAddrLen);


int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how);
int32_t SoftBusSocketClose(int32_t socketFd);

int32_t SoftBusInetPtoN(int32_t af, const char *src, void *dst);
const char *SoftBusInetNtoP(int32_t af, const void *src, char *dst, int32_t size);

uint32_t SoftBusHtoNl(uint32_t hostlong);
uint16_t SoftBusHtoNs(uint16_t hostshort);
uint32_t SoftBusNtoHl(uint32_t netlong);
uint16_t SoftBusNtoHs(uint16_t netshort);

/* host to little-endian */
uint16_t SoftBusHtoLs(uint16_t value);
uint32_t SoftBusHtoLl(uint32_t value);
uint64_t SoftBusHtoLll(uint64_t value);
/* little-endian to host */
uint16_t SoftBusLtoHs(uint16_t value);
uint32_t SoftBusLtoHl(uint32_t value);
uint64_t SoftBusLtoHll(uint64_t value);
uint16_t SoftBusLEtoBEs(uint16_t value);
uint16_t SoftBusBEtoLEs(uint16_t value);

uint32_t SoftBusInetAddr(const char *cp);
uint32_t SoftBusIfNameToIndex(const char *name);
int32_t SoftBusIndexToIfName(int32_t index, char *ifname, uint32_t nameLen);

int32_t SoftBusSocketGetError(int32_t socketFd);
int32_t GetErrCodeBySocketErr(int32_t transErrCode);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_ADAPTER_SOCKET_H
