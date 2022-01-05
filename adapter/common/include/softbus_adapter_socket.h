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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/types.h>
#include <arpa/inet.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct sockaddr SoftBusSockAddr;
int SoftBusSocketCreate(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd);
int32_t SoftBusSocketSetOpt(int32_t socketFd, int32_t level, int32_t optName,  const void *optVal, int32_t optLen);
int32_t SoftBusSocketGetOpt(int32_t socketFd, int32_t level, int32_t optName,  void *optVal, int32_t *optLen);
int32_t SoftBusSocketGetLocalName(int32_t socketFd, struct sockaddr *addr, int32_t *addrLen);
int32_t SoftBusSocketGetPeerName(int32_t socketFd, struct sockaddr *addr, int32_t *addrLen);

int32_t SoftBusSocketBind(int32_t socketFd, struct sockaddr *addr, int32_t addrLen);
int32_t SoftBusSocketListen(int32_t socketFd, int32_t backLog);
int32_t SoftBusSocketAccept(int32_t socketFd, struct sockaddr *addr, int32_t *addrLen, int32_t *acceptFd);
int32_t SoftBusSocketConnect(int32_t socketFd, const struct sockaddr *addr, int32_t addrLen);

void SoftBusSocketFdZero(fd_set *set);
void SoftBusSocketFdSet(int32_t socketFd, fd_set *set);
void SoftBusSocketFdClr(int32_t socketFd, fd_set *set);
int32_t SoftBusSocketFdIsset(int32_t socketFd, fd_set *set);

int32_t SoftBusSocketSelect(int32_t nfds, fd_set *readFds, fd_set *writeFds, fd_set *exceptFds, struct timeval *timeOut);
int32_t SoftBusSocketIoctl(int32_t socketFd, long cmd, void *argp);

int32_t SoftBusSocketSend(int32_t socketFd, const void *buf, unsigned int32_t len, int32_t flags);
int32_t SoftBusSocketSendTo(int32_t socketFd, const void *buf, unsigned int32_t len, int32_t flags, const struct sockaddr
    *toAddr, int32_t toAddrLen);

int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, unsigned int32_t len, int32_t flags);
int32_t SoftBusSocketRecvFrom(int32_t socketFd, void *buf, unsigned int32_t len, int32_t flags, struct sockaddr 
    *fromAddr, int32_t *fromAddrLen);


int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how);
int32_t SoftBusSocketClose(int32_t socketFd);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
