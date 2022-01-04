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
int SoftBusSocketCreate(int domain, int type, int protocol, int *socketFd);
int SoftBusSocketSetOpt(int socketFd, int level, int optName,  const void *optVal, int optLen);
int SoftBusSocketGetOpt(int socketFd, int level, int optName,  void *optVal, int *optLen);
int SoftBusSocketGetLocalName(int socketFd, struct sockaddr *addr, int *addrLen);
int SoftBusSocketGetPeerName(int socketFd, struct sockaddr *addr, int *addrLen);

int SoftBusSocketBind(int socketFd, struct sockaddr *addr, int addrLen);
int SoftBusSocketListen(int socketFd, int backLog);
int SoftBusSocketAccept(int socketFd, struct sockaddr *addr, int *addrLen, int *acceptFd);
int SoftBusSocketConnect(int socketFd, const struct sockaddr *addr, int addrLen);

void SoftBusSocketFdZero(fd_set *set);
void SoftBusSocketFdSet(int socketFd, fd_set *set);
void SoftBusSocketFdClr(int socketFd, fd_set *set);
int SoftBusSocketFdIsset(int socketFd, fd_set *set);

int SoftBusSocketSelect(int nfds, fd_set *readFds, fd_set *writeFds, fd_set *exceptFds, struct timeval *timeOut);
int SoftBusSocketIoctl(int socketFd, long cmd, void *argp);

int SoftBusSocketSend(int socketFd, const void *buf, unsigned int len, int flags);
int SoftBusSocketSendTo(int socketFd, const void *buf, unsigned int len, int flags, const struct sockaddr
    *toAddr, int toAddrLen);

int SoftBusSocketRecv(int socketFd, void *buf, unsigned int len, int flags);
int SoftBusSocketRecvFrom(int socketFd, void *buf, unsigned int len, int flags, struct sockaddr 
    *fromAddr, int *fromAddrLen);


int SoftBusSocketShutDown(int socketFd, int how);
int SoftBusSocketClose(int socketFd);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
