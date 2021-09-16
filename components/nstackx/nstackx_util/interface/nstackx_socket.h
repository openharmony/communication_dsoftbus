/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_SOCKET_H
#define NSTACKX_SOCKET_H

#include "sys_common_header.h"
#include "nstackx_common_header.h"

typedef enum SocketProtocol {
    NSTACKX_PROTOCOL_TCP = 0,
    NSTACKX_PROTOCOL_UDP,
    NSTACKX_PROTOCOL_D2D
} SocketProtocol;

typedef struct Socket {
    SocketProtocol protocol;
    uint8_t isServer;
    SocketDesc sockfd;
    struct sockaddr_in dstAddr;
    struct sockaddr_in srcAddr;
} Socket;

int32_t SocketModuleInit(void);
void SocketModuleClean(void);
int32_t SetSocketNonBlock(SocketDesc fd);
int32_t SocketOpInProgress(void);
int32_t SocketOpWouldBlock(void);
int32_t CheckSocketError(void);
Socket *ClientSocket(SocketProtocol protocol, const struct sockaddr_in *sockAddr);
Socket *ServerSocket(SocketProtocol protocol, const struct sockaddr_in *sockAddr);
void CloseSocket(Socket *socket);
Socket *AcceptSocket(Socket *serverSocket);
int32_t SocketSend(const Socket *socket, const uint8_t *buffer, size_t length);
int32_t SocketSendEx(const Socket *socket, uint16_t mss, const struct iovec *iov, uint32_t cnt);
void CheckGSOSupport(void);
int32_t SupportGSO(void);
int32_t SocketRecv(Socket *socket, uint8_t *buffer, size_t length, struct sockaddr_in *srcAddr,
                   const socklen_t *addrLen);
Socket *ClientSocketWithTargetDev(SocketProtocol protocol, const struct sockaddr_in *sockAddr,
                                  const char *localInterface);

#endif  /* NSTACKX_SOCKET_H */
