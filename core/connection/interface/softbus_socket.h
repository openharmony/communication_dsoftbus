/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_SOCKET_H
#define SOFTBUS_SOCKET_H

#include <sys/types.h>
#include <sys/uio.h>

#include "softbus_conn_interface.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifndef SOFTBUS_TEMP_FAILURE_RETRY
#define SOFTBUS_TEMP_FAILURE_RETRY(expression)              \
    (__extension__({                                        \
        long int __result;                                  \
        do {                                                \
            __result = (long int)(expression);              \
        } while (__result == SOFTBUS_ADAPTER_SOCKET_EINTR); \
        __result;                                           \
    }))
#endif

enum SocketEvent {
    SOFTBUS_SOCKET_OUT,       // writable
    SOFTBUS_SOCKET_IN,        // readable
    SOFTBUS_SOCKET_EXCEPTION, // exception
};

typedef struct {
    char addr[MAX_SOCKET_ADDR_LEN];
    int32_t port;
} SocketAddr;

typedef struct SocketInterface {
    const char *name;
    const ProtocolType type;
    int32_t (*GetSockPort)(int32_t fd);
    int32_t (*OpenServerSocket)(const LocalListenerInfo *option);
    int32_t (*OpenClientSocket)(const ConnectOption *option, const char *bindAddr, bool isNonBlock);
    int32_t (*AcceptClient)(int32_t fd, ConnectOption *clientAddr, int32_t *cfd);
} SocketInterface;

int32_t ConnInitSockets(void);
void ConnDeinitSockets(void);

const SocketInterface *GetSocketInterface(ProtocolType protocolType);

int32_t RegistSocketProtocol(const SocketInterface *interface);

int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock);

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout);
ssize_t ConnRecvSocketData(int32_t fd, char *buf, size_t len, int32_t timeout);
void ConnCloseSocket(int32_t fd);
void ConnShutdownSocket(int32_t fd);
int32_t ConnSetTcpKeepAlive(int32_t fd, int32_t seconds);
int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millSec);

int32_t ConnToggleNonBlockMode(int32_t fd, bool isNonBlock);
int32_t ConnGetSocketError(int32_t fd);
int32_t ConnGetLocalSocketPort(int32_t fd);
int32_t ConnGetPeerSocketAddr(int32_t fd, SocketAddr *socketAddr);

int32_t ConnPreAssignPort(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
