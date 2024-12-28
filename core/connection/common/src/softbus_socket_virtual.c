/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "softbus_socket.h"

#include "conn_log.h"

static int32_t GetSockPort(int32_t fd)
{
    (void)fd;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OpenServerSocket(const LocalListenerInfo *option)
{
    (void)option;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock)
{
    (void)option;
    (void)bindAddr;
    (void)isNonBlock;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t AcceptClient(int32_t fd, ConnectOption *clientAddr, int32_t *cfd)
{
    (void)fd;
    (void)clientAddr;
    (void)cfd;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

static const SocketInterface g_socketInterfaces = {
    .name = "",
    .type = LNN_PROTOCOL_IP,
    .GetSockPort = GetSockPort,
    .OpenServerSocket = OpenServerSocket,
    .OpenClientSocket = OpenClientSocket,
    .AcceptClient = AcceptClient,
};

const SocketInterface *GetSocketInterface(ProtocolType protocolType)
{
    return &g_socketInterfaces;
}

int32_t ConnInitSockets(void)
{
    CONN_LOGE(CONN_COMMON, "not support");
	// in order to init completely
    return SOFTBUS_OK;
}

void ConnDeinitSockets(void)
{
    CONN_LOGE(CONN_COMMON, "not support");
}

bool IsHmlIpAddr(const char *ip)
{
    (void)ip;
    CONN_LOGE(CONN_COMMON, "not support");
    return false;
}

int32_t ConnGetSocketError(int32_t fd)
{
    (void)fd;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

void ConnShutdownSocket(int32_t fd)
{
    (void)fd;
    CONN_LOGE(CONN_COMMON, "not support");
}

void ConnCloseSocket(int32_t fd)
{
    (void)fd;
    CONN_LOGE(CONN_COMMON, "not support");
}

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    (void)fd;
    (void)buf;
    (void)len;
    (void)timeout;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

ssize_t ConnRecvSocketData(int32_t fd, char *buf, size_t len, int32_t timeout)
{
    (void)fd;
    (void)buf;
    (void)len;
    (void)timeout;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetDomainByAddr(const char *addr)
{
    (void)addr;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t Ipv4AddrToAddrIn(SoftBusSockAddrIn *addrIn, const char *ip, uint16_t port)
{
    (void)addrIn;
    (void)ip;
    (void)port;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t Ipv6AddrToAddrIn(SoftBusSockAddrIn6 *addrIn6, const char *ip, uint16_t port)
{
    (void)addrIn6;
    (void)ip;
    (void)port;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock)
{
    (void)option;
    (void)bindAddr;
    (void)isNonBlock;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ConnGetPeerSocketAddr(int32_t fd, SocketAddr *socketAddr)
{
    (void)fd;
    (void)socketAddr;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ConnGetLocalSocketPort(int32_t fd)
{
    (void)fd;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t Ipv6AddrInToAddr(SoftBusSockAddrIn6 *addrIn6, char *addr, int32_t addrLen)
{
    (void)addrIn6;
    (void)addr;
    (void)addrLen;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}