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

#include "softbus_tcp_socket.h"

#include <securec.h>
#include "conn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_conn_common.h"
#include "softbus_errcode.h"
#include "softbus_socket.h"

#define M_BYTES                     0x100000
#define SEND_BUF_SIZE               (4 * M_BYTES) // 4M
#define RECV_BUF_SIZE               (6 * M_BYTES) // 6M
#define USER_TIMEOUT_MS             (15 * 1000)   // 15s
#define SOFTBUS_TCP_USER_TIME USER_TIMEOUT_MS
#define SOFTBUS_CONN_TCP_USER_TIME  (35 * 1000)   // 35s
#define ADDR_FEATURE_IPV6           ':'
#define ADDR_SPLIT_IPV6             "%"

#ifndef __LITEOS_M__
static int SetReusePort(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEPORT, &on, sizeof(on));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set SO_REUSEPORT failed");
        return -1;
    }
    return 0;
}
#endif

static int SetReuseAddr(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &on, sizeof(on));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set SO_REUSEADDR failed");
        return -1;
    }
    return 0;
}

static int SetNoDelay(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_NODELAY, &on, sizeof(on));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set TCP_NODELAY failed");
        return -1;
    }
    return 0;
}

#ifndef TCP_QUICK_START
#define TCP_QUICK_START 121
#endif

static int SetQuickStart(int fd, int quick)
{
    errno = 0;
    int rc = setsockopt(fd, SOFTBUS_IPPROTO_TCP, TCP_QUICK_START, &quick, sizeof(quick));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set TCP_QUICK_START failed. rc=%{public}d", rc);
        return -1;
    }
    return 0;
}

static int SetSendBufFix(int fd, int val)
{
    int rc = setsockopt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_SNDBUF, &val, sizeof(val));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set SOFTBUS_SO_SNDBUF failed. rc=%{public}d", rc);
        return -1;
    }
    return 0;
}

static int SetRcvBufFix(int fd, int val)
{
    int rc = setsockopt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_RCVBUF, &val, sizeof(val));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set SOFTBUS_SO_RCVBUF failed. rc=%{public}d", rc);
        return -1;
    }
    return 0;
}

static int SetSendBuf(int fd)
{
    static int sendBufSize = 0;
    if (sendBufSize > 0) {
        return SetSendBufFix(fd, sendBufSize);
    }
    // try set buffer size
    for (int size = SEND_BUF_SIZE; size > 0; size -= M_BYTES) {
        int ret = SetSendBufFix(fd, size);
        if (ret == 0) {
            sendBufSize = size;
            return ret;
        }
    }
    return -1;
}

static int SetRecvBuf(int fd)
{
    static int recvBufSize = 0;
    if (recvBufSize > 0) {
        return SetRcvBufFix(fd, recvBufSize);
    }
    // try set buffer size
    for (int size = RECV_BUF_SIZE; size > 0; size -= M_BYTES) {
        int ret = SetRcvBufFix(fd, size);
        if (ret == 0) {
            recvBufSize = size;
            return ret;
        }
    }
    return -1;
}

static void SetServerOption(int fd)
{
    (void)SetReuseAddr(fd, 1);
    (void)SetNoDelay(fd, 1);
#ifndef __LITEOS_M__
    (void)SetReusePort(fd, 1);
#endif
    SetSendBuf(fd);
    SetRecvBuf(fd);
    (void)ConnSetTcpUserTimeOut(fd, SOFTBUS_TCP_USER_TIME);
}

static void SetClientOption(int fd)
{
    SetReuseAddr(fd, 1);
    SetNoDelay(fd, 1);
#ifndef __LITEOS_M__
    SetReusePort(fd, 1);
    SetQuickStart(fd, 1);
#endif
    SetSendBuf(fd);
    SetRecvBuf(fd);
    (void)ConnSetTcpUserTimeOut(fd, SOFTBUS_TCP_USER_TIME);
}

static int BindLocalIpv6IP(int32_t domain, int fd, const char *localIP, uint16_t port)
{
    SoftBusSockAddrIn6 addrIn6;
    if (memset_s(&addrIn6, sizeof(addrIn6), 0, sizeof(addrIn6)) != EOK) {
        CONN_LOGW(CONN_COMMON, "addrIn6 memset failed");
    }
    addrIn6.sin6Family = domain;
    char *addr = NULL;
    char *ifName = NULL;
    char *nextToken = NULL;
    char tmpIp[IP_LEN] = { 0 };
    if (strcpy_s(tmpIp, sizeof(tmpIp), localIP) != EOK) {
        CONN_LOGE(CONN_COMMON, "copy local id failed");
        return SOFTBUS_MEM_ERR;
    }
    addr = strtok_s(tmpIp, ADDR_SPLIT_IPV6, &nextToken);
    if (addr == NULL) {
        addr = "";
    }
    ifName = strtok_s(NULL, ADDR_SPLIT_IPV6, &nextToken);
    if (ifName != NULL) {
        addrIn6.sin6ScopeId = SoftBusIfNameToIndex(ifName);
    }
    int rc = SoftBusInetPtoN(domain, addr, &addrIn6.sin6Addr);
    if (rc != SOFTBUS_ADAPTER_OK)
    {
        CONN_LOGE(CONN_COMMON, "ipv6 SoftBusInetPtoN rc=%{public}d", rc);
        return rc;
    }
    addrIn6.sin6Port = SoftBusHtoNs(port);
    return SOFTBUS_TEMP_FAILURE_RETRY(
        SoftBusSocketBind(fd, (SoftBusSockAddr *)&addrIn6, sizeof(SoftBusSockAddrIn6)));
}

static int BindLocalIP(int32_t domain, int fd, const char *localIP, uint16_t port)
{
    int rc = SOFTBUS_OK;
    if (domain == SOFTBUS_AF_INET6) {
        rc = BindLocalIpv6IP(domain, fd, localIP, port);
    } else {
        SoftBusSockAddrIn addrIn;
        if (memset_s(&addrIn, sizeof(addrIn), 0, sizeof(addrIn)) != EOK) {
            CONN_LOGW(CONN_COMMON, "addrIn memset failed");
        }
        addrIn.sinFamily = domain;
        int rc = SoftBusInetPtoN(domain, localIP, &addrIn.sinAddr);
        if (rc != SOFTBUS_ADAPTER_OK) {
            CONN_LOGE(CONN_COMMON, "ipv4 SoftBusInetPtoN rc=%{public}d", rc);
            return rc;
        }
        addrIn.sinPort = SoftBusHtoNs(port);
        rc = SOFTBUS_TEMP_FAILURE_RETRY(
            SoftBusSocketBind(fd, (SoftBusSockAddr *)&addrIn, sizeof(SoftBusSockAddrIn)));
    }
    if (rc < SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "bind fd=%{public}d, rc=%{public}d", fd, rc);
        return rc;
    }
    return SOFTBUS_OK;
}

int32_t SetIpTos(int fd, uint32_t tos)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_IP, SOFTBUS_IP_TOS, &tos, sizeof(tos));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set tos failed, fd=%{public}d", fd);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    return SOFTBUS_OK;
}

int32_t GetDomainByAddr(const char *addr)
{
    if (strchr(addr, ADDR_FEATURE_IPV6) != NULL) {
        return SOFTBUS_AF_INET6;
    }
    return SOFTBUS_AF_INET;
}

static int32_t OpenTcpServerSocket(const LocalListenerInfo *option)
{
    if (option == NULL) {
        CONN_LOGE(CONN_COMMON, "null ptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (option->type != CONNECT_TCP && option->type != CONNECT_P2P) {
        CONN_LOGE(CONN_COMMON, "bad type! type=%{public}d", option->type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (option->socketOption.port < 0) {
        CONN_LOGE(CONN_COMMON, "bad port! port=%{public}d", option->socketOption.port);
        return SOFTBUS_INVALID_PARAM;
    }

    int fd;
    int32_t domain = GetDomainByAddr(option->socketOption.addr);
    int ret = SoftBusSocketCreate(
        domain, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_CLOEXEC | SOFTBUS_SOCK_NONBLOCK, 0, (int32_t *)&fd);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "Create socket failed! ret=%{public}d", ret);
        return ret;
    }

    SetServerOption(fd);
    // tcp user timeout on the Server
    if (option->socketOption.moduleId >= AUTH_P2P && option->socketOption.moduleId <= AUTH_ENHANCED_P2P_END) {
        (void)ConnSetTcpUserTimeOut(fd, SOFTBUS_CONN_TCP_USER_TIME);
    }
    ret = BindLocalIP(domain, fd, option->socketOption.addr, (uint16_t)option->socketOption.port);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "BindLocalIP ret=%{public}d", ret);
        ConnShutdownSocket(fd);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "server listen tcp socket, fd=%{public}d", fd);
    return fd;
}

static int32_t BindTcpClientAddr(int32_t domain, int fd, const char *inputAddr)
{
    if (inputAddr == NULL) {
        return SOFTBUS_OK;
    }

    const char *bindAddr = NULL;
    if (strcmp(inputAddr, BIND_ADDR_ALL) == 0) {
        if (domain == SOFTBUS_AF_INET6) {
            bindAddr = "::";
        } else {
            bindAddr = "0.0.0.0";
        }
    } else {
        CONN_LOGI(CONN_COMMON, "using specified bind addr");
        bindAddr = inputAddr;
    }
    return BindLocalIP(domain, fd, bindAddr, 0);
}

static int32_t SocketConnect(int32_t fd, int32_t domain, const ConnectOption *option)
{
    if (domain == SOFTBUS_AF_INET6) {
        SoftBusSockAddrIn6 addrIn6;
        if (memset_s(&addrIn6, sizeof(addrIn6), 0, sizeof(addrIn6)) != EOK) {
            CONN_LOGW(CONN_COMMON, "addrIn6 memset failed");
        }
        addrIn6.sin6Family = domain;
        char *addr = NULL;
        char *ifName = NULL;
        char *nextToken = NULL;
        char tmpIp[IP_LEN] = { 0 };
        if (strcpy_s(tmpIp, sizeof(tmpIp), option->socketOption.addr) != EOK) {
            CONN_LOGE(CONN_COMMON, "copy local id failed");
            return SOFTBUS_MEM_ERR;
        }
        addr = strtok_s(tmpIp, ADDR_SPLIT_IPV6, &nextToken);
        if (addr == NULL) {
            addr = "";
        }
        ifName = strtok_s(NULL, ADDR_SPLIT_IPV6, &nextToken);
        if (ifName != NULL) {
            addrIn6.sin6ScopeId = SoftBusIfNameToIndex(ifName);
        }
        SoftBusInetPtoN(domain, addr, &addrIn6.sin6Addr);
        addrIn6.sin6Port = SoftBusHtoNs((uint16_t)option->socketOption.port);
        return SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketConnect(fd, (SoftBusSockAddr *)&addrIn6));
    }
    SoftBusSockAddrIn addrIn;
    if (memset_s(&addrIn, sizeof(addrIn), 0, sizeof(addrIn)) != EOK) {
        CONN_LOGW(CONN_COMMON, "addrIn memset failed");
    }
    addrIn.sinFamily = domain;
    SoftBusInetPtoN(domain, option->socketOption.addr, &addrIn.sinAddr);
    addrIn.sinPort = SoftBusHtoNs((uint16_t)option->socketOption.port);
    return SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketConnect(fd, (SoftBusSockAddr *)&addrIn));
}

static int32_t OpenTcpClientSocket(const ConnectOption *option, const char *myIp, bool isNonBlock)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, SOFTBUS_ERR, CONN_COMMON, "invalid param, option is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_TCP || option->type == CONNECT_P2P ||
        option->type == CONNECT_P2P_REUSE, SOFTBUS_ERR, CONN_COMMON, "invalid param, unsupport type=%{public}d",
        option->type);
    CONN_CHECK_AND_RETURN_RET_LOGW(option->socketOption.port > 0, SOFTBUS_ERR, CONN_COMMON,
        "invalid param, invalid port=%{public}d", option->socketOption.port);

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, option->socketOption.addr, IP_LEN);

    int32_t fd = -1;
    int32_t domain = -1;
    if (strcmp(option->socketOption.addr, "") == 0)
    {
        domain = GetDomainByAddr(myIp);
        CONN_LOGW(CONN_COMMON, "socket option addr is null, get my addr domain id");
    } else {
        domain = GetDomainByAddr(option->socketOption.addr);
    }
    int32_t ret = SoftBusSocketCreate(domain, SOFTBUS_SOCK_STREAM, 0, &fd);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "create socket failed, serverIp=%{public}s, serverPort=%{public}d, error=%{public}d",
            animizedIp, option->socketOption.port, ret);
        return ret;
    }
    if (isNonBlock && ConnToggleNonBlockMode(fd, true) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "set nonblock failed, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d",
            animizedIp, option->socketOption.port, fd);
        SoftBusSocketClose(fd);
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    SetClientOption(fd);
    // tcp user timeout on the Client
    if (option->socketOption.moduleId >= AUTH_P2P && option->socketOption.moduleId <= AUTH_ENHANCED_P2P_END) {
        (void)ConnSetTcpUserTimeOut(fd, SOFTBUS_CONN_TCP_USER_TIME);
    }
    ret = BindTcpClientAddr(domain, fd, myIp);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "bind client address failed, serverIp=%{public}s, serverPort=%{public}d, "
            "error=%{public}d", animizedIp, option->socketOption.port, ret);
        ConnShutdownSocket(fd);
        return ret;
    }
    ret = SocketConnect(fd, domain, option);
    if ((ret != SOFTBUS_ADAPTER_OK) && (ret != SOFTBUS_ADAPTER_SOCKET_EINPROGRESS) &&
        (ret != SOFTBUS_ADAPTER_SOCKET_EAGAIN)) {
        CONN_LOGE(CONN_COMMON, "client connect failed, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d, "
            "error=%{public}d, errno=%{public}d", animizedIp, option->socketOption.port, fd, ret, errno);
        ConnShutdownSocket(fd);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "client open tcp socket, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d",
        animizedIp, option->socketOption.port, fd);
    return fd;
}

static int32_t GetTcpSockPort(int32_t fd)
{
    SoftBusSockAddr addr;
    int rc = SoftBusSocketGetLocalName(fd, &addr);
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "GetTcpSockPort. fd=%{public}d, rc=%{public}d", fd, rc);
        return rc;
    }
    if (addr.saFamily == SOFTBUS_AF_INET6)
    {
        return SoftBusNtoHs(((SoftBusSockAddrIn6 *)&addr)->sin6Port);
    }
    return SoftBusNtoHs(((SoftBusSockAddrIn *)&addr)->sinPort);
}

int32_t ConnSetTcpKeepAlive(int32_t fd, int32_t seconds)
{
#define KEEP_ALIVE_COUNT 5
    if (fd < 0) {
        CONN_LOGW(CONN_COMMON, "ConnSetTcpKeepAlive invalid param");
        return -1;
    }

    int32_t rc;
    int32_t enable;
    if (seconds > 0) {
        enable = 1;
        rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_KEEPIDLE, &seconds, sizeof(seconds));
        if (rc != 0) {
            CONN_LOGE(CONN_COMMON, "set TCP_KEEPIDLE failed");
            return -1;
        }

        int32_t keepAliveCnt = KEEP_ALIVE_COUNT;
        rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_KEEPCNT, &keepAliveCnt, sizeof(keepAliveCnt));
        if (rc != 0) {
            CONN_LOGE(CONN_COMMON, "set TCP_KEEPCNT failed");
            return -1;
        }

        // Keepalive interval changed from 15s to 2s
        int32_t keepAliveIntvl = 2;
        rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_KEEPINTVL, &keepAliveIntvl,
            sizeof(keepAliveIntvl));
        if (rc != 0) {
            CONN_LOGE(CONN_COMMON, "set TCP_KEEPINTVL failed");
            return -1;
        }
    } else {
        enable = 0;
    }

    rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_KEEPALIVE, &enable, sizeof(enable));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set SO_KEEPALIVE failed");
        return -1;
    }
    return 0;
}

#ifdef TCP_USER_TIMEOUT
int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millSec)
{
    if (fd < 0) {
        CONN_LOGE(CONN_COMMON, "ConnSetTcpUserTimeOut invalid param");
        return -1;
    }
    if (SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_USER_TIMEOUT, &millSec, sizeof(millSec)) != 0) {
        CONN_LOGE(CONN_COMMON, "set SOFTBUS_TCP_USER_TIMEOUT failed");
        return -1;
    }
    return 0;
}
#else
int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millSec)
{
    (void)fd;
    (void)millSec;
    return 0;
}

#endif
static int32_t AcceptTcpClient(int32_t fd, ConnectOption *clientAddr, int32_t *cfd)
{
    SoftBusSockAddr addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        CONN_LOGE(CONN_COMMON, "memset failed");
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketAccept(fd, &addr, cfd));
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "accept failed, ret=%{public}" PRId32 ", cfd=%{public}d, fd=%{public}d", ret, *cfd, fd);
        return ret;
    }

    if (clientAddr == NULL) {
        return SOFTBUS_OK;
    }

    clientAddr->type = CONNECT_TCP;
    clientAddr->socketOption.port = GetTcpSockPort(*cfd);
    clientAddr->socketOption.protocol = LNN_PROTOCOL_IP;
    if (addr.saFamily == SOFTBUS_AF_INET6) {
        SoftBusInetNtoP(SOFTBUS_AF_INET6,&((SoftBusSockAddrIn6 *)&addr)->sin6Addr,
            clientAddr->socketOption.addr, sizeof(clientAddr->socketOption.addr));
    } else {
        SoftBusInetNtoP(SOFTBUS_AF_INET, &((SoftBusSockAddrIn *)&addr)->sinAddr,
            clientAddr->socketOption.addr, sizeof(clientAddr->socketOption.addr));
    }
    return SOFTBUS_OK;
}

const SocketInterface *GetTcpProtocol(void)
{
    static SocketInterface tcpSocketIntf = {
        .name = "TCP",
        .type = LNN_PROTOCOL_IP,
        .GetSockPort = GetTcpSockPort,
        .OpenClientSocket = OpenTcpClientSocket,
        .OpenServerSocket = OpenTcpServerSocket,
        .AcceptClient = AcceptTcpClient,
    };
    return &tcpSocketIntf;
}
