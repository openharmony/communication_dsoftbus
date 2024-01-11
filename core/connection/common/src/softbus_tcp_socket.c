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

#define M_BYTES               0x100000
#define SEND_BUF_SIZE         (4 * M_BYTES) // 4M
#define RECV_BUF_SIZE         (6 * M_BYTES) // 6M
#define USER_TIMEOUT_MS       (15 * 1000)   // 15s
#define SOFTBUS_TCP_USER_TIME USER_TIMEOUT_MS

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
        CONN_LOGE(CONN_COMMON, "set TCP_QUICK_START");
        return -1;
    }
    return 0;
}

static int SetSendBufFix(int fd, int val)
{
    int rc = setsockopt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_SNDBUF, &val, sizeof(val));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set SOFTBUS_SO_SNDBUF");
        return -1;
    }
    return 0;
}

static int SetRcvBufFix(int fd, int val)
{
    int rc = setsockopt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_RCVBUF, &val, sizeof(val));
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "set SOFTBUS_SO_RCVBUF");
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

static int BindLocalIP(int fd, const char *localIP, uint16_t port)
{
    SoftBusSockAddrIn addr;

    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        CONN_LOGW(CONN_COMMON, "memset failed");
    }

    addr.sinFamily = SOFTBUS_AF_INET;
    int rc = SoftBusInetPtoN(SOFTBUS_AF_INET, localIP, &addr.sinAddr);
    if (rc != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "SoftBusInetPtoN rc=%{public}d", rc);
        return SOFTBUS_ERR;
    }
    addr.sinPort = SoftBusHtoNs(port);
    rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketBind(fd, (SoftBusSockAddr *)&addr, sizeof(addr)));
    if (rc < 0) {
        CONN_LOGE(CONN_COMMON, "bind fd=%{public}d, rc=%{public}d", fd, rc);
        return SOFTBUS_ERR;
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

static int32_t OpenTcpServerSocket(const LocalListenerInfo *option)
{
    if (option == NULL) {
        CONN_LOGE(CONN_COMMON, "null ptr!");
        return -1;
    }
    if (option->type != CONNECT_TCP && option->type != CONNECT_P2P) {
        CONN_LOGE(CONN_COMMON, "bad type! type=%{public}d", option->type);
        return -1;
    }
    if (option->socketOption.port < 0) {
        CONN_LOGE(CONN_COMMON, "bad port! port=%{public}d", option->socketOption.port);
        return -1;
    }

    int fd;
    int ret = SoftBusSocketCreate(
        SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_CLOEXEC | SOFTBUS_SOCK_NONBLOCK, 0, (int32_t *)&fd);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "Create socket failed! ret=%{public}d", ret);
        return -1;
    }

    SetServerOption(fd);
    ret = BindLocalIP(fd, option->socketOption.addr, (uint16_t)option->socketOption.port);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "BindLocalIP ret=%{public}d", ret);
        ConnShutdownSocket(fd);
        return -1;
    }
    CONN_LOGI(CONN_COMMON, "server listen tcp socket, fd=%{public}d", fd);
    return fd;
}

static int32_t BindTcpClientAddr(int fd, const char *inputAddr)
{
    if (inputAddr == NULL) {
        return SOFTBUS_OK;
    }

    const char *bindAddr = NULL;
    if (strcmp(inputAddr, BIND_ADDR_ALL) == 0) {
        bindAddr = "0.0.0.0";
    } else {
        CONN_LOGI(CONN_COMMON, "using specified bind addr");
        bindAddr = inputAddr;
    }
    return BindLocalIP(fd, bindAddr, 0);
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
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &fd);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "create socket failed, serverIp=%{public}s, serverPort=%{public}d, error=%{public}d",
            animizedIp, option->socketOption.port, ret);
        return ret;
    }
    if (isNonBlock && ConnToggleNonBlockMode(fd, true) != SOFTBUS_OK) {
        CONN_LOGE(
            CONN_COMMON, "set nonblock failed, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d", animizedIp,
            option->socketOption.port, fd);
        SoftBusSocketClose(fd);
        return SOFTBUS_ERR;
    }
    SetClientOption(fd);
    ret = BindTcpClientAddr(fd, myIp);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(
            CONN_COMMON, "bind client address failed, serverIp=%{public}s, serverPort=%{public}d, error=%{public}d",
            animizedIp, option->socketOption.port, ret);
        ConnShutdownSocket(fd);
        return ret;
    }

    SoftBusSockAddrIn addr = { 0 };
    addr.sinFamily = SOFTBUS_AF_INET;
    SoftBusInetPtoN(SOFTBUS_AF_INET, option->socketOption.addr, &addr.sinAddr);
    addr.sinPort = SoftBusHtoNs((uint16_t)option->socketOption.port);
    ret = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketConnect(fd, (SoftBusSockAddr *)&addr));
    if ((ret != SOFTBUS_ADAPTER_OK) && (ret != SOFTBUS_ADAPTER_SOCKET_EINPROGRESS) &&
        (ret != SOFTBUS_ADAPTER_SOCKET_EAGAIN)) {
        CONN_LOGE(CONN_COMMON,
            "client connect failed, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d, error=%{public}d, "
            "errno=%{public}d",
            animizedIp, option->socketOption.port, fd, ret, errno);
        ConnShutdownSocket(fd);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "client open tcp socket, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d",
        animizedIp, option->socketOption.port, fd);
    return fd;
}

static int32_t GetTcpSockPort(int32_t fd)
{
    SoftBusSockAddrIn addr;

    int rc = SoftBusSocketGetLocalName(fd, (SoftBusSockAddr *)&addr);
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "GetTcpSockPort. fd=%{public}d, rc=%{public}d", fd, rc);
        return rc;
    }
    return SoftBusNtoHs(addr.sinPort);
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

        int32_t keepAliveIntvl = SOFTBUS_TCP_USER_TIME / 1000;
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
    SoftBusSockAddrIn addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        CONN_LOGE(CONN_COMMON, "memset failed");
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret =
        SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketAccept(fd, (SoftBusSockAddr *)&addr, cfd));
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "accept failed, ret=%{public}" PRId32 ", cfd=%{public}d, fd=%{public}d", ret, *cfd, fd);
        return ret;
    }

    if (clientAddr != NULL) {
        clientAddr->type = CONNECT_TCP;
        SoftBusInetNtoP(
            SOFTBUS_AF_INET, &addr.sinAddr, clientAddr->socketOption.addr, sizeof(clientAddr->socketOption.addr));
        clientAddr->socketOption.port = GetTcpSockPort(*cfd);
        clientAddr->socketOption.protocol = LNN_PROTOCOL_IP;
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
