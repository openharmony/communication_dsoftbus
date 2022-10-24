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
#include <fcntl.h>
#include <securec.h>
#include <unistd.h>

#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_socket.h"

#define SEND_BUF_SIZE 0x200000  // 2M
#define RECV_BUF_SIZE 0x100000  // 1M
#define USER_TIMEOUT_MS 500000  // 500000us

#ifndef __LITEOS_M__
static int SetReusePort(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEPORT, &on, sizeof(on));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set SO_REUSEPORT");
        return -1;
    }
    return 0;
}
#endif

static int SetReuseAddr(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &on, sizeof(on));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set SO_REUSEADDR");
        return -1;
    }
    return 0;
}

static int SetNoDelay(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_NODELAY, &on, sizeof(on));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set TCP_NODELAY");
        return -1;
    }
    return 0;
}

static void SetServerOption(int fd)
{
    (void)SetReuseAddr(fd, 1);
    (void)SetNoDelay(fd, 1);
#ifndef __LITEOS_M__
    (void)SetReusePort(fd, 1);
#endif
}

static void SetClientOption(int fd)
{
    SetReuseAddr(fd, 1);
    SetNoDelay(fd, 1);
#ifndef __LITEOS_M__
    SetReusePort(fd, 1);
#endif
}


static int BindLocalIP(int fd, const char *localIP, uint16_t port)
{
    SoftBusSockAddrIn addr;

    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memset failed");
    }

    addr.sinFamily = SOFTBUS_AF_INET;
    int rc = SoftBusInetPtoN(SOFTBUS_AF_INET, localIP, &addr.sinAddr);
    if (rc != SOFTBUS_ADAPTER_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusInetPtoN rc=%d", rc);
        return SOFTBUS_ERR;
    }
    addr.sinPort = SoftBusHtoNs(port);
    rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketBind(fd, (SoftBusSockAddr *)&addr, sizeof(addr)));
    if (rc < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "bind fd=%d,rc=%d", fd, rc);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SetIpTos(int fd, uint32_t tos)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_IP, SOFTBUS_IP_TOS, &tos, sizeof(tos));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set tos failed");
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OpenTcpServerSocket(const LocalListenerInfo *option)
{
    if (option == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:null ptr!", __func__);
        return -1;
    }
    if (option->type != CONNECT_TCP && option->type != CONNECT_P2P) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:bad type!type=%d", __func__, option->type);
        return -1;
    }
    if (option->socketOption.port < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:bad port!port=%d", __func__, option->socketOption.port);
        return -1;
    }

    int fd;
    int ret = SoftBusSocketCreate(
        SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_CLOEXEC | SOFTBUS_SOCK_NONBLOCK, 0, (int32_t *)&fd);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:Create socket failed! ret=%d", __func__, ret);
        return -1;
    }

    SetServerOption(fd);
    ret = BindLocalIP(fd, option->socketOption.addr, (uint16_t)option->socketOption.port);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BindLocalIP ret=%d", ret);
        ConnShutdownSocket(fd);
        return -1;
    }
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "%s:using specified bind addr", __func__);
        bindAddr = inputAddr;
    }
    return BindLocalIP(fd, bindAddr, 0);
}

static int32_t OpenTcpClientSocket(const ConnectOption *option, const char *myIp, bool isNonBlock)
{
    if (option == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:null ptr!", __func__);
        return -1;
    }
    if (option->type != CONNECT_TCP && option->type != CONNECT_P2P) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:bad type!type=%d", __func__, option->type);
        return -1;
    }
    if (option->socketOption.port <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenTcpClientSocket invalid para, port=%d",
            option->socketOption.port);
        return -1;
    }

    int32_t fd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &fd);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:%d:fd=%d", __func__, __LINE__, fd);
        return -1;
    }

    if (isNonBlock && ConnToggleNonBlockMode(fd, true) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set nonblock failed, fd=%d", fd);
        SoftBusSocketClose(fd);
        return -1;
    }

    SetClientOption(fd);
    ret = BindTcpClientAddr(fd, myIp);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BindLocalIP ret=%d", ret);
        ConnShutdownSocket(fd);
        return -1;
    }
    SoftBusSockAddrIn addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memset failed");
    }
    addr.sinFamily = SOFTBUS_AF_INET;
    SoftBusInetPtoN(SOFTBUS_AF_INET, option->socketOption.addr, &addr.sinAddr);
    addr.sinPort = SoftBusHtoNs((uint16_t)option->socketOption.port);
    int rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketConnect(fd, (SoftBusSockAddr *)&addr, sizeof(addr)));
    if ((rc != SOFTBUS_ADAPTER_OK) && (rc != SOFTBUS_ADAPTER_SOCKET_EINPROGRESS) &&
        (rc != SOFTBUS_ADAPTER_SOCKET_EAGAIN)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d,connect rc=%d", fd, rc);
        ConnShutdownSocket(fd);
        return -1;
    }
    return fd;
}

static int32_t GetTcpSockPort(int32_t fd)
{
    SoftBusSockAddrIn addr;
    int32_t addrLen = sizeof(addr);

    int rc = SoftBusSocketGetLocalName(fd, (SoftBusSockAddr *)&addr, &addrLen);
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d,GetTcpSockPort rc=%d", fd, rc);
        return rc;
    }
    return SoftBusNtoHs(addr.sinPort);
}

int32_t ConnSetTcpKeepAlive(int32_t fd, int32_t seconds)
{
#define KEEP_ALIVE_COUNT 5
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnSetTcpKeepAlive invalid param");
        return -1;
    }

    int32_t rc;
    int32_t enable;
    if (seconds > 0) {
        enable = 1;
        rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_KEEPIDLE, &seconds, sizeof(seconds));
        if (rc != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set TCP_KEEPIDLE");
            return -1;
        }

        int32_t keepAliveCnt = KEEP_ALIVE_COUNT;
        rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_KEEPCNT, &keepAliveCnt, sizeof(keepAliveCnt));
        if (rc != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set TCP_KEEPCNT");
            return -1;
        }

        int32_t keepAliveIntvl = 1;
        rc = SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_KEEPINTVL, &keepAliveIntvl,
            sizeof(keepAliveIntvl));
        if (rc != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set TCP_KEEPINTVL");
            return -1;
        }
    } else {
        enable = 0;
    }

    rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_KEEPALIVE, &enable, sizeof(enable));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set SO_KEEPALIVE");
        return -1;
    }
    return 0;
}

#ifdef TCP_USER_TIMEOUT
int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millSec)
{
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnSetTcpUserTimeOut invalid param");
        return -1;
    }
    if (SoftBusSocketSetOpt(fd, SOFTBUS_IPPROTO_TCP, SOFTBUS_TCP_USER_TIMEOUT, &millSec, sizeof(millSec)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set SOFTBUS_TCP_USER_TIMEOUT failed");
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
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:memset failed", __func__);
        return SOFTBUS_MEM_ERR;
    }
    uint32_t addrLen = sizeof(addr);
    int32_t ret =
        SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketAccept(fd, (SoftBusSockAddr *)&addr, (int32_t *)&addrLen, cfd));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "accept failed, ret=%" PRId32 " cfd=%d, fd=%d", ret, *cfd, fd);
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

static SocketInterface g_ipSocketInterface = {
    .name = "TCP",
    .type = LNN_PROTOCOL_IP,
    .GetSockPort = GetTcpSockPort,
    .OpenClientSocket = OpenTcpClientSocket,
    .OpenServerSocket = OpenTcpServerSocket,
    .AcceptClient = AcceptTcpClient,
};

const SocketInterface *GetTcpProtocol(void)
{
    return &g_ipSocketInterface;
}
