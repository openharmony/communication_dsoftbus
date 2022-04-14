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

static int WaitEvent(int fd, short events, int timeout)
{
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:%d:fd=%d invalid params", __func__, __LINE__, fd);
        return -1;
    }
    SoftBusSockTimeOut tv = {0};
    tv.sec = 0;
    tv.usec = timeout;
    int rc = 0;
    switch (events) {
        case SOFTBUS_SOCKET_OUT: {
                SoftBusFdSet writeSet;
                SoftBusSocketFdZero(&writeSet);
                SoftBusSocketFdSet(fd, &writeSet);
                rc = TEMP_FAILURE_RETRY(SoftBusSocketSelect(fd + 1, NULL, &writeSet, NULL, &tv));
                if (rc < 0) {
                    break;
                }
                if (!SoftBusSocketFdIsset(fd, &writeSet)) {
                    rc = 0;
                }
                break;
            }
        case SOFTBUS_SOCKET_IN: {
                SoftBusFdSet readSet;
                SoftBusSocketFdZero(&readSet);
                SoftBusSocketFdSet(fd, &readSet);
                rc = TEMP_FAILURE_RETRY(SoftBusSocketSelect(fd + 1, &readSet, NULL, NULL, &tv));
                if (rc < 0) {
                    break;
                }
                if (!SoftBusSocketFdIsset(fd, &readSet)) {
                    rc = 0;
                }
                break;
            }
        default:
            break;
    }
    return rc;
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
    rc = TEMP_FAILURE_RETRY(SoftBusSocketBind(fd, (SoftBusSockAddr *)&addr, sizeof(addr)));
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

int32_t OpenTcpServerSocket(const char *ip, int32_t port)
{
    if (ip == NULL || port < 0) {
        return -1;
    }

    int fd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_CLOEXEC | SOFTBUS_SOCK_NONBLOCK,
        0, (int32_t *)&fd);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d", fd);
        return -1;
    }

    SetServerOption(fd);
    ret = BindLocalIP(fd, ip, (uint16_t)port);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BindLocalIP ret=%d", ret);
        TcpShutDown(fd);
        return -1;
    }
    return fd;
}

int32_t OpenTcpClientSocket(const char *peerIp, const char *myIp, int32_t port, bool isNonBlock)
{
    if ((peerIp == NULL) || (port <= 0)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenTcpClientSocket invalid para, port=%d", port);
        return -1;
    }

    int fd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &fd);
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
    if (myIp != NULL) {
        ret = BindLocalIP(fd, myIp, 0);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BindLocalIP ret=%d", ret);
            TcpShutDown(fd);
            return -1;
        }
    }
    SoftBusSockAddrIn addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memset failed");
    }
    addr.sinFamily = SOFTBUS_AF_INET;
    SoftBusInetPtoN(SOFTBUS_AF_INET, peerIp, &addr.sinAddr);
    addr.sinPort = SoftBusHtoNs((uint16_t)port);
    int rc = TEMP_FAILURE_RETRY(SoftBusSocketConnect(fd, (SoftBusSockAddr *)&addr, sizeof(addr)));
    if ((rc != SOFTBUS_ADAPTER_OK) && (rc != SOFTBUS_ADAPTER_SOCKET_EINPROGRESS)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d,connect rc=%d", fd, rc);
        TcpShutDown(fd);
        return -1;
    }
    return fd;
}

int32_t ConnToggleNonBlockMode(int32_t fd, bool isNonBlock)
{
    if (fd < 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d,fcntl get flag failed, errno=%d", fd, errno);
        return SOFTBUS_ERR;
    }
    if (isNonBlock && ((uint32_t)flags & O_NONBLOCK) == 0) {
        flags = (int32_t)((uint32_t)flags | O_NONBLOCK);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "fd=%d set to nonblock", fd);
    } else if (!isNonBlock && ((uint32_t)flags & O_NONBLOCK) != 0) {
        flags = (int32_t)((uint32_t)flags & ~O_NONBLOCK);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "fd=%d set to block", fd);
    } else {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "fd=%d nonblock state is already ok", fd);
        return SOFTBUS_OK;
    }
    return fcntl(fd, F_SETFL, flags);
}

int32_t GetTcpSockPort(int32_t fd)
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

ssize_t SendTcpData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    if (fd < 0 || buf == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d invalid params", fd);
        return -1;
    }

    if (timeout == 0) {
        timeout = USER_TIMEOUT_MS;
    }

    int err = WaitEvent(fd, SOFTBUS_SOCKET_OUT, USER_TIMEOUT_MS);
    if (err <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "wait event error %d", err);
        return err;
    }
    ssize_t bytes = 0;
    while (1) {
        ssize_t rc = TEMP_FAILURE_RETRY(SoftBusSocketSend(fd, &buf[bytes], len - bytes, 0));
        if (rc == SOFTBUS_ADAPTER_SOCKET_EAGAIN) {
            continue;
        } else if (rc <= 0) {
            if (bytes == 0) {
                bytes = -1;
            }
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "tcp send fail %d %d", rc, errno);
            break;
        }
        bytes += rc;
        if (bytes == (ssize_t)(len)) {
            break;
        }

        err = WaitEvent(fd, SOFTBUS_SOCKET_OUT, timeout);
        if (err == 0) {
            continue;
        } else if (err < 0) {
            if (bytes == 0) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "send data wait event fail %d", err);
                bytes = err;
            }
            break;
        }
    }
    return bytes;
}

static ssize_t OnRecvData(int32_t fd, char *buf, size_t len, int timeout, int flags)
{
    if (fd < 0 || buf == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd[%d] len[%d] invalid params", fd, len);
        return -1;
    }

    if (timeout != 0) {
        int err = WaitEvent(fd, SOFTBUS_SOCKET_IN, timeout);
        if (err < 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "tcp recv data wait event err[%d]", err);
            return err;
        }
    }

    ssize_t rc = TEMP_FAILURE_RETRY(SoftBusSocketRecv(fd, buf, len, flags));
    if (rc == SOFTBUS_ADAPTER_SOCKET_EAGAIN) {
        rc = 0;
    } else if (rc <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "tcp recv data fail errno[%d]", errno);
        rc = -1;
    }
    return rc;
}

ssize_t RecvTcpData(int32_t fd, char *buf, size_t len, int32_t timeout)
{
    return OnRecvData(fd, buf, len, timeout, 0);
}

void CloseTcpFd(int32_t fd)
{
    if (fd >= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "close fd=%d", fd);
        SoftBusSocketClose(fd);
    }
}

void TcpShutDown(int32_t fd)
{
    if (fd >= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "shutdown fd=%d", fd);
        SoftBusSocketShutDown(fd, SOFTBUS_SHUT_RDWR);
        SoftBusSocketClose(fd);
    }
}

int32_t ConnGetSocketError(int32_t fd)
{
    return SoftBusSocketGetError(fd);
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
