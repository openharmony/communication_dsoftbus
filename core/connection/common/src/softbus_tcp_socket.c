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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <securec.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "softbus_errcode.h"
#include "softbus_log.h"

#define SEND_BUF_SIZE 0x200000  // 2M
#define RECV_BUF_SIZE 0x100000  // 1M
#define USER_TIMEOUT_MS 5000  // 5000us

#ifndef __LITEOS_M__
static int SetReusePort(int fd, int on)
{
    int rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set SO_REUSEPORT");
        return -1;
    }
    return 0;
}
#endif

static int SetReuseAddr(int fd, int on)
{
    int rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set SO_REUSEADDR");
        return -1;
    }
    return 0;
}

static int SetNoDelay(int fd, int on)
{
    int rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set SO_REUSEADDR");
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
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeout;
    int rc = 0;
    switch (events) {
        case SOFTBUS_SOCKET_OUT: {
                fd_set writeSet;
                FD_ZERO(&writeSet);
                FD_SET(fd, &writeSet);
                rc = TEMP_FAILURE_RETRY(select(fd + 1, NULL, &writeSet, NULL, &tv));
                if (rc < 0) {
                    break;
                }
                if (!FD_ISSET(fd, &writeSet)) {
                    rc = 0;
                }
                break;
            }
        case SOFTBUS_SOCKET_IN: {
                fd_set readSet;
                FD_ZERO(&readSet);
                FD_SET(fd, &readSet);
                rc = TEMP_FAILURE_RETRY(select(fd + 1, &readSet, NULL, NULL, &tv));
                if (rc < 0) {
                    break;
                }
                if (!FD_ISSET(fd, &readSet)) {
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
    struct sockaddr_in addr;

    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memset failed");
    }

    addr.sin_family = AF_INET;
    int rc = inet_pton(AF_INET, localIP, &addr.sin_addr);
    if (rc <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "inet_pton rc=%d", rc);
        return SOFTBUS_ERR;
    }
    addr.sin_port = htons(port);

    errno = 0;
    rc = TEMP_FAILURE_RETRY(bind(fd, (struct sockaddr *)&addr, sizeof(addr)));
    if (rc < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "bind fd=%d,rc=%d", fd, rc);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int OpenTcpServerSocket(const char *ip, int port)
{
    if (ip == NULL || port < 0) {
        return -1;
    }
    errno = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d", fd);
        return -1;
    }
    SetServerOption(fd);
    int ret = BindLocalIP(fd, ip, port);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BindLocalIP ret=%d", ret);
        TcpShutDown(fd);
        return -1;
    }
    return fd;
}

int OpenTcpClientSocket(const char *peerIp, const char *myIp, int port)
{
    if ((peerIp == NULL) || (port <= 0)) {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:%d:fd=%d", __func__, __LINE__, fd);
        return -1;
    }

    SetClientOption(fd);
    if (myIp != NULL) {
        int ret = BindLocalIP(fd, myIp, 0);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BindLocalIP ret=%d", ret);
            TcpShutDown(fd);
            return -1;
        }
    }
    struct sockaddr_in addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memset failed");
    }
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, peerIp, &addr.sin_addr);
    addr.sin_port = htons(port);
    errno = 0;
    int rc = TEMP_FAILURE_RETRY(connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
    if ((rc == -1) && (errno != EINPROGRESS)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d,connect rc=%d, errno=%d", fd, rc, errno);
        TcpShutDown(fd);
        return -1;
    }
    return fd;
}

int GetTcpSockPort(int fd)
{
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);

    int rc = getsockname(fd, (struct sockaddr *)&addr, &addrLen);
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd=%d,getsockname rc=%d", fd, rc);
        return rc;
    }
    return ntohs(addr.sin_port);
}

ssize_t SendTcpData(int fd, const char *buf, size_t len, int timeout)
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
        return err;
    }
    ssize_t bytes = 0;
    while (1) {
        errno = 0;
        ssize_t rc = TEMP_FAILURE_RETRY(send(fd, &buf[bytes], len - bytes, 0));
        if ((rc == -1) && (errno == EAGAIN)) {
            continue;
        } else if (rc <= 0) {
            if (bytes == 0) {
                bytes = -1;
            }
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
                bytes = err;
            }
            break;
        }
    }
    return bytes;
}

static ssize_t OnRecvData(int fd, char *buf, size_t len, int timeout, int flags)
{
    if (fd < 0 || buf == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fd[%d] len[%d] invalid params", fd, len);
        return -1;
    }

    if (timeout != 0) {
        int err = WaitEvent(fd, SOFTBUS_SOCKET_IN, timeout);
        if (err < 0) {
            return err;
        }
    }

    errno = 0;
    ssize_t rc = TEMP_FAILURE_RETRY(recv(fd, buf, len, flags));
    if ((rc == -1) && (errno == EAGAIN)) {
        rc = 0;
    } else if (rc <= 0) {
        rc = -1;
    }
    return rc;
}

ssize_t RecvTcpData(int fd, char *buf, size_t len, int timeout)
{
    return OnRecvData(fd, buf, len, timeout, 0);
}

void CloseTcpFd(int fd)
{
    if (fd >= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "close fd=%d", fd);
        close(fd);
    }
}

void TcpShutDown(int fd)
{
    if (fd >= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "shutdown fd=%d", fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}

int32_t SetTcpKeepAlive(int32_t fd, int32_t seconds)
{
#define KEEP_ALIVE_COUNT 5
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SetTcpKeepAlive invalid param");
        return -1;
    }

    int32_t rc;
    int32_t enable;
    if (seconds > 0) {
        enable = 1;
        rc = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &seconds, sizeof(seconds));
        if (rc != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set TCP_KEEPIDLE");
            return -1;
        }

        int32_t keepAliveCnt = KEEP_ALIVE_COUNT;
        rc = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepAliveCnt, sizeof(keepAliveCnt));
        if (rc != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set TCP_KEEPCNT");
            return -1;
        }

        int32_t keepAliveIntvl = 1;
        rc = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepAliveIntvl, sizeof(keepAliveIntvl));
        if (rc != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set TCP_KEEPINTVL");
            return -1;
        }
    } else {
        enable = 0;
    }

    rc = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set SO_KEEPALIVE");
        return -1;
    }
    return 0;
}