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

#include "softbus_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <securec.h>
#include "conn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_tcp_socket.h"

#define MAX_SOCKET_TYPE 5
#define SEND_BUF_SIZE   0x200000 // 2M
#define RECV_BUF_SIZE   0x100000 // 1M
#define USER_TIMEOUT_US 2000000   // 2000000us

static const SocketInterface *g_socketInterfaces[MAX_SOCKET_TYPE] = { 0 };
static SoftBusMutex g_socketsMutex;

int32_t RegistSocketProtocol(const SocketInterface *interface)
{
    if (interface == NULL || interface->GetSockPort == NULL || interface->OpenClientSocket == NULL ||
        interface->OpenServerSocket == NULL || interface->AcceptClient == NULL) {
        CONN_LOGW(CONN_COMMON, "Bad socket interface!");
        return SOFTBUS_ERR;
    }
    int ret = SoftBusMutexLock(&g_socketsMutex);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "get lock failed!ret=%" PRId32, ret);
        return ret;
    }

    ret = SOFTBUS_ERR;
    for (uint8_t i = 0; i < MAX_SOCKET_TYPE; i++) {
        if (g_socketInterfaces[i] == NULL) {
            g_socketInterfaces[i] = interface;
            ret = SOFTBUS_OK;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_socketsMutex);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "socket type list is full!");
    }
    return ret;
}

const SocketInterface *GetSocketInterface(ProtocolType protocolType)
{
    int ret = SoftBusMutexLock(&g_socketsMutex);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "get lock failed!ret=%" PRId32, ret);
        return NULL;
    }
    const SocketInterface *result = NULL;
    for (uint8_t i = 0; i < MAX_SOCKET_TYPE; i++) {
        if (g_socketInterfaces[i] != NULL && g_socketInterfaces[i]->type == protocolType) {
            result = g_socketInterfaces[i];
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_socketsMutex);
    return result;
}

int32_t __attribute__((weak)) RegistNewIpSocket(void)
{
    CONN_LOGI(CONN_COMMON, "newip not deployed");
    return SOFTBUS_OK;
}

int32_t ConnInitSockets(void)
{
    int32_t ret = SoftBusMutexInit(&g_socketsMutex, NULL);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "init mutex failed!ret=%" PRId32, ret);
        return ret;
    }

    (void)memset_s(g_socketInterfaces, sizeof(g_socketInterfaces), 0, sizeof(g_socketInterfaces));

    ret = RegistSocketProtocol(GetTcpProtocol());
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "regist tcp failed!!ret=%" PRId32, ret);
        (void)SoftBusMutexDestroy(&g_socketsMutex);
        return ret;
    }
    CONN_LOGI(CONN_INIT, "tcp registed!");

    ret = RegistNewIpSocket();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "regist newip failed!!ret=%" PRId32, ret);
        (void)SoftBusMutexDestroy(&g_socketsMutex);
        return ret;
    }

    return ret;
}

void ConnDeinitSockets(void)
{
    (void)memset_s(g_socketInterfaces, sizeof(g_socketInterfaces), 0, sizeof(g_socketInterfaces));
    (void)SoftBusMutexDestroy(&g_socketsMutex);
}

int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock)
{
    if (option == NULL) {
        return SOFTBUS_ERR;
    }
    const SocketInterface *socketInterface = GetSocketInterface(option->socketOption.protocol);
    if (socketInterface == NULL) {
        CONN_LOGE(CONN_COMMON, "protocol not supported!protocol=%d", option->socketOption.protocol);
        return SOFTBUS_ERR;
    }
    return socketInterface->OpenClientSocket(option, bindAddr, isNonBlock);
}

static int WaitEvent(int fd, short events, int timeout)
{
    if (fd < 0) {
        CONN_LOGE(CONN_COMMON, "fd=%d invalid params", fd);
        return -1;
    }
    SoftBusSockTimeOut tv = { 0 };
    tv.sec = 0;
    tv.usec = timeout;
    int rc = 0;
    switch (events) {
        case SOFTBUS_SOCKET_OUT: {
            SoftBusFdSet writeSet;
            SoftBusSocketFdZero(&writeSet);
            SoftBusSocketFdSet(fd, &writeSet);
            rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketSelect(fd + 1, NULL, &writeSet, NULL, &tv));
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
            rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketSelect(fd + 1, &readSet, NULL, NULL, &tv));
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
int32_t ConnToggleNonBlockMode(int32_t fd, bool isNonBlock)
{
    if (fd < 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        CONN_LOGE(CONN_COMMON, "fd=%d,fcntl get flag failed, errno=%d", fd, errno);
        return SOFTBUS_ERR;
    }
    if (isNonBlock && ((uint32_t)flags & O_NONBLOCK) == 0) {
        flags = (int32_t)((uint32_t)flags | O_NONBLOCK);
        CONN_LOGI(CONN_COMMON, "fd=%d set to nonblock", fd);
    } else if (!isNonBlock && ((uint32_t)flags & O_NONBLOCK) != 0) {
        flags = (int32_t)((uint32_t)flags & ~O_NONBLOCK);
        CONN_LOGI(CONN_COMMON, "fd=%d set to block", fd);
    } else {
        CONN_LOGI(CONN_COMMON, "fd=%d nonblock state is already ok", fd);
        return SOFTBUS_OK;
    }
    return fcntl(fd, F_SETFL, flags);
}

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    if (fd < 0 || buf == NULL || len == 0) {
        CONN_LOGE(CONN_COMMON, "fd=%d invalid params", fd);
        return -1;
    }

    if (timeout == 0) {
        timeout = USER_TIMEOUT_US;
    }

    int err = WaitEvent(fd, SOFTBUS_SOCKET_OUT, USER_TIMEOUT_US);
    if (err <= 0) {
        CONN_LOGE(CONN_COMMON, "wait event error %d", err);
        return err;
    }
    ssize_t bytes = 0;
    while (1) {
        ssize_t rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketSend(fd, &buf[bytes], len - bytes, 0));
        if (rc == SOFTBUS_ADAPTER_SOCKET_EAGAIN) {
            continue;
        } else if (rc <= 0) {
            if (bytes == 0) {
                bytes = -1;
            }
            CONN_LOGE(CONN_COMMON, "tcp send fail %zd %d", rc, errno);
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
                CONN_LOGE(CONN_COMMON, "send data wait event fail %d", err);
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
        CONN_LOGE(CONN_COMMON, "fd[%d] len[%zu] invalid params", fd, len);
        return -1;
    }

    if (timeout != 0) {
        int err = WaitEvent(fd, SOFTBUS_SOCKET_IN, timeout);
        if (err < 0) {
            CONN_LOGE(CONN_COMMON, "recv data wait event err[%d]", err);
            return err;
        }
    }

    ssize_t rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketRecv(fd, buf, len, flags));
    if (rc == SOFTBUS_ADAPTER_SOCKET_EAGAIN) {
        CONN_LOGW(CONN_COMMON, "recv data socket EAGAIN");
        rc = 0;
    } else if (rc == 0) {
        CONN_LOGE(CONN_COMMON, "recv data fail, peer close connection, fd=%d", fd);
        rc = -1;
    } else if (rc < 0) {
        CONN_LOGE(CONN_COMMON, "recv data fail fd[%d] errno[%d], rc[%d]", fd, errno, rc);
        rc = -1;
    }
    return rc;
}

ssize_t ConnRecvSocketData(int32_t fd, char *buf, size_t len, int32_t timeout)
{
    return OnRecvData(fd, buf, len, timeout, 0);
}

void ConnCloseSocket(int32_t fd)
{
    if (fd >= 0) {
        CONN_LOGI(CONN_COMMON, "close fd=%d", fd);
        SoftBusSocketClose(fd);
    }
}

void ConnShutdownSocket(int32_t fd)
{
    if (fd >= 0) {
        CONN_LOGI(CONN_COMMON, "shutdown fd=%d", fd);
        SoftBusSocketShutDown(fd, SOFTBUS_SHUT_RDWR);
        SoftBusSocketClose(fd);
    }
}

int32_t ConnGetSocketError(int32_t fd)
{
    return SoftBusSocketGetError(fd);
}

int32_t ConnGetLocalSocketPort(int32_t fd)
{
    const SocketInterface *socketInterface = GetSocketInterface(LNN_PROTOCOL_IP);
    if (socketInterface == NULL) {
        CONN_LOGW(CONN_COMMON, "LNN_PROTOCOL_IP not supported!");
        return SOFTBUS_ERR;
    }
    return socketInterface->GetSockPort(fd);
}

int32_t ConnGetPeerSocketAddr(int32_t fd, SocketAddr *socketAddr)
{
    SoftBusSockAddrIn addr;
    if (socketAddr == NULL) {
        CONN_LOGW(CONN_COMMON, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int rc = SoftBusSocketGetPeerName(fd, (SoftBusSockAddr *)&addr);
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "fd=%d, GetPeerName rc=%d", fd, rc);
        return SOFTBUS_ERR;
    }
    if (SoftBusInetNtoP(SOFTBUS_AF_INET, (void *)&addr.sinAddr, socketAddr->addr, sizeof(socketAddr->addr)) == NULL) {
        CONN_LOGE(CONN_COMMON, "fd=%d, InetNtoP fail", fd);
        return SOFTBUS_ERR;
    }
    socketAddr->port = SoftBusNtoHs(addr.sinPort);
    return SOFTBUS_OK;
}
