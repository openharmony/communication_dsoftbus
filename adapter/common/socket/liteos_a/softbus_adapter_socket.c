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

#include "softbus_adapter_socket.h"
#include <pthread.h>
#include <string.h>

#include "softbus_adapter_log.h"
#include "softbus_def.h"
#include "softbus_errcode.h"


int32_t SoftBusSocketCreate(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd)
{
    if (socketFd == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socketFd is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;
    ret = socket(domain, type, protocol);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    } else {
        *socketFd = ret;
        return SOFTBUS_OK;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusSocketSetOpt(int32_t socketFd, int32_t level, int32_t optName, const void *optVal, int32_t optLen)
{
    int32_t ret = setsockopt(socketFd, level, optName, optVal, (socklen_t)optLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "setsockopt : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusSocketGetOpt(int32_t socketFd, int32_t level, int32_t optName,  void *optVal, int32_t *optLen)
{
    int32_t ret = getsockopt(socketFd, level, optName, optVal, (socklen_t *)optLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockopt : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusSocketGetLocalName(int32_t socketFd, struct sockaddr *addr, int32_t *addrLen)
{
    int32_t ret = getsockname(socketFd, addr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockname : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, struct sockaddr *addr, int32_t *addrLen)
{
    int32_t ret = getpeername(socketFd, addr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getpeername : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusSocketBind(int32_t socketFd, struct sockaddr *addr, int32_t addrLen)
{
    int32_t ret = bind(socketFd, addr, addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "bind : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusSocketListen(int32_t socketFd, int32_t backLog)
{
    int32_t ret = listen(socketFd, backLog);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "listen : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusSocketAccept(int32_t socketFd, struct sockaddr *addr, int32_t *addrLen, int32_t *acceptFd)
{
    if (acceptFd == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "acceptFd is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = accept(socketFd, addr, (socklen_t *)addrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "accept : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    } else {
        *acceptFd = ret;
        return SOFTBUS_OK;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusSocketConnect(int32_t socketFd, const struct sockaddr *addr, int32_t addrLen)
{
    int32_t ret = connect(socketFd, addr, addrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "connect :%{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void SoftBusSocketFdZero(fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_ZERO(set);

    return ;
}

void SoftBusSocketFdSet(int32_t socketFd, fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_SET(socketFd, set);

    return ;
}

void SoftBusSocketFdClr(int32_t socketFd, fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_CLR(socketFd, set);

    return ;
}

int32_t SoftBusSocketFdIsset(int32_t socketFd, fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return 0;
    }

    if (FD_ISSET(socketFd, set) == true) {
        return 1;
    } else {
        return 0;
    }
}

int32_t SoftBusSocketSelect(int32_t nfds, fd_set *readFds, fd_set *writeFds, fd_set *exceptFds, struct timeval
    *timeOut)
{
    int32_t ret = select(nfds, readFds, writeFds, exceptFds, timeOut);

    return ret;
}

int32_t SoftBusSocketIoctl(int32_t socketFd, long cmd, void *argp)
{
    int32_t ret = ioctl(socketFd, cmd, argp);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ioctl : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return ret;
}

int32_t SoftBusSocketSend(int32_t socketFd, const void *buf, uint32_t len, int32_t flags)
{
    int32_t ret = send(socketFd, buf, len, flags);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "send : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return ret;
}

int32_t SoftBusSocketSendTo(int32_t socketFd, const void *buf, uint32_t len, int32_t flags, const struct sockaddr
    *toAddr, int32_t toAddrLen)
{
    int32_t ret = sendto(socketFd, buf, len, flags, toAddr, toAddrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "sendto : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return ret;
}

int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, uint32_t len, int32_t flags)
{
    int32_t ret = recv(socketFd, buf, len, flags);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "recv : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return ret;
}

int32_t SoftBusSocketRecvFrom(int32_t socketFd, void *buf, uint32_t len, int32_t flags, struct sockaddr
    *fromAddr, int32_t *fromAddrLen)
{
    int32_t ret = recvfrom(socketFd, buf, len, flags, fromAddr, (socklen_t *)fromAddrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "recvfrom : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return ret;
}

int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how)
{
    int32_t ret = shutdown(socketFd, how);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "shutdown :%{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusSocketClose(int32_t socketFd)
{
    int32_t ret = close(socketFd);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "close : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}
