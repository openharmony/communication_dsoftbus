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


int SoftBusSocketCreate(int domain, int type, int protocol, int *socketFd)
{
    if (socketFd == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socketFd is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret;
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

int SoftBusSocketSetOpt(int socketFd, int level, int optName,  const void *optVal, int optLen)
{
    int ret = setsockopt(socketFd, level, optName, optVal, (socklen_t)optLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "setsockopt : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int SoftBusSocketGetOpt(int socketFd, int level, int optName,  void *optVal, int *optLen)
{
    int ret = getsockopt(socketFd, level, optName, optVal, (socklen_t *)optLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockopt : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusSocketGetLocalName(int socketFd, struct sockaddr *addr, int *addrLen)
{
    int ret = getsockname(socketFd, addr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockname : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusSocketGetPeerName(int socketFd, struct sockaddr *addr, int *addrLen)
{
    int ret = getpeername(socketFd, addr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getpeername : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusSocketBind(int socketFd, struct sockaddr *addr, int addrLen)
{
    int ret = bind(socketFd, addr, addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "bind : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int SoftBusSocketListen(int socketFd, int backLog)
{
    int ret = listen(socketFd, backLog);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "listen : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int SoftBusSocketAccept(int socketFd, struct sockaddr *addr, int *addrLen, int *acceptFd)
{
    if (acceptFd == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "acceptFd is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = accept(socketFd, addr, (socklen_t *)addrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "accept : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    } else {
        *acceptFd = ret;
        return SOFTBUS_OK;
    }
    return SOFTBUS_OK;
}

int SoftBusSocketConnect(int socketFd, const struct sockaddr *addr, int addrLen)
{
    int ret = connect(socketFd, addr, addrLen);
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

void SoftBusSocketFdSet(int socketFd, fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_SET(socketFd, set);

    return ;
}

void SoftBusSocketFdClr(int socketFd, fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_CLR(socketFd, set);

    return ;
}

int SoftBusSocketFdIsset(int socketFd, fd_set *set)
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

int SoftBusSocketSelect(int nfds, fd_set *readFds, fd_set *writeFds, fd_set *exceptFds, struct timeval
    *timeOut)
{
    int ret = select(nfds, readFds, writeFds, exceptFds, timeOut);

    return ret;
}

int SoftBusSocketIoctl(int socketFd, long cmd, void *argp)
{
    int ret = ioctl(socketFd, cmd, argp);

    return ret;
}

int SoftBusSocketSend(int socketFd, const void *buf, unsigned int len, int flags)
{
    int ret = send(socketFd, buf, len, flags);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "send : %{pbulic}s", strerror(errno));
        return -1;
    }

    return ret;
}

int SoftBusSocketSendTo(int socketFd, const void *buf, unsigned int len, int flags, const struct sockaddr
    *toAddr, int toAddrLen)
{
    int ret = sendto(socketFd, buf, len, flags, toAddr, toAddrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "sendto : %{pbulic}s", strerror(errno));
        return -1;
    }

    return ret;
}

int SoftBusSocketRecv(int socketFd, void *buf, unsigned int len, int flags)
{
    int ret = recv(socketFd, buf, len, flags);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "recv : %{pbulic}s", strerror(errno));
        return -1;
    }

    return ret;
}

int SoftBusSocketRecvFrom(int socketFd, void *buf, unsigned int len, int flags, struct sockaddr
    *fromAddr, int *fromAddrLen)
{
    int ret = recvfrom(socketFd, buf, len, flags, fromAddr, (socklen_t *)fromAddrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "recvfrom : %{pbulic}s", strerror(errno));
        return -1;
    }

    return ret;
}

int SoftBusSocketShutDown(int socketFd, int how)
{
    int ret = shutdown(socketFd, how);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "shutdown :%{pbulic}s", strerror(errno));
        return -1;
    }

    return SOFTBUS_OK;
}

int SoftBusSocketClose(int socketFd)
{
    int ret = close(socketFd);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "close : %{pbulic}s", strerror(errno));
        return -1;
    }

    return SOFTBUS_OK;
}
