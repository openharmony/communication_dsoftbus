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
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "softbus_adapter_log.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

static int32_t GetErrorCode(void) {
    int32_t errCode = SOFTBUS_ADAPTER_ERR;
    switch (errno) {
        case EINTR : {
            errCode = SOFTBUS_ADAPTER_SOCKET_EINTR;
            break;
        }
        case EINPROGRESS : {
            errCode = SOFTBUS_ADAPTER_SOCKET_EINPROGRESS;
            break;
        }
        case EAGAIN : {
            errCode = SOFTBUS_ADAPTER_SOCKET_EAGAIN;
            break;
        }
        default : {
            errCode = SOFTBUS_ADAPTER_ERR;
            break;
        }
    }
    return errCode;
}
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

int32_t SoftBusSocketGetLocalName(int32_t socketFd, SoftBusSockAddr *addr, SoftBusSockLen *addrLen)
{
    int32_t ret = getsockname(socketFd, (struct sockaddr *)addr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockname : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr, SoftBusSockLen *addrLen)
{
    int32_t ret = getpeername(socketFd, (struct sockaddr *)addr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getpeername : %{pbulic}s", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, SoftBusSockLen addrLen)
{
    int32_t ret = bind(socketFd, (struct sockaddr *)addr, (socklen_t)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "bind : %{pbulic}s", strerror(errno));
        return GetErrorCode();
    }

    return SOFTBUS_ADAPTER_OK;
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

int32_t SoftBusSocketAccept(int32_t socketFd, SoftBusSockAddr *addr, SoftBusSockLen *addrLen, int32_t *acceptFd)
{
    if (acceptFd == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "acceptFd is null");
        return SOFTBUS_ADAPTER_INVALID_PARAM;
    }
    int32_t ret = accept(socketFd, (struct sockaddr *)addr, (socklen_t *)addrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "accept : %{pbulic}s", strerror(errno));
        return GetErrorCode();
    } else {
        *acceptFd = ret;
        return SOFTBUS_ADAPTER_OK;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketConnect(int32_t socketFd, const SoftBusSockAddr *addr, SoftBusSockLen addrLen)
{
    int32_t ret = connect(socketFd, (struct sockaddr *)addr, (socklen_t)addrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "connect :%{pbulic}s", strerror(errno));
        return GetErrorCode();
    }
    return SOFTBUS_ADAPTER_OK;
}

void SoftBusSocketFdZero(fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_ZERO(set);
}

void SoftBusSocketFdSet(int32_t socketFd, fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_SET(socketFd, set);
}

void SoftBusSocketFdClr(int32_t socketFd, fd_set *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_CLR(socketFd, set);
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
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "select : %{pbulic}s", strerror(errno));
        return GetErrorCode();
    }

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
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketSendTo(int32_t socketFd, const void *buf, uint32_t len, int32_t flags, const SoftBusSockAddr
    *toAddr, int32_t toAddrLen)
{
    int32_t ret = sendto(socketFd, buf, len, flags, (struct sockaddr *)toAddr, toAddrLen);
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
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketRecvFrom(int32_t socketFd, void *buf, uint32_t len, int32_t flags, SoftBusSockAddr
    *fromAddr, SoftBusSockLen *fromAddrLen)
{
    int32_t ret = recvfrom(socketFd, buf, len, flags, (struct sockaddr *)fromAddr, (socklen_t *)fromAddrLen);
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

int32_t SoftBusInetPtoN(int32_t af, const char *src, void *dst)
{
    int32_t ret = inet_pton(af, src, dst);
    if (ret == 1) {
        return SOFTBUS_ADAPTER_OK;
    } else if (ret == 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid str input fromat");
        return SOFTBUS_ADAPTER_INVALID_PARAM;
    } else {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "inet_pton failed");
        return SOFTBUS_ADAPTER_ERR;
    }
}

char *SoftBusInetNtoP(int32_t af, const void* src, char *dst, int32_t size)
{
    return (inet_ntop(af, src, dst, size));
}

uint32_t SoftBusHtoNl(uint32_t hostlong)
{
    return htonl(hostlong);
}

uint16_t SoftBusHtoNs(uint16_t hostshort)
{
    return htons(hostshort);
}

uint32_t SoftBusNtoHl(uint32_t netlong)
{
    return ntohl(netlong);
}

uint16_t SoftBusNtoHs(uint16_t netshort)
{
    return ntohs(netshort);
}