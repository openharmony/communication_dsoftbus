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
#include <fcntl.h>
#include <netinet/in.h>
#include <securec.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "endian.h" /* liteos_m htons */
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_log.h"
#include "softbus_def.h"


static int32_t GetErrorCode(void)
{
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
        return SOFTBUS_ADAPTER_INVALID_PARAM;
    }
    int32_t ret;
    ret = socket(domain, type, protocol);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    } else {
        *socketFd = ret;
        return SOFTBUS_ADAPTER_OK;
    }
}

int32_t SoftBusSocketSetOpt(int32_t socketFd, int32_t level, int32_t optName, const void *optVal, int32_t optLen)
{
    int32_t ret = setsockopt(socketFd, level, optName, optVal, (socklen_t)optLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "setsockopt : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetOpt(int32_t socketFd, int32_t level, int32_t optName,  void *optVal, int32_t *optLen)
{
    int32_t ret = getsockopt(socketFd, level, optName, optVal, (socklen_t *)optLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockopt : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetLocalName(int32_t socketFd, SoftBusSockAddr *addr, int32_t *addrLen)
{
    int32_t ret = getsockname(socketFd, (struct sockaddr *)addr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockname : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr, int32_t *addrLen)
{
    int32_t ret = getpeername(socketFd, (struct sockaddr *)addr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getpeername : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen)
{
    int32_t ret = bind(socketFd, (struct sockaddr *)addr, (socklen_t)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "bind : %{public}s", strerror(errno));
        return GetErrorCode();
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketListen(int32_t socketFd, int32_t backLog)
{
    int32_t ret = listen(socketFd, backLog);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "listen : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketAccept(int32_t socketFd, SoftBusSockAddr *addr, int32_t *addrLen, int32_t *acceptFd)
{
    if (acceptFd == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "acceptFd is null");
        return SOFTBUS_ADAPTER_INVALID_PARAM;
    }
    int32_t ret = accept(socketFd, (struct sockaddr *)addr, (socklen_t *)addrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "accept : %{public}s", strerror(errno));
        return GetErrorCode();
    } else {
        *acceptFd = ret;
        return SOFTBUS_ADAPTER_OK;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketConnect(int32_t socketFd, const SoftBusSockAddr *addr, int32_t addrLen)
{
    int32_t ret = connect(socketFd, (struct sockaddr *)addr, (socklen_t)addrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "connect :%{public}s", strerror(errno));
        return GetErrorCode();
    }
    return SOFTBUS_ADAPTER_OK;
}

void SoftBusSocketFdZero(SoftBusFdSet *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }
    fd_set tempSet;
    if (memcpy_s(&tempSet, sizeof(tempSet), set->fdsBits, sizeof(set->fdsBits)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "memcpy_s FD_ZERO error");
        return;
    }
    FD_ZERO(&tempSet);
}

void SoftBusSocketFdSet(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }
    fd_set tempSet;
    if (memcpy_s(&tempSet, sizeof(tempSet), set->fdsBits, sizeof(set->fdsBits)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "memcpy_s FD_SET error");
        return;
    }
    FD_SET(socketFd, &tempSet);
}

void SoftBusSocketFdClr(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }
    fd_set tempSet;
    if (memcpy_s(&tempSet, sizeof(tempSet), set->fdsBits, sizeof(set->fdsBits)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "memcpy_s FD_CLR error");
        return;
    }
    FD_CLR(socketFd, &tempSet);
}

int32_t SoftBusSocketFdIsset(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return 0;
    }
    fd_set tempSet;
    if (memcpy_s(&tempSet, sizeof(tempSet), set->fdsBits, sizeof(set->fdsBits)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "memcpy_s FD_ISSET error");
        return 0;
    }
    if (FD_ISSET(socketFd, &tempSet) == true) {
        return 1;
    } else {
        return 0;
    }
}

int32_t SoftBusSocketSelect(int32_t nfds, SoftBusFdSet *readFds, SoftBusFdSet *writeFds, SoftBusFdSet
    *exceptFds, struct timeval *timeOut)
{
    fd_set tempReadSet;
    fd_set tempWriteSet;
    fd_set tempExceptSet;
    if (memcpy_s(&tempReadSet, sizeof(tempReadSet), readFds->fdsBits, sizeof(readFds->fdsBits)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "memcpy_s ReadSet error");
        return SOFTBUS_ADAPTER_ERR;
    }
    if (memcpy_s(&tempWriteSet, sizeof(tempWriteSet), writeFds->fdsBits, sizeof(writeFds->fdsBits)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "memcpy_s WriteSet error");
        return SOFTBUS_ADAPTER_ERR;
    }
    if (memcpy_s(&tempExceptSet, sizeof(tempExceptSet), exceptFds->fdsBits, sizeof(exceptFds->fdsBits)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "memcpy_s ExceptSet error");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = select(nfds, &tempReadSet, &tempWriteSet, &tempWriteSet, timeOut);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "select : %{public}s", strerror(errno));
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketIoctl(int32_t socketFd, long cmd, void *argp)
{
    int32_t ret = ioctl(socketFd, cmd, argp);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ioctl : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusFcntl(int32_t socketFd, long cmd, void *argp)
{
    int32_t ret = fcntl(socketFd, cmd, argp);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "fcntl : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusSocketSend(int32_t socketFd, const void *buf, uint32_t len, int32_t flags)
{
    int32_t ret = send(socketFd, buf, len, flags);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "send : %{public}s", strerror(errno));
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketSendTo(int32_t socketFd, const void *buf, uint32_t len, int32_t flags, const SoftBusSockAddr
    *toAddr, int32_t toAddrLen)
{
    int32_t ret = sendto(socketFd, buf, len, flags, (struct sockaddr *)toAddr, toAddrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "sendto : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, uint32_t len, int32_t flags)
{
    int32_t ret = recv(socketFd, buf, len, flags);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "recv : %{public}s", strerror(errno));
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketRecvFrom(int32_t socketFd, void *buf, uint32_t len, int32_t flags, SoftBusSockAddr
    *fromAddr, int32_t *fromAddrLen)
{
    int32_t ret = recvfrom(socketFd, buf, len, flags, (struct sockaddr *)fromAddr, (socklen_t *)fromAddrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "recvfrom : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how)
{
    int32_t ret = shutdown(socketFd, how);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "shutdown :%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketClose(int32_t socketFd)
{
    int32_t ret = close(socketFd);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "close : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return SOFTBUS_ADAPTER_OK;
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

const char *SoftBusInetNtoP(int32_t af, const void* src, char *dst, int32_t size)
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

uint32_t SoftBusInetAddr(const char *cp)
{
    return inet_addr(cp);
}
