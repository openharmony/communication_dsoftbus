/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <unistd.h>

#include "comm_log.h"
#include "endian.h" /* liteos_m htons */
#include "softbus_adapter_errcode.h"
#include "softbus_def.h"

static void ShiftByte(uint8_t *in, int8_t inSize)
{
    int8_t left = 0;
    int8_t right = inSize - 1;
    while (left < right) {
        in[left] ^= in[right];
        in[right] ^= in[left];
        in[left] ^= in[right];
        ++left;
        --right;
    }
}

static int32_t GetErrorCode(void)
{
    int32_t errCode;
    switch (errno) {
        case EINTR:
            errCode = SOFTBUS_ADAPTER_SOCKET_EINTR;
            break;
        case EINPROGRESS:
            errCode = SOFTBUS_ADAPTER_SOCKET_EINPROGRESS;
            break;
        case EAGAIN:
            errCode = SOFTBUS_ADAPTER_SOCKET_EAGAIN;
            break;
        case EBADF:
            errCode = SOFTBUS_ADAPTER_SOCKET_EBADF;
            break;
        case EINVAL:
            errCode = SOFTBUS_ADAPTER_SOCKET_EINVAL;
            break;
        case ENETUNREACH:
            errCode = SOFTBUS_ADAPTER_SOCKET_ENETUNREACH;
            break;
        default:
            errCode = SOFTBUS_ADAPTER_ERR;
            break;
    }
    return errCode;
}

int32_t SoftBusSocketCreate(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd)
{
    if (socketFd == NULL) {
        COMM_LOGE(COMM_ADAPTER, "socketFd is null");
        return SOFTBUS_ADAPTER_INVALID_PARAM;
    }
    int32_t ret = socket(domain, type, protocol);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "socket errno=%{public}s", strerror(errno));
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
        COMM_LOGE(COMM_ADAPTER, "setsockopt errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetOpt(int32_t socketFd, int32_t level, int32_t optName, void *optVal, int32_t *optLen)
{
    int32_t ret = getsockopt(socketFd, level, optName, optVal, (socklen_t *)optLen);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "getsockopt errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetError(int32_t socketFd)
{
    int32_t err = 0;
    socklen_t errSize = sizeof(err);
    int32_t ret = getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &err, &errSize);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "getsockopt fd=%{public}d, ret=%{public}d", socketFd, ret);
        return ret;
    }
    if (err != 0) {
        COMM_LOGE(COMM_ADAPTER, "getsockopt fd=%{public}d, err=%{public}d", socketFd, err);
        return err;
    }
    return err;
}

static int32_t SoftBusAddrToSysAddr(const SoftBusSockAddr *softbusAddr, struct sockaddr *sysAddr, uint32_t len)
{
    if ((softbusAddr == NULL) || (sysAddr == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "invalid input");
        return SOFTBUS_ADAPTER_ERR;
    }
    if (len < sizeof(softbusAddr->saFamily)) {
        COMM_LOGE(COMM_ADAPTER, "invalid len");
        return SOFTBUS_ADAPTER_ERR;
    }
    if (memset_s(sysAddr, sizeof(struct sockaddr), 0, sizeof(struct sockaddr)) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "memset fail");
        return SOFTBUS_ADAPTER_ERR;
    }
    sysAddr->sa_family = softbusAddr->saFamily;
    if (memcpy_s(sysAddr->sa_data, sizeof(sysAddr->sa_data), softbusAddr->saData,
            len - sizeof(softbusAddr->saFamily)) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "memcpy fail");
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

static int32_t SysAddrToSoftBusAddr(const struct sockaddr *sysAddr, SoftBusSockAddr *softbusAddr)
{
    if (memset_s(softbusAddr, sizeof(SoftBusSockAddr), 0, sizeof(SoftBusSockAddr)) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "memset fail");
        return SOFTBUS_ADAPTER_ERR;
    }
    softbusAddr->saFamily = sysAddr->sa_family;
    if (memcpy_s(softbusAddr->saData, sizeof(softbusAddr->saData), sysAddr->sa_data, sizeof(sysAddr->sa_data))
        != EOK) {
        COMM_LOGE(COMM_ADAPTER, "memcpy fail");
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetLocalName(int32_t socketFd, SoftBusSockAddr *addr)
{
    if (addr == NULL) {
        COMM_LOGE(COMM_ADAPTER, "get local name invalid input");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    uint32_t len = sizeof(struct sockaddr);
    if (memset_s(&sysAddr, len, 0, len) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "get local name memset fail");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = getsockname(socketFd, &sysAddr, (socklen_t *)&len);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "getsockname errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }
    if (SysAddrToSoftBusAddr(&sysAddr, addr) != SOFTBUS_ADAPTER_OK) {
        COMM_LOGE(COMM_ADAPTER, "get local name sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr)
{
    if (addr == NULL) {
        COMM_LOGE(COMM_ADAPTER, "get peer name invalid input");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    if (memset_s(&sysAddr, sizeof(struct sockaddr), 0, sizeof(struct sockaddr)) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "get peer name memset fail");
        return SOFTBUS_ADAPTER_ERR;
    }
    uint32_t len = sizeof(sysAddr);
    int32_t ret = getpeername(socketFd, &sysAddr, (socklen_t *)&len);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "getpeername errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }
    if (SysAddrToSoftBusAddr(&sysAddr, addr) != SOFTBUS_ADAPTER_OK) {
        COMM_LOGE(COMM_ADAPTER, "get peer name sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen)
{
    if (addr == NULL || addrLen < 0) {
        COMM_LOGE(COMM_ADAPTER, "socket bind invalid input");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    uint32_t len = ((uint32_t)addrLen >= sizeof(SoftBusSockAddr)) ? sizeof(SoftBusSockAddr) : (uint32_t)addrLen;
    if (SoftBusAddrToSysAddr(addr, &sysAddr, len) != SOFTBUS_ADAPTER_OK) {
        COMM_LOGE(COMM_ADAPTER, "socket bind sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = bind(socketFd, &sysAddr, (socklen_t)addrLen);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "bind strerror=%{public}s, errno=%{public}d", strerror(errno), errno);
        return GetErrorCode();
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketListen(int32_t socketFd, int32_t backLog)
{
    int32_t ret = listen(socketFd, backLog);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "listen strerror=%{public}s, errno=%{public}d", strerror(errno), errno);
        return SOFTBUS_ADAPTER_ERR;
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketAccept(int32_t socketFd, SoftBusSockAddr *addr, int32_t *acceptFd)
{
    if (addr == NULL || acceptFd == NULL) {
        COMM_LOGE(COMM_ADAPTER, "socket accept invalid input");
        return SOFTBUS_ADAPTER_INVALID_PARAM;
    }
    struct sockaddr sysAddr;
    uint32_t len = sizeof(sysAddr);
    if (memset_s(&sysAddr, len, 0, len) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "memset failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = accept(socketFd, &sysAddr, (socklen_t *)&len);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "accept strerror=%{public}s, errno=%{public}d", strerror(errno), errno);
        return GetErrorCode();
    }
    if (SysAddrToSoftBusAddr(&sysAddr, addr) != SOFTBUS_ADAPTER_OK) {
        COMM_LOGE(COMM_ADAPTER, "socket accept sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    *acceptFd = ret;
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketConnect(int32_t socketFd, const SoftBusSockAddr *addr)
{
    struct sockaddr sysAddr;
    if (SoftBusAddrToSysAddr(addr, &sysAddr, sizeof(SoftBusSockAddr)) != SOFTBUS_ADAPTER_OK) {
        COMM_LOGE(COMM_ADAPTER, "socket connect sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    uint32_t len = sizeof(sysAddr);
    int32_t ret = connect(socketFd, &sysAddr, (socklen_t)len);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "connect=%{public}s", strerror(errno));
        return GetErrorCode();
    }
    return SOFTBUS_ADAPTER_OK;
}

void SoftBusSocketFdZero(SoftBusFdSet *set)
{
    if (set == NULL) {
        COMM_LOGE(COMM_ADAPTER, "set is null");
        return;
    }

    FD_ZERO((fd_set *)set->fdsBits);
}

void SoftBusSocketFdSet(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        COMM_LOGE(COMM_ADAPTER, "set is null");
        return;
    }
    if (socketFd >= SOFTBUS_FD_SETSIZE) {
        COMM_LOGE(COMM_ADAPTER, "socketFd is too big. socketFd=%{public}d", socketFd);
        return;
    }

    FD_SET(socketFd, (fd_set *)set->fdsBits);
}

void SoftBusSocketFdClr(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        COMM_LOGE(COMM_ADAPTER, "set is null");
        return;
    }

    FD_CLR(socketFd, (fd_set *)set->fdsBits);
}

int32_t SoftBusSocketFdIsset(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        COMM_LOGE(COMM_ADAPTER, "set is null");
        return 0;
    }
    if (socketFd >= SOFTBUS_FD_SETSIZE) {
        COMM_LOGE(COMM_ADAPTER, "socketFd is too big. socketFd=%{public}d", socketFd);
        return 0;
    }

    if (FD_ISSET(socketFd, (fd_set *)set->fdsBits) == true) {
        return 1;
    } else {
        return 0;
    }
}

int32_t SoftBusSocketSelect(
    int32_t nfds, SoftBusFdSet *readFds, SoftBusFdSet *writeFds, SoftBusFdSet *exceptFds, SoftBusSockTimeOut *timeout)
{
    fd_set *tempReadSet = NULL;
    fd_set *tempWriteSet = NULL;
    fd_set *tempExceptSet = NULL;

    if (readFds != NULL) {
        tempReadSet = (fd_set *)readFds->fdsBits;
    }
    if (writeFds != NULL) {
        tempWriteSet = (fd_set *)writeFds->fdsBits;
    }
    if (exceptFds != NULL) {
        tempExceptSet = (fd_set *)exceptFds->fdsBits;
    }

    struct timeval *timeoutPtr = NULL;
    struct timeval tv = { 0 };
    if (timeout != NULL) {
        tv.tv_sec = timeout->sec;
        tv.tv_usec = timeout->usec;
        timeoutPtr = &tv;
    }
#define SELECT_INTERVAL_US (100 * 1000)
#ifdef __LITEOS__
    tv.tv_sec = 0;
    tv.tv_usec = SELECT_INTERVAL_US;
    timeoutPtr = &tv;
#endif
    int32_t ret = select(nfds, tempReadSet, tempWriteSet, tempExceptSet, timeoutPtr);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "select errno=%{public}s", strerror(errno));
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketIoctl(int32_t socketFd, long cmd, void *argp)
{
    int32_t ret = ioctl(socketFd, cmd, argp);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "ioctl errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusSocketFcntl(int32_t socketFd, long cmd, long flag)
{
    int32_t ret = fcntl(socketFd, cmd, flag);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "fcntl errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusSocketSend(int32_t socketFd, const void *buf, uint32_t len, int32_t flags)
{
    int32_t wrapperFlag = flags | MSG_NOSIGNAL;
    int32_t ret = send(socketFd, buf, len, wrapperFlag);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "send errno=%{public}s", strerror(errno));
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketSendTo(int32_t socketFd, const void *buf, uint32_t len, int32_t flags,
    const SoftBusSockAddr *toAddr, int32_t toAddrLen)
{
    if ((toAddr == NULL) || (toAddrLen <= 0)) {
        COMM_LOGE(COMM_ADAPTER, "toAddr is null or toAddrLen <= 0");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    if (SoftBusAddrToSysAddr(toAddr, &sysAddr, sizeof(SoftBusSockAddr)) != SOFTBUS_ADAPTER_OK) {
        COMM_LOGE(COMM_ADAPTER, "socket sendto sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = sendto(socketFd, buf, len, flags, &sysAddr, toAddrLen);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "sendto errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, uint32_t len, int32_t flags)
{
    int32_t ret = recv(socketFd, buf, len, flags);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "recv errno=%{public}s", strerror(errno));
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketRecvFrom(int32_t socketFd, void *buf, uint32_t len, int32_t flags, SoftBusSockAddr *fromAddr,
    int32_t *fromAddrLen)
{
    if ((fromAddr == NULL) || (fromAddrLen == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "fromAddr or fromAddrLen is null");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    if (SoftBusAddrToSysAddr(fromAddr, &sysAddr, sizeof(SoftBusSockAddr)) != SOFTBUS_ADAPTER_OK) {
        COMM_LOGE(COMM_ADAPTER, "socket recvfrom sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = recvfrom(socketFd, buf, len, flags, &sysAddr, (socklen_t *)fromAddrLen);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "recvfrom errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how)
{
    int32_t ret = shutdown(socketFd, how);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "shutdown=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketClose(int32_t socketFd)
{
    int32_t ret = close(socketFd);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "close errno=%{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusInetPtoN(int32_t af, const char *src, void *dst)
{
    if (src == NULL || dst == NULL) {
        COMM_LOGE(COMM_ADAPTER, "src or dst is null");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = inet_pton(af, src, dst);
    if (ret == 1) {
        return SOFTBUS_ADAPTER_OK;
    } else if (ret == 0) {
        COMM_LOGE(COMM_ADAPTER, "invalid str input fromat");
        return SOFTBUS_ADAPTER_INVALID_PARAM;
    } else {
        COMM_LOGE(COMM_ADAPTER, "inet_pton failed");
        return SOFTBUS_ADAPTER_ERR;
    }
}

const char *SoftBusInetNtoP(int32_t af, const void *src, char *dst, int32_t size)
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

static bool IsLittleEndian(void)
{
    uint32_t data = 0x1;
    if (data == ntohl(data)) {
        return false;
    } else {
        return true;
    }
}

static void ProcByteOrder(uint8_t *value, int8_t size)
{
    if (IsLittleEndian()) {
        return;
    }
    ShiftByte(value, size);
}

uint16_t SoftBusHtoLs(uint16_t value)
{
    uint16_t res = value;
    ProcByteOrder((uint8_t *)&res, (int8_t)sizeof(res));
    return res;
}

uint32_t SoftBusHtoLl(uint32_t value)
{
    uint32_t res = value;
    ProcByteOrder((uint8_t *)&res, (int8_t)sizeof(res));
    return res;
}

uint64_t SoftBusHtoLll(uint64_t value)
{
    uint64_t res = value;
    ProcByteOrder((uint8_t *)&res, (int8_t)sizeof(res));
    return res;
}

uint16_t SoftBusLtoHs(uint16_t value)
{
    uint16_t res = value;
    ProcByteOrder((uint8_t *)&res, (int8_t)sizeof(res));
    return res;
}

uint32_t SoftBusLtoHl(uint32_t value)
{
    uint32_t res = value;
    ProcByteOrder((uint8_t *)&res, (int8_t)sizeof(res));
    return res;
}

uint64_t SoftBusLtoHll(uint64_t value)
{
    uint64_t res = value;
    ProcByteOrder((uint8_t *)&res, (int8_t)sizeof(res));
    return res;
}

uint16_t SoftBusLEtoBEs(uint16_t value)
{
    if (!IsLittleEndian()) {
        return value;
    }
    uint16_t res = value;
    ShiftByte((uint8_t *)&res, (int8_t)sizeof(res));
    return res;
}

uint16_t SoftBusBEtoLEs(uint16_t value)
{
    if (!IsLittleEndian()) {
        return value;
    }
    uint16_t res = value;
    ShiftByte((uint8_t *)&res, (int8_t)sizeof(res));
    return res;
}