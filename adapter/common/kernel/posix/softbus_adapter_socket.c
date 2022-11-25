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
        default:
            errCode = SOFTBUS_ADAPTER_ERR;
            break;
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

int32_t SoftBusSocketGetError(int32_t socketFd)
{
    int err = 0;
    socklen_t errSize = sizeof(err);
    int32_t ret = getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &err, &errSize);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockopt fd=%{public}d, ret=%{public}d", socketFd, ret);
        return ret;
    }
    if (err != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockopt fd=%{public}d, err=%{public}d", socketFd, err);
        return err;
    }
    return err;
}

static int32_t SoftBusAddrToSysAddr(const SoftBusSockAddr *softbusAddr, struct sockaddr * sysAddr, uint32_t len)
{
    if (len < sizeof(softbusAddr->saFamily)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "%s:invalid len", __func__);
        return SOFTBUS_ADAPTER_ERR;
    }
    if ((softbusAddr == NULL) || (sysAddr == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "%s:invalid input", __func__);
        return SOFTBUS_ADAPTER_ERR;
    }
    if (memset_s(sysAddr, sizeof(struct sockaddr), 0, sizeof(struct sockaddr)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "%s:memset fail", __func__);
        return SOFTBUS_ADAPTER_ERR;
    }
    sysAddr->sa_family = softbusAddr->saFamily;
    if (memcpy_s(sysAddr->sa_data, sizeof(sysAddr->sa_data), softbusAddr->saData, len - sizeof(softbusAddr->saFamily))
        != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "%s:memcpy fail", __func__);
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

static int32_t SysAddrToSoftBusAddr(const struct sockaddr *sysAddr, SoftBusSockAddr *softbusAddr)
{
    if (memset_s(softbusAddr, sizeof(SoftBusSockAddr), 0, sizeof(SoftBusSockAddr)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "%s:memset fail", __func__);
        return SOFTBUS_ADAPTER_ERR;
    }
    softbusAddr->saFamily = sysAddr->sa_family;
    if (memcpy_s(softbusAddr->saData, sizeof(softbusAddr->saData), sysAddr->sa_data, sizeof(sysAddr->sa_data))
        != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "%s:memcpy fail", __func__);
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetLocalName(int32_t socketFd, SoftBusSockAddr *addr, int32_t *addrLen)
{
    if (addr == NULL || addrLen == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "get local name invalid input");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    if (memset_s(&sysAddr, sizeof(struct sockaddr), 0, sizeof(struct sockaddr)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "get local name memset fail");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = getsockname(socketFd, &sysAddr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getsockname : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }
    if (SysAddrToSoftBusAddr(&sysAddr, addr) != SOFTBUS_ADAPTER_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "get local name sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr, int32_t *addrLen)
{
    if (addr == NULL || addrLen == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "get peer name invalid input");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    if (memset_s(&sysAddr, sizeof(struct sockaddr), 0, sizeof(struct sockaddr)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "get peer name memset fail");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = getpeername(socketFd, &sysAddr, (socklen_t *)addrLen);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "getpeername : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }
    if (SysAddrToSoftBusAddr(&sysAddr, addr) != SOFTBUS_ADAPTER_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "get peer name sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen)
{
    if (addrLen < 0) {
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    uint32_t len = (sizeof(SoftBusSockAddr) > (uint32_t)addrLen) ? (uint32_t)addrLen : sizeof(SoftBusSockAddr);
    if (SoftBusAddrToSysAddr(addr, &sysAddr, len) != SOFTBUS_ADAPTER_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket bind sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = bind(socketFd, &sysAddr, (socklen_t)addrLen);
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
    if (addr == NULL || addrLen == NULL || acceptFd == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket accept invalid input");
        return SOFTBUS_ADAPTER_INVALID_PARAM;
    }
    struct sockaddr sysAddr;
    if (SoftBusAddrToSysAddr(addr, &sysAddr, sizeof(SoftBusSockAddr)) != SOFTBUS_ADAPTER_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket accept softbus addr to sys addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = accept(socketFd, &sysAddr, (socklen_t *)addrLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "accept : %{public}s", strerror(errno));
        return GetErrorCode();
    }
    if (SysAddrToSoftBusAddr(&sysAddr, addr) != SOFTBUS_ADAPTER_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket accept sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    *acceptFd = ret;
    return SOFTBUS_ADAPTER_OK;
}

int32_t SoftBusSocketConnect(int32_t socketFd, const SoftBusSockAddr *addr, int32_t addrLen)
{
    struct sockaddr sysAddr;
    if (SoftBusAddrToSysAddr(addr, &sysAddr, sizeof(SoftBusSockAddr)) != SOFTBUS_ADAPTER_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket connect sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = connect(socketFd, &sysAddr, (socklen_t)addrLen);
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

    FD_ZERO((fd_set *)set->fdsBits);
}

void SoftBusSocketFdSet(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_SET(socketFd, (fd_set *)set->fdsBits);
}

void SoftBusSocketFdClr(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return;
    }

    FD_CLR(socketFd, (fd_set *)set->fdsBits);
}

int32_t SoftBusSocketFdIsset(int32_t socketFd, SoftBusFdSet *set)
{
    if (set == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set is null");
        return 0;
    }

    if (FD_ISSET(socketFd, (fd_set *)set->fdsBits) == true) {
        return 1;
    } else {
        return 0;
    }
}

int32_t SoftBusSocketSelect(int32_t nfds, SoftBusFdSet *readFds, SoftBusFdSet *writeFds, SoftBusFdSet *exceptFds,
    SoftBusSockTimeOut *timeOut)
{
    if (timeOut == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "timeOut is null");
        return SOFTBUS_ADAPTER_ERR;
    }
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

    struct timeval sysTimeOut = {0};

    sysTimeOut.tv_sec = timeOut->sec;
    sysTimeOut.tv_usec = timeOut->usec;
    int32_t ret = select(nfds, tempReadSet, tempWriteSet, tempExceptSet, &sysTimeOut);
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

int32_t SoftBusSocketFcntl(int32_t socketFd, long cmd, long flag)
{
    int32_t ret = fcntl(socketFd, cmd, flag);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "fcntl : %{public}s", strerror(errno));
        return SOFTBUS_ADAPTER_ERR;
    }

    return ret;
}

int32_t SoftBusSocketSend(int32_t socketFd, const void *buf, uint32_t len, int32_t flags)
{
    int32_t wrapperFlag = flags | MSG_NOSIGNAL;
    int32_t ret = send(socketFd, buf, len, wrapperFlag);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "send : %{public}s", strerror(errno));
        return GetErrorCode();
    }

    return ret;
}

int32_t SoftBusSocketSendTo(int32_t socketFd, const void *buf, uint32_t len, int32_t flags,
    const SoftBusSockAddr *toAddr, int32_t toAddrLen)
{
    if ((toAddr == NULL) || (toAddrLen <= 0)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "toAddr is null or toAddrLen <= 0");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    if (SoftBusAddrToSysAddr(toAddr, &sysAddr, sizeof(SoftBusSockAddr)) != SOFTBUS_ADAPTER_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket sendto sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = sendto(socketFd, buf, len, flags, &sysAddr, toAddrLen);
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

int32_t SoftBusSocketRecvFrom(int32_t socketFd, void *buf, uint32_t len, int32_t flags, SoftBusSockAddr *fromAddr,
    int32_t *fromAddrLen)
{
    if ((fromAddr == NULL) || (fromAddrLen == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "fromAddr or fromAddrLen is null");
        return SOFTBUS_ADAPTER_ERR;
    }
    struct sockaddr sysAddr;
    if (SoftBusAddrToSysAddr(fromAddr, &sysAddr, sizeof(SoftBusSockAddr)) != SOFTBUS_ADAPTER_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "socket recvfrom sys addr to softbus addr failed");
        return SOFTBUS_ADAPTER_ERR;
    }
    int32_t ret = recvfrom(socketFd, buf, len, flags, &sysAddr, (socklen_t *)fromAddrLen);
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
    return;
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