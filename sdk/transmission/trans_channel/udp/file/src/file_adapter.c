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

#include "file_adapter.h"

#include <securec.h>
#include <unistd.h>

#include "client_trans_tcp_direct_listener.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_conn_common.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "trans_log.h"

#define DEFAULT_KEY_LENGTH 32

static int SetReuseAddr(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &on, sizeof(on));
    if (rc != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "set SO_REUSEADDR error. fd=%{public}d", fd);
        return SOFTBUS_INVALID_FD;
    }
    return SOFTBUS_OK;
}

static int SetReusePort(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEPORT, &on, sizeof(on));
    if (rc != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "set SO_REUSEPORT error. fd=%{public}d", fd);
        return SOFTBUS_INVALID_FD;
    }
    return SOFTBUS_OK;
}

static int CreateServerSocketByIpv4(const char *ip, int port, uint32_t capabilityValue)
{
    SoftBusSockAddrIn addr;
    int32_t ret = Ipv4AddrToAddrIn(&addr, ip, port);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "init addr error, ret=%{public}d", ret);
        return ret;
    }

    int fd;
    if (capabilityValue != NSTACKX_WLAN_CAT_TCP) {
        ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_DGRAM | SOFTBUS_SOCK_NONBLOCK |
            SOFTBUS_SOCK_CLOEXEC, 0, &fd);
    } else {
        ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_NONBLOCK |
            SOFTBUS_SOCK_CLOEXEC, 0, &fd);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "create socket error, ret=%{public}d.", ret);
        return ret;
    }

    ret = SetReuseAddr(fd, 1);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "reuse addr error, ret=%{public}d.", ret);
        TransTdcReleaseFd(fd);
        return ret;
    }

    ret = SetReusePort(fd, 1);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "reuse port error, ret=%{public}d.", ret);
        TransTdcReleaseFd(fd);
        return ret;
    }

    ret = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketBind(fd, (SoftBusSockAddr *)&addr, sizeof(addr)));
    if (ret != SOFTBUS_ADAPTER_OK) {
        TRANS_LOGE(TRANS_FILE, "bind error, ret=%{public}d.", ret);
        TransTdcReleaseFd(fd);
        return ret;
    }

    return fd;
}

static int CreateServerSocketByIpv6(const char *ip, int port, uint32_t capabilityValue)
{
    SoftBusSockAddrIn6 addr;
    int32_t ret = Ipv6AddrToAddrIn(&addr, ip, port);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "init addr error, ret=%{public}d", ret);
        return ret;
    }

    int fd;
    if (capabilityValue != NSTACKX_WLAN_CAT_TCP) {
        ret = SoftBusSocketCreate(SOFTBUS_AF_INET6, SOFTBUS_SOCK_DGRAM | SOFTBUS_SOCK_NONBLOCK |
            SOFTBUS_SOCK_CLOEXEC, 0, &fd);
    } else {
        ret = SoftBusSocketCreate(SOFTBUS_AF_INET6, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_NONBLOCK |
            SOFTBUS_SOCK_CLOEXEC, 0, &fd);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "create socket error, ret=%{public}d.", ret);
        return ret;
    }

    ret = SetReuseAddr(fd, 1);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "reuse addr error, ret=%{public}d.", ret);
        TransTdcReleaseFd(fd);
        return ret;
    }

    ret = SetReusePort(fd, 1);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "reuse port error, ret=%{public}d.", ret);
        TransTdcReleaseFd(fd);
        return ret;
    }

    ret = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketBind(fd, (SoftBusSockAddr *)&addr, sizeof(addr)));
    TRANS_LOGI(TRANS_FILE, "bind addr port=%{public}#x", addr.sin6Port);
    if (ret != SOFTBUS_ADAPTER_OK) {
        TRANS_LOGE(TRANS_FILE, "bind error, ret=%{public}d.", ret);
        TransTdcReleaseFd(fd);
        return ret;
    }
    return fd;
}

static int32_t CreateServerSocket(const char *ip, int32_t *fd, int32_t *port, uint32_t capabilityValue)
{
    if (ip == NULL || fd == NULL || port == NULL) {
        TRANS_LOGE(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t socketFd = -1;
    if (GetDomainByAddr(ip) == SOFTBUS_AF_INET6) {
        socketFd = CreateServerSocketByIpv6(ip, 0, capabilityValue);
    } else {
        socketFd = CreateServerSocketByIpv4(ip, 0, capabilityValue);
    }

    if (socketFd < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start tcp server for getting port");
        return SOFTBUS_FILE_ERR;
    }
    const SocketInterface *interface = GetSocketInterface(LNN_PROTOCOL_IP);
    if (interface == NULL) {
        TRANS_LOGE(TRANS_FILE, "no ip supportted");
        TransTdcReleaseFd(socketFd);
        return SOFTBUS_NOT_FIND;
    }
    int32_t socketPort = interface->GetSockPort(socketFd);
    if (socketPort < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to get port from tcp socket");
        TransTdcReleaseFd(socketFd);
        return SOFTBUS_INVALID_PORT;
    }
    *fd = socketFd;
    *port = socketPort;
    TRANS_LOGI(TRANS_FILE, "create socket success, fd=%{public}d, port=%{public}d", socketFd, socketPort);
    return SOFTBUS_OK;
}

static int32_t InitSockAddrInByIpPort(const char *ip, int32_t port, struct sockaddr_in *addr)
{
    if (ip == NULL || port < 0 || addr == NULL) {
        TRANS_LOGE(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    (void)memset_s(addr, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = port;
    addr->sin_addr.s_addr = SoftBusNtoHl(SoftBusInetAddr(ip));
    return SOFTBUS_OK;
}

static int32_t InitSockAddrIn6ByIpPort(const char *ip, int32_t port, struct sockaddr_in6 *addr)
{
    if (ip == NULL || port < 0 || addr == NULL) {
        TRANS_LOGE(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    SoftBusSockAddrIn6 addrIn6;
    int32_t ret = Ipv6AddrToAddrIn(&addrIn6, ip, port);
    addrIn6.sin6Port = port;
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "init addr error, ret=%{public}d", ret);
        return ret;
    }

    (void)memset_s(addr, sizeof(struct sockaddr_in6), 0, sizeof(struct sockaddr_in6));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = addrIn6.sin6Port;
    addr->sin6_scope_id = addrIn6.sin6ScopeId;
    if (memcpy_s(&addr->sin6_addr, sizeof(addr->sin6_addr), &addrIn6.sin6Addr, sizeof(addrIn6.sin6Addr)) != EOK) {
        TRANS_LOGE(TRANS_FILE, "failed to get ip, ret=%{public}d", ret);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t StartNStackXDFileServer(
    const char *myIp, const uint8_t *key, DFileMsgReceiver msgReceiver, int32_t *filePort, uint32_t capabilityValue)
{
    if (myIp == NULL || filePort == NULL) {
        TRANS_LOGE(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t port = -1;
    int32_t fd = -1;
    int32_t ret = CreateServerSocket(myIp, &fd, &port, capabilityValue);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "failed to start tcp server for getting port");
        return ret;
    }
    int sessionId = -1;
    if (GetDomainByAddr(myIp) == SOFTBUS_AF_INET6) {
        struct sockaddr_in6 localAddr = { 0 };
        ret = InitSockAddrIn6ByIpPort(myIp, port, &localAddr);
        if (ret != SOFTBUS_OK) {
            TransTdcReleaseFd(fd);
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in6, ret=%{public}d", ret);
            return ret;
        }
        socklen_t addrLen = sizeof(struct sockaddr_in6);
        sessionId = NSTACKX_DFileServer(
            (struct sockaddr_in *)&localAddr, addrLen, key, DEFAULT_KEY_LENGTH, msgReceiver);
    } else {
        struct sockaddr_in localAddr = { 0 };
        ret = InitSockAddrInByIpPort(myIp, port, &localAddr);
        if (ret != SOFTBUS_OK) {
            TransTdcReleaseFd(fd);
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in, ret=%{public}d", ret);
            return ret;
        }
        socklen_t addrLen = sizeof(struct sockaddr_in);
        sessionId = NSTACKX_DFileServer(
            (struct sockaddr_in *)&localAddr, addrLen, key, DEFAULT_KEY_LENGTH, msgReceiver);
    }
    *filePort = port;
    TransTdcReleaseFd(fd);
    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile server.");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, myIp, IP_LEN);
    TRANS_LOGI(TRANS_FILE, "start dfile server, ip=%{public}s, port=%{public}d", animizedIp, port);
    return sessionId;
}

int32_t StartNStackXDFileClient(
    const char *peerIp, int32_t peerPort, const uint8_t *key, uint32_t keyLen, DFileMsgReceiver msgReceiver)
{
    if (peerIp == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t sessionId = -1;
    if (GetDomainByAddr(peerIp) == SOFTBUS_AF_INET6) {
        struct sockaddr_in6 localAddr = { 0 };
        int32_t ret = InitSockAddrIn6ByIpPort(peerIp, peerPort, &localAddr);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in6, ret=%{public}d", ret);
            return ret;
        }
        socklen_t addrLen = sizeof(struct sockaddr_in6);
        sessionId = NSTACKX_DFileClient((struct sockaddr_in *)&localAddr, addrLen, key, keyLen, msgReceiver);
    } else {
        struct sockaddr_in localAddr = { 0 };
        int32_t ret = InitSockAddrInByIpPort(peerIp, peerPort, &localAddr);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in, ret=%{public}d", ret);
            return ret;
        }
        socklen_t addrLen = sizeof(struct sockaddr_in);
        sessionId = NSTACKX_DFileClient(&localAddr, addrLen, key, keyLen, msgReceiver);
    }

    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile client");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, peerIp, IP_LEN);
    TRANS_LOGI(TRANS_FILE, "start dfile client, peerIp=%{public}s, peerPort=%{public}d", animizedIp, peerPort);
    return sessionId;
}

int32_t TransOnFileChannelServerAddSecondPath(
    const ChannelInfo *channel, int32_t *filePort, int32_t dfileId, AddrInfo *addrInfo, uint32_t capabilityValue)
{
    if (channel == NULL || filePort == NULL || addrInfo == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t port = -1;
    int32_t fd = -1;
    int32_t ret = CreateServerSocket(channel->myIp, &fd, &port, capabilityValue);
    NSTACKX_SessionParaMpV2 para[1];
    struct sockaddr_storage *addrStorage = (struct sockaddr_storage *)SoftBusCalloc(sizeof(struct sockaddr_storage));
    if (addrStorage == NULL) {
        TRANS_LOGE(TRANS_FILE, "addr calloc failed.");
        TransTdcReleaseFd(fd);
        return SOFTBUS_MEM_ERR;
    }
    para[0].addr = (struct sockaddr_in *)addrStorage;
    ret = FillDFileParam(channel->myIp, port, channel->linkType, para);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "fill dfile param error, ret=%{public}d", ret);
        TransTdcReleaseFd(fd);
        SoftBusFree(addrStorage);
        return SOFTBUS_MEM_ERR;
    }
    TRANS_LOGI(TRANS_FILE, "is wired=%{public}d", type);

    if (memcpy_s(&(addrInfo->addr), sizeof(struct sockaddr_storage), para[0].addr, para[0].addrLen) != EOK) {
        TRANS_LOGE(TRANS_FILE, "failed to memcpy addr");
        TransTdcReleaseFd(fd);
        SoftBusFree(addrStorage);
        return SOFTBUS_MEM_ERR;
    }
    addrInfo->addrLen = para[0].addrLen;
    int32_t paraNum = sizeof(para) / sizeof(para[0]);
    int32_t sessionId = -1;
    ret = NSTACKX_DFileAddMpPath(dfileId, para, paraNum, (uint8_t *)channel->sessionKey, DEFAULT_KEY_LENGTH);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "NSTACK_DFileAddMpPath error, ret=%{public}d", ret);
        TransTdcReleaseFd(fd);
        SoftBusFree(addrStorage);
        return sessionId;
    }
    sessionId = dfileId;
    *filePort = port;
    TRANS_LOGI(TRANS_FILE, "add second path success, dfileId=%{public}d, port=%{public}d", sessionId, *filePort);
    TransTdcReleaseFd(fd);
    SoftBusFree(addrStorage);
    return sessionId;
}

int32_t TransOnFileChannelClientAddSecondPath(
    const ChannelInfo *channel, int32_t dfileId, uint32_t keyLen, AddrInfo *addrInfo)
{
    if (channel == NULL || addrInfo == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    NSTACKX_SessionParaMpV2 para[1];
    struct sockaddr_storage *addrStorage = (struct sockaddr_storage *)SoftBusCalloc(sizeof(struct sockaddr_storage));
    if (addrStorage == NULL) {
        TRANS_LOGE(TRANS_FILE, "addr calloc failed.");
        return SOFTBUS_MEM_ERR;
    }
    para[0].addr = (struct sockaddr_in *)addrStorage;
    int32_t ret = FillDFileParam(channel->peerIp, channel->peerPort, channel->linkType, para);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "fill dfile param error, ret=%{public}d", ret);
        SoftBusFree(addrStorage);
        return SOFTBUS_MEM_ERR;
    }
    TRANS_LOGI(TRANS_FILE, "is wired=%{public}d", type);

    if (memcpy_s(&(addrInfo->addr), sizeof(struct sockaddr_storage), para[0].addr, para[0].addrLen) != EOK) {
        TRANS_LOGE(TRANS_FILE, "failed to memcpy addr");
        SoftBusFree(addrStorage);
        return SOFTBUS_MEM_ERR;
    }
    addrInfo->addrLen = para[0].addrLen;

    int32_t paraNum = sizeof(para) / sizeof(para[0]);
    int32_t sessionId = -1;
    ret = NSTACKX_DFileAddMpPath(dfileId, para, paraNum, (uint8_t *)channel->sessionKey, keyLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "NSTACK_DFileAddMpPath error, ret=%{public}d", ret);
        SoftBusFree(addrStorage);
        return sessionId;
    }
    sessionId = dfileId;
    SoftBusFree(addrStorage);
    TRANS_LOGI(
        TRANS_FILE, "add second path success, dfileId=%{public}d, peerPort=%{public}d", sessionId, channel->peerPort);
    return sessionId;
}

int32_t StartNStackXDFileServerV2(
    const ChannelInfo *channel, DFileMsgReceiver msgReceiver, int32_t *filePort, uint32_t capabilityValue)
{
    TRANS_LOGI(TRANS_FILE, "enter.");
    if (channel == NULL || filePort == NULL) {
        TRANS_LOGE(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t port = -1;
    int32_t fd = -1;
    int32_t ret = CreateServerSocket(channel->myIp, &fd, &port, capabilityValue);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "failed to start tcp server for getting port");
        return ret;
    }

    NSTACKX_SessionParaMpV2 para[1];
    struct sockaddr_storage *addrStorage = (struct sockaddr_storage *)SoftBusCalloc(sizeof(struct sockaddr_storage));
    if (addrStorage == NULL) {
        TRANS_LOGE(TRANS_FILE, "addr calloc failed.");
        TransTdcReleaseFd(fd);
        return SOFTBUS_MEM_ERR;
    }
    para[0].addr = (struct sockaddr_in *)addrStorage;
    ret = FillDFileParam(channel->myIp, port, channel->linkType, para);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "fill dfile param error, ret=%{public}d", ret);
        TransTdcReleaseFd(fd);
        SoftBusFree(addrStorage);
        return SOFTBUS_MEM_ERR;
    }
    TRANS_LOGI(TRANS_FILE, "is wired=%{public}d", para[0].linkType);

    int32_t paraNum = sizeof(para) / sizeof(para[0]);
    sessionId = NSTACKX_DFileServerMpV2(para, paraNum, (uint8_t *)channel->sessionKey, DEFAULT_KEY_LENGTH, msgReceiver);
    *filePort = port;
    TransTdcReleaseFd(fd);
    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile server.");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, channel->myIp, IP_LEN);
    TRANS_LOGI(TRANS_FILE, "start dfile server, ip=%{public}s, port=%{public}d, dfileId=%{public}d",
        animizedIp, port, sessionId);
    return sessionId;
}

int32_t StartNStackXDFileClientV2(const ChannelInfo *channel, uint32_t keyLen, DFileMsgReceiver msgReceiver)
{
    TRANS_LOGI(TRANS_FILE, "enter.");
    if (channel == NULL) {
        TRANS_LOGE(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    NSTACKX_SessionParaMpV2 para[1];
    struct sockaddr_storage *addrStorage = (struct sockaddr_storage *)SoftBusCalloc(sizeof(struct sockaddr_storage));
    if (addrStorage == NULL) {
        TRANS_LOGE(TRANS_FILE, "addr calloc failed.");
        TransTdcReleaseFd(fd);
        return SOFTBUS_MEM_ERR;
    }
    para[0].addr = (struct sockaddr_in *)addrStorage;
    ret = FillDFileParam(channel->peerIp, channel->peerPort, channel->linkType, para);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "fill dfile param error, ret=%{public}d", ret);
        TransTdcReleaseFd(fd);
        SoftBusFree(addrStorage);
        return SOFTBUS_MEM_ERR;
    }
    TRANS_LOGI(TRANS_FILE, "is wired=%{public}d", para[0].linkType);

    int32_t paraNum = sizeof(para) / sizeof(para[0]);
    int32_t sessionId = NSTACKX_DFileClientMpV2(para, paraNum, (uint8_t *)channel->sessionKey, keyLen, msgReceiver);
    SoftBusFree(addrStorage);
    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile client.");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, channel->peerIp, IP_LEN);
    TRANS_LOGI(TRANS_FILE, "start dfile client, peerip=%{public}s, peerPort=%{public}d, dfileId=%{public}d",
        animizedIp, channel->peerPort, sessionId);
    return sessionId;
}

int32_t FillDFileParam(const char *srvIp, int32_t srvPort, int32_t linkType, NSTACKX_SessionParaMpV2 para[])
{
    if (srvIp == NULL || para == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    socklen_t addrLen = sizeof(struct sockaddr_in);
    if (GetDomainByAddr(srvIp) == SOFTBUS_AF_INET6) {
        addrLen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 localAddr6 = { 0 };
        int32_t ret = InitSockAddrIn6ByIpPort(srvIp, srvPort, &localAddr6);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in6, ret=%{public}d", ret);
            return ret;
        }
        if (memcpy_s(para[0].addr, sizeof(struct sockaddr_in6), &localAddr6, sizeof(struct sockaddr_in6)) != EOK) {
            TRANS_LOGE(TRANS_FILE, "memcpy loaclAddr failed");
            return SOFTBUS_MEM_ERR;
        }
    } else {
        struct sockaddr_in localAddr = { 0 };
        int32_t ret = InitSockAddrInByIpPort(srvIp, srvPort, &localAddr);
        if (ret!= SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in, ret=%{public}d", ret);
            return ret;
        }
        if (memcpy_s(para[0].addr, sizeof(struct sockaddr_in), &localAddr, sizeof(struct sockaddr_in)) != EOK) {
            TRANS_LOGE(TRANS_FILE, "memcpy loaclAddr failed");
            return SOFTBUS_MEM_ERR;
        }
    }
    para[0].addrLen = addrLen;
    DFileLinkType type = DFILE_LINK_MAX;
    if (linkType == LANE_USB) {
        type = DFILE_LINK_WIRED;
    } else {
        type = DFILE_LINK_WIRELESS;
    }
    para[0].linkType = type;
    return SOFTBUS_OK;
}
