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

#include "softbus_adapter_mem.h"
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
        TRANS_LOGE(TRANS_FILE, "failed to start tcp server socket");
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

static int32_t StartDFileServerIpv6(
    const ChannelInfo *channel, int32_t port, DFileMsgReceiver msgReceiver, int32_t *sessionId)
{
    if (channel == NULL || sessionId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    struct sockaddr_in6 localAddr = { 0 };
    int32_t ret = InitSockAddrIn6ByIpPort(channel->myIp, port, &localAddr);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in6, ret=%{public}d", ret);
        return ret;
    }
    socklen_t addrLen = sizeof(struct sockaddr_in6);
    if (channel->cancelEncryption) {
        *sessionId = NSTACKX_DFileServer((struct sockaddr_in *)&localAddr, addrLen, NULL, 0, msgReceiver);
    } else {
        *sessionId = NSTACKX_DFileServer((struct sockaddr_in *)&localAddr, addrLen,
            (const uint8_t *)channel->sessionKey, DEFAULT_KEY_LENGTH, msgReceiver);
    }
    return SOFTBUS_OK;
}

static int32_t StartDFileServerIpv4(
    const ChannelInfo *channel, int32_t port, DFileMsgReceiver msgReceiver, int32_t *sessionId)
{
    if (channel == NULL || sessionId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    struct sockaddr_in localAddr = { 0 };
    int32_t ret = InitSockAddrInByIpPort(channel->myIp, port, &localAddr);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in, ret=%{public}d", ret);
        return ret;
    }
    socklen_t addrLen = sizeof(struct sockaddr_in);
    if (channel->cancelEncryption) {
        *sessionId = NSTACKX_DFileServer(
            (struct sockaddr_in *)&localAddr, addrLen, NULL, 0, msgReceiver);
    } else {
        *sessionId = NSTACKX_DFileServer((struct sockaddr_in *)&localAddr, addrLen,
            (const uint8_t *)channel->sessionKey, DEFAULT_KEY_LENGTH, msgReceiver);
    }
    return SOFTBUS_OK;
}

int32_t StartNStackXDFileServer(
    const ChannelInfo *channel, DFileMsgReceiver msgReceiver, int32_t *filePort, uint32_t capabilityValue)
{
    if (channel == NULL || channel->myIp == NULL || filePort == NULL) {
        TRANS_LOGE(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t port = -1;
    int32_t fd = -1;
    int32_t ret = CreateServerSocket(channel->myIp, &fd, &port, capabilityValue);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "failed to start tcp server socket");
        return ret;
    }
    int sessionId = -1;
    if (GetDomainByAddr(channel->myIp) == SOFTBUS_AF_INET6) {
        ret = StartDFileServerIpv6(channel, port, msgReceiver, &sessionId);
        if (ret != SOFTBUS_OK) {
            TransTdcReleaseFd(fd);
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in, ret=%{public}d", ret);
            return ret;
        }
    } else {
        ret = StartDFileServerIpv4(channel, port, msgReceiver, &sessionId);
        if (ret != SOFTBUS_OK) {
            TransTdcReleaseFd(fd);
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in, ret=%{public}d", ret);
            return ret;
        }
    }
    *filePort = port;
    TransTdcReleaseFd(fd);
    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile server.");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, channel->myIp, IP_LEN);
    TRANS_LOGI(TRANS_FILE, "start dfile server, ip=%{public}s, port=%{public}d, linkType=%{public}d, "
        "cancelEncryption=%{public}d", animizedIp, port, channel->linkType, channel->cancelEncryption);
    return sessionId;
}

int32_t StartNStackXDFileClient(const ChannelInfo *channel, uint32_t keyLen, DFileMsgReceiver msgReceiver)
{
    if (channel == NULL || channel->peerIp == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t sessionId = -1;
    if (GetDomainByAddr(channel->peerIp) == SOFTBUS_AF_INET6) {
        struct sockaddr_in6 localAddr = { 0 };
        int32_t ret = InitSockAddrIn6ByIpPort(channel->peerIp, channel->peerPort, &localAddr);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in6, ret=%{public}d", ret);
            return ret;
        }
        socklen_t addrLen = sizeof(struct sockaddr_in6);
        if (channel->cancelEncryption) {
            sessionId = NSTACKX_DFileClient(
                (struct sockaddr_in *)&localAddr, addrLen, NULL, 0, msgReceiver);
        } else {
            sessionId = NSTACKX_DFileClient((struct sockaddr_in *)&localAddr, addrLen,
                (const uint8_t *)channel->sessionKey, keyLen, msgReceiver);
        }
    } else {
        struct sockaddr_in localAddr = { 0 };
        int32_t ret = InitSockAddrInByIpPort(channel->peerIp, channel->peerPort, &localAddr);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in, ret=%{public}d", ret);
            return ret;
        }
        socklen_t addrLen = sizeof(struct sockaddr_in);
        if (channel->cancelEncryption) {
            sessionId = NSTACKX_DFileClient(&localAddr, addrLen, NULL, 0, msgReceiver);
        } else {
            sessionId = NSTACKX_DFileClient(&localAddr, addrLen,
                (const uint8_t *)channel->sessionKey, keyLen, msgReceiver);
        }
    }

    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile client");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, channel->peerIp, IP_LEN);
    TRANS_LOGI(TRANS_FILE, "start dfile client, peerIp=%{public}s, peerPort=%{public}d, linkType=%{public}d, "
        "cancelEncryption=%{public}d", animizedIp, channel->peerPort, channel->linkType, channel->cancelEncryption);
    return sessionId;
}

static int32_t StartDFileAddMpPath(const ChannelInfo *channel, int32_t port, int32_t dfileId, AddrInfo *addrInfo)
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
    int32_t ret = FillDFileParam(channel->myIp, port, channel->linkType, para);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "fill dfile param error, ret=%{public}d", ret);
        SoftBusFree(addrStorage);
        return ret;
    }
    TRANS_LOGI(TRANS_FILE, "is wired=%{public}d", para[0].linkType);

    if (memcpy_s(&(addrInfo->addr), sizeof(struct sockaddr_storage), para[0].addr, para[0].addrLen) != EOK) {
        TRANS_LOGE(TRANS_FILE, "failed to memcpy addr");
        SoftBusFree(addrStorage);
        return SOFTBUS_MEM_ERR;
    }
    addrInfo->addrLen = para[0].addrLen;
    int32_t paraNum = sizeof(para) / sizeof(para[0]);
    if (channel->cancelEncryption) {
        ret = NSTACKX_DFileAddMpPath(dfileId, para, paraNum, NULL, 0);
    } else {
        ret = NSTACKX_DFileAddMpPath(dfileId, para, paraNum, (const uint8_t *)channel->sessionKey, DEFAULT_KEY_LENGTH);
    }
    SoftBusFree(addrStorage);
    return ret;
}

int32_t DFileServerAddSecondPath(const ChannelInfo *channel, int32_t *filePort,
    int32_t dfileId, AddrInfo *addrInfo, uint32_t capabilityValue)
{
    if (channel == NULL || filePort == NULL || addrInfo == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t port = -1;
    int32_t fd = -1;
    int32_t ret = CreateServerSocket(channel->myIp, &fd, &port, capabilityValue);
    int32_t sessionId = -1;
    ret = StartDFileAddMpPath(channel, port, dfileId, addrInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "NSTACK_DFileAddMpPath error, ret=%{public}d", ret);
        TransTdcReleaseFd(fd);
        return sessionId;
    }
    sessionId = dfileId;
    *filePort = port;
    TRANS_LOGI(TRANS_FILE, "add second path succ, dfileId=%{public}d, port=%{public}d, linkType=%{public}d, "
        "cancelEncryption=%{public}d", sessionId, *filePort, channel->linkType, channel->cancelEncryption);
    TransTdcReleaseFd(fd);
    return sessionId;
}

int32_t DFileClientAddSecondPath(
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
        return ret;
    }
    TRANS_LOGI(TRANS_FILE, "is wired=%{public}d", para[0].linkType);

    if (memcpy_s(&(addrInfo->addr), sizeof(struct sockaddr_storage), para[0].addr, para[0].addrLen) != EOK) {
        TRANS_LOGE(TRANS_FILE, "failed to memcpy addr");
        SoftBusFree(addrStorage);
        return SOFTBUS_MEM_ERR;
    }
    addrInfo->addrLen = para[0].addrLen;

    int32_t paraNum = sizeof(para) / sizeof(para[0]);
    int32_t sessionId = -1;
    if (channel->cancelEncryption) {
        ret = NSTACKX_DFileAddMpPath(dfileId, para, paraNum, NULL, 0);
    } else {
        ret = NSTACKX_DFileAddMpPath(dfileId, para, paraNum, (const uint8_t *)channel->sessionKey, keyLen);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "NSTACK_DFileAddMpPath error, ret=%{public}d", ret);
        SoftBusFree(addrStorage);
        return sessionId;
    }
    sessionId = dfileId;
    SoftBusFree(addrStorage);
    TRANS_LOGI(TRANS_FILE, "add second path succ, dfileId=%{public}d, peerPort=%{public}d, linkType=%{public}d, "
        "cancelEncryption=%{public}d", sessionId, channel->peerPort, channel->linkType, channel->cancelEncryption);
    return sessionId;
}

static int32_t StartDFileServerMpV2(
    const ChannelInfo *channel, DFileMsgReceiver msgReceiver, int32_t port, int32_t *sessionId)
{
    if (channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NSTACKX_SessionParaMpV2 para[1];
    struct sockaddr_storage *addrStorage = (struct sockaddr_storage *)SoftBusCalloc(sizeof(struct sockaddr_storage));
    if (addrStorage == NULL) {
        TRANS_LOGE(TRANS_FILE, "addr calloc failed.");
        return SOFTBUS_MEM_ERR;
    }
    para[0].addr = (struct sockaddr_in *)addrStorage;
    int32_t ret = FillDFileParam(channel->myIp, port, channel->linkType, para);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "fill dfile param error, ret=%{public}d", ret);
        SoftBusFree(addrStorage);
        return ret;
    }
    TRANS_LOGI(TRANS_FILE, "is wired=%{public}d", para[0].linkType);

    int32_t paraNum = sizeof(para) / sizeof(para[0]);
    if (channel->cancelEncryption) {
        *sessionId = NSTACKX_DFileServerMpV2(para, paraNum, NULL, 0, msgReceiver);
    } else {
        *sessionId = NSTACKX_DFileServerMpV2(
            para, paraNum, (const uint8_t *)channel->sessionKey, DEFAULT_KEY_LENGTH, msgReceiver);
    }
    SoftBusFree(addrStorage);
    return SOFTBUS_OK;
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
        TRANS_LOGE(TRANS_FILE, "failed to start tcp server socket");
        return ret;
    }
    int32_t sessionId = -1;
    ret = StartDFileServerMpV2(channel, msgReceiver, port, &sessionId);
    if (ret != SOFTBUS_OK) {
        TransTdcReleaseFd(fd);
        TRANS_LOGE(TRANS_FILE, "failed to start dfile server mp v2");
        return ret;
    }
    *filePort = port;
    TransTdcReleaseFd(fd);
    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile server.");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, channel->myIp, IP_LEN);
    TRANS_LOGI(TRANS_FILE, "start dfile server, ip=%{public}s, port=%{public}d, dfileId=%{public}d, "
        "linkType=%{public}d, cancelEncryption=%{public}d",
        animizedIp, port, sessionId, channel->linkType, channel->cancelEncryption);
    return sessionId;
}

int32_t StartNStackXDFileClientV2(const ChannelInfo *channel, uint32_t keyLen, DFileMsgReceiver msgReceiver)
{
    TRANS_LOGI(TRANS_FILE, "enter .");
    if (channel == NULL) {
        TRANS_LOGE(TRANS_FILE, "invalid param.");
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
        return ret;
    }
    TRANS_LOGI(TRANS_FILE, "is wired=%{public}d", para[0].linkType);

    int32_t paraNum = sizeof(para) / sizeof(para[0]);
    int32_t sessionId = -1;
    if (channel->cancelEncryption) {
        sessionId = NSTACKX_DFileClientMpV2(para, paraNum, NULL, 0, msgReceiver);
    } else {
        sessionId = NSTACKX_DFileClientMpV2(para, paraNum, (const uint8_t *)channel->sessionKey, keyLen, msgReceiver);
    }
    SoftBusFree(addrStorage);
    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile client.");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, channel->peerIp, IP_LEN);
    TRANS_LOGI(TRANS_FILE, "start dfile client, peerip=%{public}s, peerPort=%{public}d, dfileId=%{public}d, "
        "linkType=%{public}d, cancelEncryption=%{public}d",
        animizedIp, channel->peerPort, sessionId, channel->linkType, channel->cancelEncryption);
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
            TRANS_LOGE(TRANS_FILE, "memcpy localAddr failed");
            return SOFTBUS_MEM_ERR;
        }
    } else {
        struct sockaddr_in localAddr = { 0 };
        int32_t ret = InitSockAddrInByIpPort(srvIp, srvPort, &localAddr);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "failed to create sockaddr_in, ret=%{public}d", ret);
            return ret;
        }
        if (memcpy_s(para[0].addr, sizeof(struct sockaddr_in), &localAddr, sizeof(struct sockaddr_in)) != EOK) {
            TRANS_LOGE(TRANS_FILE, "memcpy localAddr failed");
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
