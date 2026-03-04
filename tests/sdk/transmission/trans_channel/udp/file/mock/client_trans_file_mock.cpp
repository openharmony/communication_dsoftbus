/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "client_trans_file_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static void *g_clientTransFileInterface = nullptr;

ClientTransFileInterfaceMock::ClientTransFileInterfaceMock()
{
    g_clientTransFileInterface = reinterpret_cast<void *>(this);
}

ClientTransFileInterfaceMock::~ClientTransFileInterfaceMock()
{
    g_clientTransFileInterface = nullptr;
}

static ClientTransFileInterface *GetClientTransFileInterface()
{
    return reinterpret_cast<ClientTransFileInterface *>(g_clientTransFileInterface);
}

extern "C" {
// UDP Manager wrappers
int32_t TransGetUdpChannelByFileId(int32_t dfileId, UdpChannel *udpChannel)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->TransGetUdpChannelByFileId(dfileId, udpChannel);
}

int32_t TransGetUdpChannel(int32_t channelId, UdpChannel *udpChannel)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->TransGetUdpChannel(channelId, udpChannel);
}

int32_t ClientGetSessionNameByChannelId(int32_t channelId, int32_t channelType,
    char *sessionName, uint32_t len)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->ClientGetSessionNameByChannelId(channelId, channelType, sessionName, len);
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType,
    int32_t *sessionId, bool isClosing)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->ClientGetSessionIdByChannelId(channelId, channelType, sessionId, isClosing);
}

int32_t TransOnUdpChannelClosed(int32_t channelId, ShutdownReason reason)
{
    if (GetClientTransFileInterface() != nullptr) {
        return GetClientTransFileInterface()->TransOnUdpChannelClosed(channelId, reason);
    }
    return SOFTBUS_ERR;
}

int32_t TransOnUdpChannelOpened(const char *sessionName, const ChannelInfo *channel,
    int32_t *udpPort, SocketAccessInfo *accessInfo)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->TransOnUdpChannelOpened(sessionName, channel, udpPort, accessInfo);
}

// File Listener wrappers
int32_t TransGetFileListener(const char *sessionName, FileListener *fileListener)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->TransGetFileListener(sessionName, fileListener);
}

// File Adapter wrappers
int32_t StartNStackXDFileServer(const char *myIp, const uint8_t *key,
    DFileMsgReceiver msgReceiver, int32_t *filePort, uint32_t capabilityValue)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->StartNStackXDFileServer(myIp, key, msgReceiver, filePort, capabilityValue);
}

int32_t StartNStackXDFileClient(const char *peerIp, int32_t peerPort, const uint8_t *key,
    uint32_t keyLen, DFileMsgReceiver msgReceiver)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->StartNStackXDFileClient(peerIp, peerPort, key, keyLen, msgReceiver);
}

int32_t TransOnFileChannelClientAddSecondPath(const ChannelInfo *channel,
    int32_t dfileId, uint32_t keyLen)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->TransOnFileChannelClientAddSecondPath(channel, dfileId, keyLen);
}

int32_t TransOnFileChannelServerAddSecondPath(const ChannelInfo *channel,
    int32_t *filePort, int32_t dfileId, uint32_t capabilityValue)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->TransOnFileChannelServerAddSecondPath(
        channel, filePort, dfileId, capabilityValue);
}

int32_t StartNStackXDFileClientV2(const char *peerIp, int32_t peerPort,
    const uint8_t *key, uint32_t keyLen, DFileMsgReceiver msgReceiver, int32_t linkType)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->StartNStackXDFileClientV2(
        peerIp, peerPort, key, keyLen, msgReceiver, linkType);
}

int32_t StartNStackXDFileServerV2(const char *myIp, const uint8_t *key,
    DFileMsgReceiver msgReceiver, int32_t *filePort, int32_t linkType, uint32_t capabilityValue)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->StartNStackXDFileServerV2(
        myIp, key, msgReceiver, filePort, linkType, capabilityValue);
}

int32_t FillDFileParam(NSTACKX_SessionParaMpV2 *para, const char *srvIp, int32_t srvPort)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->FillDFileParam(para, srvIp, srvPort);
}

void NSTACKX_DFileClose(int32_t sessionId)
{
    if (GetClientTransFileInterface() != nullptr) {
        GetClientTransFileInterface()->NSTACKX_DFileClose(sessionId);
    }
}

int32_t NSTACKX_RemoveMpPath(int32_t sessionId, NSTACKX_SessionParaMpV2 para[], uint8_t paraNum)
{
    if (GetClientTransFileInterface() != nullptr) {
        return GetClientTransFileInterface()->NSTACKX_RemoveMpPath(sessionId, para, paraNum);
    }
    return SOFTBUS_ERR;
}

int32_t NSTACKX_DFileSetStoragePath(int32_t sessionId, const char *path)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->NSTACKX_DFileSetStoragePath(sessionId, path);
}

int32_t NSTACKX_DFileSetRenameHook(int32_t sessionId, OnDFileRenameFile onRenameFile)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->NSTACKX_DFileSetRenameHook(sessionId, onRenameFile);
}

int32_t NSTACKX_DFileSendFiles(int32_t sessionId, const char *files[],
    uint32_t fileNum, const char *userData)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->NSTACKX_DFileSendFiles(sessionId, files, fileNum, userData);
}

int32_t NSTACKX_DFileSendFilesWithRemotePath(int32_t sessionId, const char *files[],
    const char *remotePath[], uint32_t fileNum, const char *userData)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->NSTACKX_DFileSendFilesWithRemotePath(
        sessionId, files, remotePath, fileNum, userData);
}

// Session wrappers
void HandleMultiPathOnEvent(int32_t channelId, uint8_t changeType,
    LinkMediumType linkMediumType, enum SoftBusMPErrNo reason)
{
    if (GetClientTransFileInterface() != nullptr) {
        GetClientTransFileInterface()->HandleMultiPathOnEvent(channelId, changeType, linkMediumType, reason);
    }
}

// Statistics wrappers
void UpdateChannelStatistics(int32_t socketId, int64_t len)
{
    if (GetClientTransFileInterface() != nullptr) {
        GetClientTransFileInterface()->UpdateChannelStatistics(socketId, len);
    }
}

int32_t SaveAddrInfo(int32_t channelId, struct sockaddr_storge *addr, socklen_t addrLen)
{
    if (GetClientTransFileInterface() == nullptr) {
        return SOFTBUS_ERR;
    }
    return GetClientTransFileInterface()->SaveAddrInfo(channelId, addr, addrLen);
}

} // extern "C"

} // namespace OHOS
