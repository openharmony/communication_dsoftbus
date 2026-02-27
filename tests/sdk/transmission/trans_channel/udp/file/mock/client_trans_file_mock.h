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

#ifndef CLIENT_TRANS_FILE_MOCK_H
#define CLIENT_TRANS_FILE_MOCK_H

#include <gmock/gmock.h>
#include "client_trans_udp_manager.h"
#include "client_trans_file_listener.h"
#include "nstackx_dfile.h"
#include "softbus_def.h"

namespace OHOS {

#ifdef __cplusplus
extern "C" {
#endif

// Unified mock interface for client trans file module
class ClientTransFileInterface {
public:
    ClientTransFileInterface() {};
    virtual ~ClientTransFileInterface() {};

    // UDP Manager methods
    virtual int32_t TransGetUdpChannelByFileId(int32_t dfileId, UdpChannel *udpChannel) = 0;
    virtual int32_t TransGetUdpChannel(int32_t channelId, UdpChannel *udpChannel) = 0;
    virtual int32_t ClientGetSessionNameByChannelId(int32_t channelId, int32_t channelType,
        char *sessionName, uint32_t len) = 0;
    virtual int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType,
        int32_t *sessionId, bool isClosing) = 0;
    virtual int32_t TransOnUdpChannelClosed(int32_t channelId, ShutdownReason reason) = 0;
    virtual int32_t TransOnUdpChannelOpened(const char *sessionName, const ChannelInfo *channel,
        int32_t *udpPort, SocketAccessInfo *accessInfo) = 0;

    // File Listener methods
    virtual int32_t TransGetFileListener(const char *sessionName, FileListener *fileListener) = 0;

    // File Adapter methods
    virtual int32_t StartNStackXDFileServer(const char *myIp, const uint8_t *key,
        DFileMsgReceiver msgReceiver, int32_t *filePort, uint32_t capabilityValue) = 0;
    virtual int32_t StartNStackXDFileClient(const char *peerIp, int32_t peerPort, const uint8_t *key,
        uint32_t keyLen, DFileMsgReceiver msgReceiver) = 0;
    virtual int32_t TransOnFileChannelClientAddSecondPath(const ChannelInfo *channel,
        int32_t dfileId, uint32_t keyLen) = 0;
    virtual int32_t TransOnFileChannelServerAddSecondPath(const ChannelInfo *channel,
        int32_t *filePort, int32_t dfileId, uint32_t capabilityValue) = 0;
    virtual int32_t StartNStackXDFileClientV2(const char *peerIp, int32_t peerPort,
        const uint8_t *key, uint32_t keyLen, DFileMsgReceiver msgReceiver, int32_t linkType) = 0;
    virtual int32_t StartNStackXDFileServerV2(const char *myIp, const uint8_t *key,
        DFileMsgReceiver msgReceiver, int32_t *filePort, int32_t linkType, uint32_t capabilityValue) = 0;
    virtual int32_t FillDFileParam(NSTACKX_SessionParaMpV2 *para, const char *srvIp, int32_t srvPort) = 0;
    virtual void NSTACKX_DFileClose(int32_t sessionId) = 0;
    virtual int32_t NSTACKX_RemoveMpPath(int32_t sessionId, NSTACKX_SessionParaMpV2 para[], uint8_t paraNum) = 0;
    virtual int32_t NSTACKX_DFileSetStoragePath(int32_t sessionId, const char *path) = 0;
    virtual int32_t NSTACKX_DFileSetRenameHook(int32_t sessionId, OnDFileRenameFile onRenameFile) = 0;
    virtual int32_t NSTACKX_DFileSendFiles(int32_t sessionId, const char *files[],
        uint32_t fileNum, const char *userData) = 0;
    virtual int32_t NSTACKX_DFileSendFilesWithRemotePath(int32_t sessionId, const char *files[],
        const char *remotePath[], uint32_t fileNum, const char *userData) = 0;

    // Session methods
    virtual void HandleMultiPathOnEvent(int32_t channelId, uint8_t changeType,
        LinkMediumType linkMediumType, enum SoftBusMPErrNo reason) = 0;

    // Statistics methods
    virtual void UpdateChannelStatistics(int32_t socketId, int64_t len) = 0;
    virtual int32_t SaveAddrInfo(int32_t channelId, struct sockaddr_storge *addr, socklen_t addrLen) = 0;
};

class ClientTransFileInterfaceMock : public ClientTransFileInterface {
public:
    ClientTransFileInterfaceMock();
    ~ClientTransFileInterfaceMock() override;

    // UDP Manager mocks
    MOCK_METHOD2(TransGetUdpChannelByFileId, int32_t(int32_t dfileId, UdpChannel *udpChannel));
    MOCK_METHOD2(TransGetUdpChannel, int32_t(int32_t channelId, UdpChannel *udpChannel));
    MOCK_METHOD4(ClientGetSessionNameByChannelId, int32_t(int32_t channelId, int32_t channelType,
        char *sessionName, uint32_t len));
    MOCK_METHOD4(ClientGetSessionIdByChannelId, int32_t(int32_t channelId, int32_t channelType,
        int32_t *sessionId, bool isClosing));
    MOCK_METHOD2(TransOnUdpChannelClosed, int32_t(int32_t channelId, ShutdownReason reason));
    MOCK_METHOD4(TransOnUdpChannelOpened, int32_t(const char *sessionName, const ChannelInfo *channel,
        int32_t *udpPort, SocketAccessInfo *accessInfo));

    // File Listener mocks
    MOCK_METHOD2(TransGetFileListener, int32_t(const char *sessionName, FileListener *fileListener));

    // File Adapter mocks
    MOCK_METHOD5(StartNStackXDFileServer, int32_t(const char *myIp, const uint8_t *key,
        DFileMsgReceiver msgReceiver, int32_t *filePort, uint32_t capabilityValue));
    MOCK_METHOD5(StartNStackXDFileClient, int32_t(const char *peerIp, int32_t peerPort, const uint8_t *key,
        uint32_t keyLen, DFileMsgReceiver msgReceiver));
    MOCK_METHOD3(TransOnFileChannelClientAddSecondPath, int32_t(const ChannelInfo *channel,
        int32_t dfileId, uint32_t keyLen));
    MOCK_METHOD4(TransOnFileChannelServerAddSecondPath, int32_t(const ChannelInfo *channel,
        int32_t *filePort, int32_t dfileId, uint32_t capabilityValue));
    MOCK_METHOD6(StartNStackXDFileClientV2, int32_t(const char *peerIp, int32_t peerPort,
        const uint8_t *key, uint32_t keyLen, DFileMsgReceiver msgReceiver, int32_t linkType));
    MOCK_METHOD6(StartNStackXDFileServerV2, int32_t(const char *myIp, const uint8_t *key,
        DFileMsgReceiver msgReceiver, int32_t *filePort, int32_t linkType, uint32_t capabilityValue));
    MOCK_METHOD3(FillDFileParam, int32_t(NSTACKX_SessionParaMpV2 *para, const char *srvIp, int32_t srvPort));
    MOCK_METHOD1(NSTACKX_DFileClose, void(int32_t sessionId));
    MOCK_METHOD3(NSTACKX_RemoveMpPath, int32_t(int32_t sessionId, NSTACKX_SessionParaMpV2 para[], uint8_t paraNum));
    MOCK_METHOD2(NSTACKX_DFileSetStoragePath, int32_t(int32_t sessionId, const char *path));
    MOCK_METHOD2(NSTACKX_DFileSetRenameHook, int32_t(int32_t sessionId, OnDFileRenameFile onRenameFile));
    MOCK_METHOD4(NSTACKX_DFileSendFiles, int32_t(int32_t sessionId, const char *files[],
        uint32_t fileNum, const char *userData));
    MOCK_METHOD5(NSTACKX_DFileSendFilesWithRemotePath, int32_t(int32_t sessionId, const char *files[],
        const char *remotePath[], uint32_t fileNum, const char *userData));

    // Session mocks
    MOCK_METHOD4(HandleMultiPathOnEvent, void(int32_t channelId, uint8_t changeType,
        LinkMediumType linkMediumType, enum SoftBusMPErrNo reason));

    // Statistics mocks
    MOCK_METHOD2(UpdateChannelStatistics, void(int32_t socketId, int64_t len));
    MOCK_METHOD3(SaveAddrInfo, int32_t(int32_t channelId, struct sockaddr_storge *addr, socklen_t addrLen));
};

} // namespace OHOS

#ifdef __cplusplus
}
#endif

#endif // CLIENT_TRANS_FILE_MOCK_H
