/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_PROXY_FILE_MANAGER_MOCK_H
#define CLIENT_TRANS_PROXY_FILE_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include "client_trans_pending.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"

namespace OHOS {
class ClientTransProxyFileManagerInterface {
public:
    ClientTransProxyFileManagerInterface() {};
    virtual ~ClientTransProxyFileManagerInterface() {};
    virtual uint32_t SoftBusLtoHl(uint32_t value) = 0;
    virtual uint32_t SoftBusHtoLl(uint32_t value) = 0;
    virtual uint64_t SoftBusLtoHll(uint64_t value) = 0;
    virtual uint64_t SoftBusHtoLll(uint64_t value) = 0;
    virtual uint32_t SoftBusNtoHl(uint32_t netlong) = 0;
    virtual int32_t SoftBusGetFileSize(const char *fileName, uint64_t *fileSize) = 0;
    virtual int32_t GetPendingPacketData(uint32_t id, uint64_t seq, uint32_t waitMillis,
        bool isDelete, TransPendData *data) = 0;
    virtual int32_t CreatePendingPacket(uint32_t id, uint64_t seq) = 0;
    virtual int32_t FrameIndexToType(uint64_t index, uint64_t frameNumber) = 0;
    virtual int64_t SoftBusPreadFile(int32_t fd, void *buf, uint64_t readBytes, uint64_t offset) = 0;
    virtual bool CheckDestFilePathValid(const char *destFile) = 0;
    virtual int32_t GetAndCheckRealPath(const char *filePath, char *absPath) = 0;
    virtual int32_t SoftBusOpenFile(const char *fileName, int32_t flags) = 0;
    virtual int32_t TryFileLock(int32_t fd, int32_t type, int32_t retryTimes) = 0;
    virtual int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType,
        int32_t *sessionId, bool isClosing) = 0;
    virtual int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, SessionKey key) = 0;
    virtual int32_t ClientGetFileConfigInfoById(int32_t sessionId,
        int32_t *fileEncrypt, int32_t *algorithm, int32_t *crc) = 0;
    virtual int32_t TransGetFileListener(const char *sessionName, FileListener *fileListener) = 0;
    virtual int32_t InitPendingPacket(void) = 0;
    virtual int32_t FileUnLock(int32_t fd) = 0;
    virtual int32_t SendFileTransResult(int32_t channelId, uint32_t seq, int32_t result, uint32_t side) = 0;
    virtual int32_t SendFileAckReqAndResData(int32_t channelId, uint32_t startSeq, uint32_t value, int32_t type) = 0;
    virtual void DeletePendingPacket(uint32_t id, uint64_t seq) = 0;
    virtual int32_t AckResponseDataHandle(const SendListenerInfo *info, const char *data, uint32_t len) = 0;
    virtual int32_t ProxyChannelSendFileStream(int32_t channelId, const char *data, uint32_t len, int32_t type) = 0;
    virtual int64_t PackReadFileData(FileFrame *fileFrame, uint64_t readLength,
        uint64_t fileOffset, SendListenerInfo *info) = 0;
    virtual int32_t FileListToBuffer(const char **destFile, uint32_t fileCnt, FileListBuffer *outbufferInfo) = 0;
    virtual int32_t SetPendingPacket(int32_t channelId, int32_t seqNum, int32_t type) = 0;
};

class ClientTransProxyFileManagerInterfaceMock : public ClientTransProxyFileManagerInterface {
public:
    ClientTransProxyFileManagerInterfaceMock();
    ~ClientTransProxyFileManagerInterfaceMock() override;
    MOCK_METHOD1(SoftBusLtoHl, uint32_t (uint32_t value));
    MOCK_METHOD1(SoftBusHtoLl, uint32_t (uint32_t value));
    MOCK_METHOD1(SoftBusLtoHll, uint64_t (uint64_t value));
    MOCK_METHOD1(SoftBusHtoLll, uint64_t (uint64_t value));
    MOCK_METHOD1(SoftBusNtoHl, uint32_t (uint32_t netlong));
    MOCK_METHOD2(SoftBusGetFileSize, int32_t (const char *fileName, uint64_t *fileSize));
    MOCK_METHOD5(GetPendingPacketData, int32_t (uint32_t id, uint64_t seq, uint32_t waitMillis,
        bool isDelete, TransPendData *data));
    MOCK_METHOD2(CreatePendingPacket, int32_t (uint32_t id, uint64_t seq));
    MOCK_METHOD2(FrameIndexToType, int32_t (uint64_t index, uint64_t frameNumber));
    MOCK_METHOD4(SoftBusPreadFile, int64_t (int32_t fd, void *buf, uint64_t readBytes, uint64_t offset));
    MOCK_METHOD1(CheckDestFilePathValid, bool (const char *destFile));
    MOCK_METHOD2(GetAndCheckRealPath, int32_t (const char *filePath, char *absPath));
    MOCK_METHOD2(SoftBusOpenFile, int32_t (const char *fileName, int32_t flags));
    MOCK_METHOD3(TryFileLock, int32_t (int32_t fd, int32_t type, int32_t retryTimes));
    MOCK_METHOD4(ClientGetSessionIdByChannelId, int32_t (int32_t channelId, int32_t channelType,
        int32_t *sessionId, bool isClosing));
    MOCK_METHOD4(ClientGetSessionDataById, int32_t (int32_t sessionId, char *data, uint16_t len, SessionKey key));
    MOCK_METHOD4(ClientGetFileConfigInfoById, int32_t (int32_t sessionId,
        int32_t *fileEncrypt, int32_t *algorithm, int32_t *crc));
    MOCK_METHOD2(TransGetFileListener, int32_t (const char *sessionName, FileListener *fileListener));
    MOCK_METHOD0(InitPendingPacket, int32_t (void));
    MOCK_METHOD1(FileUnLock, int32_t (int32_t fd));
    MOCK_METHOD4(SendFileTransResult, int32_t (int32_t channelId, uint32_t seq, int32_t result, uint32_t side));
    MOCK_METHOD4(SendFileAckReqAndResData, int32_t (int32_t channelId, uint32_t startSeq,
        uint32_t value, int32_t type));
    MOCK_METHOD2(DeletePendingPacket, void (uint32_t id, uint64_t seq));
    MOCK_METHOD3(AckResponseDataHandle, int32_t (const SendListenerInfo *info, const char *data, uint32_t len));
    MOCK_METHOD4(ProxyChannelSendFileStream, int32_t (int32_t channelId, const char *data, uint32_t len, int32_t type));
    MOCK_METHOD4(PackReadFileData, int64_t (FileFrame *fileFrame, uint64_t readLength,
        uint64_t fileOffset, SendListenerInfo *info));
    MOCK_METHOD3(FileListToBuffer, int32_t (const char **destFile, uint32_t fileCnt, FileListBuffer *outbufferInfo));
    MOCK_METHOD3(SetPendingPacket, int32_t (int32_t channelId, int32_t seqNum, int32_t type));
};
} // namespace OHOS
#endif // CLIENT_TRANS_PROXY_FILE_MANAGER_MOCK_H
