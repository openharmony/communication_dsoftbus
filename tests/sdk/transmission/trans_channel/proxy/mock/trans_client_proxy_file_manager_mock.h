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

#ifndef TRANS_CLIENT_PROXY_FILE_MANAGER_MOCK_H
#define TRANS_CLIENT_PROXY_FILE_MANAGER_MOCK_H

#include <gmock/gmock.h>

#include "client_trans_pending.h"
#include "client_trans_proxy_file_manager.h"
#include "softbus_def.h"
#include "softbus_utils.h"
#include "trans_proxy_process_data.h"

namespace OHOS {
class TransClientProxyFileManagerInterface {
public:
    TransClientProxyFileManagerInterface() {};
    virtual ~TransClientProxyFileManagerInterface() {};
    virtual SoftBusList *CreateSoftBusList(void) = 0;
    virtual int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback) = 0;
    virtual int32_t UnRegisterTimeoutCallback(int32_t timerFunId) = 0;
    virtual int32_t InitPendingPacket(void) = 0;
    virtual int32_t PendingInit(int32_t type) = 0;
    virtual int32_t TransProxyDecryptPacketData(int32_t seq, ProxyDataInfo *dataInfo, const char *sessionKey) = 0;
    virtual int32_t GetSupportTlvAndNeedAckById(
        int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck) = 0;
    virtual int32_t TransProxyPackTlvBytes(ProxyDataInfo *dataInfo, const char *sessionKey,
        SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info) = 0;
    virtual int32_t TransProxyPackBytes(
        int32_t channelId, ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq) = 0;
    virtual int32_t FileUnLock(int32_t fd) = 0;
    virtual int32_t SendFileTransResult(int32_t channelId, uint32_t seq, int32_t result, uint32_t side) = 0;
    virtual int32_t ServerIpcSendMessage(
        int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType) = 0;
    virtual int32_t CreatePendingPacket(uint32_t id, uint64_t seq) = 0;
    virtual int32_t ProxyChannelSendFileStream(int32_t channelId, const char *data, uint32_t len, int32_t type) = 0;
    virtual int32_t GetPendingPacketData(
        uint32_t id, uint64_t seq, uint32_t waitMillis, bool isDelete, TransPendData *data) = 0;
    virtual int64_t SoftBusPwriteFile(int32_t fd, const void *buf, uint64_t writeBytes, uint64_t offset) = 0;
    virtual int32_t SendFileAckReqAndResData(int32_t channelId, uint32_t startSeq, uint32_t value, int32_t type) = 0;
    virtual void DeletePendingPacket(uint32_t id, uint64_t seq) = 0;
    virtual int32_t AckResponseDataHandle(const SendListenerInfo *info, const char *data, uint32_t len) = 0;
};

class TransClientProxyFileManagerInterfaceMock : public TransClientProxyFileManagerInterface {
public:
    TransClientProxyFileManagerInterfaceMock();
    ~TransClientProxyFileManagerInterfaceMock() override;
    MOCK_METHOD0(CreateSoftBusList, SoftBusList *());
    MOCK_METHOD2(RegisterTimeoutCallback, int32_t (int32_t timerFunId, TimerFunCallback callback));
    MOCK_METHOD1(UnRegisterTimeoutCallback, int32_t (int32_t timerFunId));
    MOCK_METHOD0(InitPendingPacket, int32_t ());
    MOCK_METHOD1(PendingInit, int32_t (int32_t type));
    MOCK_METHOD3(TransProxyDecryptPacketData, int32_t (int32_t seq, ProxyDataInfo *dataInfo, const char *sessionKey));
    MOCK_METHOD4(GetSupportTlvAndNeedAckById, int32_t (int32_t channelId,
        int32_t channelType, bool *supportTlv, bool *needAck));
    MOCK_METHOD5(TransProxyPackTlvBytes, int32_t (ProxyDataInfo *dataInfo, const char *sessionKey,
        SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info));
    MOCK_METHOD5(TransProxyPackBytes, int32_t (int32_t channelId, ProxyDataInfo *dataInfo,
        const char *sessionKey, SessionPktType flag, int32_t seq));
    MOCK_METHOD1(FileUnLock, int32_t (int32_t fd));
    MOCK_METHOD4(SendFileTransResult, int32_t (int32_t channelId, uint32_t seq, int32_t result, uint32_t side));
    MOCK_METHOD5(ServerIpcSendMessage, int32_t (
        int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType));
    MOCK_METHOD2(CreatePendingPacket, int32_t (uint32_t id, uint64_t seq));
    MOCK_METHOD4(ProxyChannelSendFileStream, int32_t (
        int32_t channelId, const char *data, uint32_t len, int32_t type));
    MOCK_METHOD5(GetPendingPacketData, int32_t (
        uint32_t id, uint64_t seq, uint32_t waitMillis, bool isDelete, TransPendData *data));
    MOCK_METHOD4(SoftBusPwriteFile, int64_t (int32_t fd, const void *buf, uint64_t writeBytes, uint64_t offset));
    MOCK_METHOD4(SendFileAckReqAndResData, int32_t (int32_t channelId, uint32_t startSeq,
        uint32_t value, int32_t type));
    MOCK_METHOD2(DeletePendingPacket, void (uint32_t id, uint64_t seq));
    MOCK_METHOD3(AckResponseDataHandle, int32_t (const SendListenerInfo *info, const char *data, uint32_t len));
};
} // namespace OHOS
#endif // TRANS_CLIENT_PROXY_FILE_MANAGER_MOCK_H
