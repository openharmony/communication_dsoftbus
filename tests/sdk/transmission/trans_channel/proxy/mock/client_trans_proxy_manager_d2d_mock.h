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

#ifndef TRANS_CLIENT_PROXY_MANAGER_D2D_MOCK_H
#define TRANS_CLIENT_PROXY_MANAGER_D2D_MOCK_H

#include <gmock/gmock.h>

#include "softbus_def.h"
#include "softbus_utils.h"
#include "client_trans_session_manager.h"
#include "trans_proxy_process_data.h"
#include "client_trans_proxy_manager.h"
#include "softbus_def.h"
#include "client_trans_session_manager_struct.h"

namespace OHOS {
class TransClientProxyManagerD2DInterface {
public:
    TransClientProxyManagerD2DInterface() {};
    virtual ~TransClientProxyManagerD2DInterface() {};
    
    virtual int32_t ClientGetChannelBusinessTypeByChannelId(int32_t channelId, int32_t *businessType) = 0;
    virtual int32_t TransProxyPackD2DBytes(ProxyDataInfo *dataInfo, const char *sessionKey,
        const char *sessionIv, SessionPktType flag) = 0;
    virtual uint8_t *TransProxyPackD2DData(
    ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType, uint32_t cnt, uint32_t *dataLen) = 0;
    virtual int32_t ServerIpcSendMessage(
        int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType) = 0;
    virtual int32_t TransProxyProcessD2DData(
    ProxyDataInfo *dataInfo, const PacketD2DHead *dataHead, const char *data, int32_t businessType) = 0;
    virtual int32_t TransProxyDecryptD2DData(int32_t businessType, ProxyDataInfo *dataInfo, const char *sessionKey,
        const char *sessionBytesIv, const unsigned char *sessionMsgIv) = 0;
    virtual int32_t TransProxySessionDataLenCheck(uint32_t dataLen, SessionPktType type);
    virtual int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType,
        int32_t *sessionId, bool isClosing) = 0;
    virtual int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter,
        bool *isServer) = 0;
    virtual int32_t DeleteDataSeqInfoList(uint32_t dataSeq, int32_t channelId) = 0;
    virtual int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType,
        bool *supportTlv, bool *needAck) = 0;
    virtual int32_t DataSeqInfoListAddItem(uint32_t dataSeq, int32_t channelId, int32_t socketId,
        int32_t channelType) = 0;
};

class TransClientProxyD2DInterfaceMock : public TransClientProxyManagerD2DInterface {
public:
    TransClientProxyD2DInterfaceMock();
    ~TransClientProxyD2DInterfaceMock() override;
    MOCK_METHOD2(ClientGetChannelBusinessTypeByChannelId, int32_t(int32_t channelId, int32_t *businessType));
    MOCK_METHOD4(TransProxyPackD2DBytes, int32_t(ProxyDataInfo *dataInfo, const char *sessionKey,
        const char *sessionIv, SessionPktType flag));
    MOCK_METHOD5(TransProxyPackD2DData, uint8_t *(ProxyDataInfo *dataInfo, uint32_t sliceNum,
        SessionPktType pktType, uint32_t cnt, uint32_t *dataLen));
    MOCK_METHOD5(ServerIpcSendMessage, int32_t(int32_t channelId, int32_t channelType, const void *data,
            uint32_t len, int32_t msgType));
    MOCK_METHOD4(TransProxyProcessD2DData, int32_t(ProxyDataInfo *dataInfo, const PacketD2DHead *dataHead,
            const char *data, int32_t businessType));
    MOCK_METHOD5(TransProxyDecryptD2DData, int32_t(int32_t businessType, ProxyDataInfo *dataInfo,
            const char *sessionKey, const char *sessionBytesIv, const unsigned char *sessionMsgIv));
    MOCK_METHOD2(TransProxySessionDataLenCheck, int32_t(uint32_t dataLen, SessionPktType type));
    MOCK_METHOD4(ClientGetSessionIdByChannelId, int32_t (int32_t channelId, int32_t channelType,
        int32_t *sessionId, bool isClosing));
    MOCK_METHOD3(ClientGetSessionCallbackAdapterById, int32_t(int32_t sessionId,
        SessionListenerAdapter *callbackAdapter, bool *isServer));
    MOCK_METHOD2(DeleteDataSeqInfoList, int32_t(uint32_t dataSeq, int32_t channelId));
    MOCK_METHOD4(GetSupportTlvAndNeedAckById, int32_t (int32_t channelId, int32_t channelType,
        bool *supportTlv, bool *needAck));
    MOCK_METHOD4(DataSeqInfoListAddItem, int32_t(uint32_t dataSeq, int32_t channelId, int32_t socketId,
        int32_t channelType));
};
} // namespace OHOS
#endif // TRANS_CLIENT_PROXY_FILE_MANAGER_MOCK_H
