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

#ifndef CLIENT_TRANS_PROXY_MANAGER_MOCK_H
#define CLIENT_TRANS_PROXY_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include "client_trans_pending.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "trans_proxy_process_data.h"
#include "trans_server_proxy.h"

namespace OHOS {
class ClientTransProxyManagerInterface {
public:
    ClientTransProxyManagerInterface() {};
    virtual ~ClientTransProxyManagerInterface() {};
    virtual int32_t ClinetTransProxyFileManagerInit(void) = 0;
    virtual SoftBusList *CreateSoftBusList(void) = 0;
    virtual int32_t PendingInit(int32_t type) = 0;
    virtual uint32_t SoftBusHtoLl(uint32_t value) = 0;
    virtual uint32_t SoftBusHtoNl(uint32_t value) = 0;
    virtual uint32_t SoftBusNtoHl(uint32_t netlong) = 0;
    virtual int32_t ClientGetSessionIdByChannelId(
        int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing) = 0;
    virtual int32_t ClientGetSessionCallbackAdapterById(
        int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer) = 0;
    virtual int32_t DeleteDataSeqInfoList(uint32_t dataSeq, int32_t channelId) = 0;
    virtual int32_t GetSupportTlvAndNeedAckById(
        int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck) = 0;
    virtual int32_t ServerIpcSendMessage(
        int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType) = 0;
    virtual int32_t TransProxySessionDataLenCheck(uint32_t dataLen, SessionPktType type) = 0;
    virtual int32_t TransProxyPackTlvBytes(ProxyDataInfo *dataInfo, const char *sessionKey,
        SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info) = 0;
    virtual uint8_t *TransProxyPackData(
        ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType, uint32_t cnt, uint32_t *dataLen) = 0;
    virtual int32_t ProcPendingPacket(int32_t channelId, int32_t seqNum, int32_t type) = 0;
    virtual int32_t AddPendingPacket(int32_t channelId, int32_t seqNum, int32_t type) = 0;
    virtual int32_t TransProxyDecryptPacketData(int32_t seq, ProxyDataInfo *dataInfo, const char *sessionKey) = 0;
    virtual int32_t DataSeqInfoListAddItem(uint32_t dataSeq, int32_t channelId,
        int32_t socketId, int32_t channelType);
    virtual int32_t ClientGetChannelBusinessTypeByChannelId(int32_t channelId, int32_t *businessType) = 0;
    virtual int32_t TransProxyD2dDataLenCheck(uint32_t dataLen, BusinessType type) = 0;
};

class ClientTransProxyManagerInterfaceMock : public ClientTransProxyManagerInterface {
public:
    ClientTransProxyManagerInterfaceMock();
    ~ClientTransProxyManagerInterfaceMock() override;
    MOCK_METHOD0(ClinetTransProxyFileManagerInit, int32_t (void));
    MOCK_METHOD0(CreateSoftBusList, SoftBusList* (void));
    MOCK_METHOD1(PendingInit, int32_t (int32_t type));
    MOCK_METHOD1(SoftBusHtoLl, uint32_t (uint32_t value));
    MOCK_METHOD1(SoftBusHtoNl, uint32_t (uint32_t value));
    MOCK_METHOD1(SoftBusNtoHl, uint32_t (uint32_t netlong));
    MOCK_METHOD4(ClientGetSessionIdByChannelId, int32_t (
        int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing));
    MOCK_METHOD3(ClientGetSessionCallbackAdapterById, int32_t (
        int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer));
    MOCK_METHOD2(DeleteDataSeqInfoList, int32_t (uint32_t dataSeq, int32_t channelId));
    MOCK_METHOD4(GetSupportTlvAndNeedAckById, int32_t (
        int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck));
    MOCK_METHOD5(ServerIpcSendMessage, int32_t (
        int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType));
    MOCK_METHOD2(TransProxySessionDataLenCheck, int32_t (uint32_t dataLen, SessionPktType type));
    MOCK_METHOD5(TransProxyPackTlvBytes, int32_t (ProxyDataInfo *dataInfo, const char *sessionKey,
        SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info));
    MOCK_METHOD5(TransProxyPackData, uint8_t* (
        ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType, uint32_t cnt, uint32_t *dataLen));
    MOCK_METHOD3(ProcPendingPacket, int32_t (int32_t channelId, int32_t seqNum, int32_t type));
    MOCK_METHOD3(AddPendingPacket, int32_t (int32_t channelId, int32_t seqNum, int32_t type));
    MOCK_METHOD3(TransProxyDecryptPacketData, int32_t (int32_t seq, ProxyDataInfo *dataInfo, const char *sessionKey));
    MOCK_METHOD4(DataSeqInfoListAddItem, int32_t (uint32_t dataSeq, int32_t channelId,
        int32_t socketId, int32_t channelType));
    MOCK_METHOD2(ClientGetChannelBusinessTypeByChannelId, int32_t(int32_t channelId, int32_t *businessType));
    MOCK_METHOD2(TransProxyD2dDataLenCheck, int32_t(uint32_t dataLen, BusinessType type));
};
}
#endif