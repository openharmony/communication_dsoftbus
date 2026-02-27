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

#ifndef TRANS_TCP_DIRECT_TLV_MOCK_H
#define TRANS_TCP_DIRECT_TLV_MOCK_H

#include <gmock/gmock.h>

#include "client_bus_center_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_tcp_direct_manager.h"
#include "softbus_bus_center.h"
#include "trans_assemble_tlv.h"

namespace OHOS {
class TransTcpDirectInterface {
public:
    TransTcpDirectInterface() {};
    virtual ~TransTcpDirectInterface() {};
    virtual int32_t TransAssembleTlvData(DataHead *pktHead, uint8_t type, uint8_t *buffer, uint8_t bufferLen,
        int32_t *bufferSize) = 0;
    virtual int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId,
        bool isClosing) = 0;
    virtual int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter,
        bool *isServer) = 0;
    virtual int32_t DeleteDataSeqInfoList(uint32_t dataSeq, int32_t channelId) = 0;
    virtual int32_t ClientGetSessionNameByChannelId(int32_t channelId, int32_t channelType, char *sessionName,
        int32_t len) = 0;
    virtual int32_t SetIpTos(int fd, uint32_t tos) = 0;
    virtual int32_t AddPendingPacket(int32_t channelId, int32_t seqNum, int32_t type) = 0;
    virtual int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType, bool *supportTlv,
        bool *needAck) = 0;
    virtual void ReleaseTlvValueBuffer(DataHead *pktHead) = 0;
    virtual int32_t DataSeqInfoListAddItem(uint32_t dataSeq, int32_t channelId, int32_t socketId,
        int32_t channelType) = 0;
    virtual int32_t ClientTransTdcOnDataReceived(int32_t channelId, const void *data, uint32_t len,
    SessionPktType type) = 0;
    virtual int32_t SetMintpSocketTos(int32_t fd, uint32_t tos) = 0;
    virtual int32_t SetPendingPacket(int32_t channelId, int32_t seqNum, int32_t type) = 0;
    virtual ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout) = 0;
    virtual int32_t ConnSetTcpKeepalive(
        int32_t fd, int32_t seconds, int32_t keepAliveIntvl, int32_t keepAliveCount) = 0;
    virtual int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millsec) = 0;
    virtual int32_t StartTimeSyncWithSocketInner(const char *pkgName, const TimeSyncSocketInfo *socketInfo,
        TimeSyncAccuracy accuracy, TimeSyncPeriod period, ITimeSyncCbWithSocket *cbWithSocket) = 0;
};

class TransTcpDirectInterfaceMock : public TransTcpDirectInterface {
public:
    TransTcpDirectInterfaceMock();
    ~TransTcpDirectInterfaceMock() override;
    MOCK_METHOD5(TransAssembleTlvData, int32_t(DataHead *pktHead, uint8_t type, uint8_t *buffer, uint8_t bufferLen,
        int32_t *bufferSize));
    MOCK_METHOD4(ClientGetSessionIdByChannelId, int32_t(int32_t channelId, int32_t channelType, int32_t *sessionId,
        bool isClosing));
    MOCK_METHOD3(ClientGetSessionCallbackAdapterById, int32_t(int32_t sessionId,
        SessionListenerAdapter *callbackAdapter, bool *isServer));
    MOCK_METHOD2(DeleteDataSeqInfoList, int32_t(uint32_t dataSeq, int32_t channelId));
    MOCK_METHOD4(ClientGetSessionNameByChannelId, int32_t(int32_t channelId, int32_t channelType, char *sessionName,
        int32_t len));
    MOCK_METHOD2(SetIpTos, int32_t(int fd, uint32_t tos));
    MOCK_METHOD3(AddPendingPacket, int32_t(int32_t channelId, int32_t seqNum, int32_t type));
    MOCK_METHOD4(GetSupportTlvAndNeedAckById, int32_t(int32_t channelId, int32_t channelType, bool *supportTlv,
        bool *needAck));
    MOCK_METHOD1(ReleaseTlvValueBuffer, void (DataHead *pktHead));
    MOCK_METHOD4(DataSeqInfoListAddItem, int32_t(uint32_t dataSeq, int32_t channelId, int32_t socketId,
        int32_t channelType));
    MOCK_METHOD4(ClientTransTdcOnDataReceived, int32_t(int32_t channelId, const void *data, uint32_t len,
        SessionPktType type));
    MOCK_METHOD2(SetMintpSocketTos, int32_t(int32_t fd, uint32_t tos));
    MOCK_METHOD3(SetPendingPacket, int32_t(int32_t channelId, int32_t seqNum, int32_t type));
    MOCK_METHOD4(ConnSendSocketData, ssize_t(int32_t fd, const char *buf, size_t len, int32_t timeout));
    MOCK_METHOD4(ConnSetTcpKeepalive, int32_t(
        int32_t fd, int32_t seconds, int32_t keepAliveIntvl, int32_t keepAliveCount));
    MOCK_METHOD2(ConnSetTcpUserTimeOut, int32_t(int32_t fd, uint32_t millsec));
    MOCK_METHOD5(StartTimeSyncWithSocketInner, int32_t(const char *pkgName, const TimeSyncSocketInfo *socketInfo,
        TimeSyncAccuracy accuracy, TimeSyncPeriod period, ITimeSyncCbWithSocket *cbWithSocket));
};
} // namespace OHOS
#endif // TRANS_TCP_DIRECT_TLV_MOCK_H
