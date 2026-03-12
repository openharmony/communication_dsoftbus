/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_TCP_DIRECT_MESSAGE_MOCK_H
#define CLIENT_TRANS_TCP_DIRECT_MESSAGE_MOCK_H

#include <gmock/gmock.h>
#include "client_trans_session_manager_struct.h"
#include "client_trans_tcp_direct_manager.h"
#include "trans_tcp_process_data.h"

namespace OHOS {
class TransTcpDirectMsgInterface {
public:
    TransTcpDirectMsgInterface() {};
    virtual ~TransTcpDirectMsgInterface() {};
    virtual int32_t GetSupportTlvAndNeedAckById(
        int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck) = 0;
    virtual char *TransTdcPackAllData(TransTdcPackDataInfo *info,
        const char *sessionKey, const char *data, int32_t flags, DataLenInfo *lenInfo) = 0;
    virtual int32_t ClientGetSessionNameByChannelId(
        int32_t channelId, int32_t channelType, char *sessionName, int32_t len) = 0;
    virtual int32_t TransTdcSendData(DataLenInfo *lenInfo, bool supportTlv, int32_t fd, uint32_t len, char *buf) = 0;
    virtual TcpDirectChannelInfo *TransTdcGetInfoIncFdRefById(
        int32_t channelId, TcpDirectChannelInfo *info, bool withSeq) = 0;
    virtual int32_t AddPendingPacket(int32_t channelId, int32_t seqNum, int32_t type) = 0;
    virtual int32_t ProcPendingPacket(int32_t channelId, int32_t seqNum, int32_t type) = 0;
    virtual int32_t BuildDataHead(DataHead *pktHead, int32_t finalSeq, int32_t flags, uint32_t dataLen,
        int32_t *tlvBufferSize) = 0;
    virtual int32_t BuildNeedAckTlvData(DataHead *pktHead, bool needAck, uint32_t dataSeqs, int32_t *tlvBufferSize) = 0;
    virtual char *TransTdcPackTlvData(DataHead *pktHead, int32_t tlvBufferSize, uint32_t dataLen) = 0;
    virtual void ReleaseDataHeadResource(DataHead *pktHead) = 0;
    virtual int32_t TransTdcEncryptWithSeq(const char *sessionKey, int32_t seqNum, EncrptyInfo *info) = 0;
    virtual ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout) = 0;
    virtual void TransUpdateFdState(int32_t channelId) = 0;
    virtual void DelPendingPacketbyChannelId(int32_t channelId, int32_t seqNum, int32_t type) = 0;
    virtual int32_t ClientTransTdcOnDataReceived(
        int32_t channelId, const void *data, uint32_t len, SessionPktType type) = 0;
    virtual int32_t TransTdcGetInfoById(int32_t channelId, TcpDirectChannelInfo *info) = 0;
    virtual int32_t TransTdcDecrypt(
        const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen) = 0;
    virtual int32_t MoveNode(int32_t channelId, DataBuf *node, uint32_t dataLen, int32_t pkgHeadSize) = 0;
    virtual int32_t TransTdcUnPackData(
        int32_t channelId, const char *sessionKey, char *plain, uint32_t *plainLen, DataBuf *node) = 0;
    virtual uint64_t SoftBusGetTimeMs(void) = 0;
    virtual void TransTdcSetTimestamp(int32_t channelId, uint64_t timestamp) = 0;
    virtual int32_t TransTdcUnPackAllTlvData(
        int32_t channelId, TcpDataTlvPacketHead *head, uint32_t *headSize, DataBuf *node, bool *flag) = 0;
    virtual int32_t TransTdcUnPackAllData(int32_t channelId, DataBuf *node, bool *flag) = 0;
    virtual int32_t ClientGetSessionIdByChannelId(
        int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing) = 0;
    virtual int32_t DataSeqInfoListAddItem(
        uint32_t dataSeq, int32_t channelId, int32_t socketId, int32_t channelType) = 0;
    virtual int32_t ClientGetSessionCallbackAdapterById(
        int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer) = 0;
    virtual int32_t DeleteDataSeqInfoList(uint32_t dataSeq, int32_t channelId) = 0;
};

class TransTcpDirectMsgInterfaceMock : public TransTcpDirectMsgInterface {
public:
    TransTcpDirectMsgInterfaceMock();
    ~TransTcpDirectMsgInterfaceMock() override;
    MOCK_METHOD4(GetSupportTlvAndNeedAckById, int32_t (
        int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck));
    MOCK_METHOD5(TransTdcPackAllData, char *(TransTdcPackDataInfo *info,
        const char *sessionKey, const char *data, int32_t flags, DataLenInfo *lenInfo));
    MOCK_METHOD4(ClientGetSessionNameByChannelId, int32_t (
        int32_t channelId, int32_t channelType, char *sessionName, int32_t len));
    MOCK_METHOD5(TransTdcSendData, int32_t (
        DataLenInfo *lenInfo, bool supportTlv, int32_t fd, uint32_t len, char *buf));
    MOCK_METHOD3(TransTdcGetInfoIncFdRefById, TcpDirectChannelInfo *(
        int32_t channelId, TcpDirectChannelInfo *info, bool withSeq));
    MOCK_METHOD3(AddPendingPacket, int32_t (int32_t channelId, int32_t seqNum, int32_t type));
    MOCK_METHOD3(ProcPendingPacket, int32_t (int32_t channelId, int32_t seqNum, int32_t type));
    MOCK_METHOD5(BuildDataHead, int32_t (DataHead *pktHead, int32_t finalSeq, int32_t flags, uint32_t dataLen,
        int32_t *tlvBufferSize));
    MOCK_METHOD4(BuildNeedAckTlvData, int32_t (
        DataHead *pktHead, bool needAck, uint32_t dataSeqs, int32_t *tlvBufferSize));
    MOCK_METHOD3(TransTdcPackTlvData, char *(DataHead *pktHead, int32_t tlvBufferSize, uint32_t dataLen));
    MOCK_METHOD1(ReleaseDataHeadResource, void (DataHead *pktHead));
    MOCK_METHOD3(TransTdcEncryptWithSeq, int32_t (const char *sessionKey, int32_t seqNum, EncrptyInfo *info));
    MOCK_METHOD4(ConnSendSocketData, ssize_t (int32_t fd, const char *buf, size_t len, int32_t timeout));
    MOCK_METHOD1(TransUpdateFdState, void (int32_t channelId));
    MOCK_METHOD3(DelPendingPacketbyChannelId, void (int32_t channelId, int32_t seqNum, int32_t type));
    MOCK_METHOD4(ClientTransTdcOnDataReceived, int32_t (
        int32_t channelId, const void *data, uint32_t len, SessionPktType type));
    MOCK_METHOD2(TransTdcGetInfoById, int32_t (int32_t channelId, TcpDirectChannelInfo *info));
    MOCK_METHOD5(TransTdcDecrypt, int32_t (
        const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen));
    MOCK_METHOD4(MoveNode, int32_t (int32_t channelId, DataBuf *node, uint32_t dataLen, int32_t pkgHeadSize));
    MOCK_METHOD5(TransTdcUnPackData, int32_t (
        int32_t channelId, const char *sessionKey, char *plain, uint32_t *plainLen, DataBuf *node));
    MOCK_METHOD0(SoftBusGetTimeMs, uint64_t ());
    MOCK_METHOD2(TransTdcSetTimestamp, void (int32_t channelId, uint64_t timestamp));
    MOCK_METHOD5(TransTdcUnPackAllTlvData, int32_t (
        int32_t channelId, TcpDataTlvPacketHead *head, uint32_t *headSize, DataBuf *node, bool *flag));
    MOCK_METHOD3(TransTdcUnPackAllData, int32_t (int32_t channelId, DataBuf *node, bool *flag));
    MOCK_METHOD4(ClientGetSessionIdByChannelId, int32_t (
        int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing));
    MOCK_METHOD4(DataSeqInfoListAddItem, int32_t (
        uint32_t dataSeq, int32_t channelId, int32_t socketId, int32_t channelType));
    MOCK_METHOD3(ClientGetSessionCallbackAdapterById, int32_t (
        int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer));
    MOCK_METHOD2(DeleteDataSeqInfoList, int32_t (uint32_t dataSeq, int32_t channelId));
};
} // namespace OHOS
#endif // CLIENT_TRANS_TCP_DIRECT_MESSAGE_MOCK_H
