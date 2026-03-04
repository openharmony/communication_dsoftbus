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

#include "client_trans_tcp_direct_message_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transTcpDirectMsgInterface;
TransTcpDirectMsgInterfaceMock::TransTcpDirectMsgInterfaceMock()
{
    g_transTcpDirectMsgInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectMsgInterfaceMock::~TransTcpDirectMsgInterfaceMock()
{
    g_transTcpDirectMsgInterface = nullptr;
}

static TransTcpDirectMsgInterface *GetTransTcpDirectMsgInterface()
{
    return reinterpret_cast<TransTcpDirectMsgInterface *>(g_transTcpDirectMsgInterface);
}

extern "C" {
int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck)
{
    return GetTransTcpDirectMsgInterface()->GetSupportTlvAndNeedAckById(channelId, channelType, supportTlv, needAck);
}

char *TransTdcPackAllData(
    TransTdcPackDataInfo *info, const char *sessionKey, const char *data, int32_t flags, DataLenInfo *lenInfo)
{
    return GetTransTcpDirectMsgInterface()->TransTdcPackAllData(info, sessionKey, data, flags, lenInfo);
}

int32_t ClientGetSessionNameByChannelId(int32_t channelId, int32_t channelType, char *sessionName, int32_t len)
{
    return GetTransTcpDirectMsgInterface()->ClientGetSessionNameByChannelId(channelId, channelType, sessionName, len);
}

int32_t TransTdcSendData(DataLenInfo *lenInfo, bool supportTlv, int32_t fd, uint32_t len, char *buf)
{
    return GetTransTcpDirectMsgInterface()->TransTdcSendData(lenInfo, supportTlv, fd, len, buf);
}

TcpDirectChannelInfo *TransTdcGetInfoIncFdRefById(int32_t channelId, TcpDirectChannelInfo *info, bool withSeq)
{
    return GetTransTcpDirectMsgInterface()->TransTdcGetInfoIncFdRefById(channelId, info, withSeq);
}

int32_t AddPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    return GetTransTcpDirectMsgInterface()->AddPendingPacket(channelId, seqNum, type);
}

int32_t ProcPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    return GetTransTcpDirectMsgInterface()->ProcPendingPacket(channelId, seqNum, type);
}

int32_t BuildDataHead(DataHead *pktHead, int32_t finalSeq, int32_t flags, uint32_t dataLen,
    int32_t *tlvBufferSize)
{
    return GetTransTcpDirectMsgInterface()->BuildDataHead(pktHead, finalSeq, flags, dataLen, tlvBufferSize);
}

int32_t BuildNeedAckTlvData(DataHead *pktHead, bool needAck, uint32_t dataSeqs, int32_t *tlvBufferSize)
{
    return GetTransTcpDirectMsgInterface()->BuildNeedAckTlvData(pktHead, needAck, dataSeqs, tlvBufferSize);
}

char *TransTdcPackTlvData(DataHead *pktHead, int32_t tlvBufferSize, uint32_t dataLen)
{
    return GetTransTcpDirectMsgInterface()->TransTdcPackTlvData(pktHead, tlvBufferSize, dataLen);
}

void ReleaseDataHeadResource(DataHead *pktHead)
{
    return GetTransTcpDirectMsgInterface()->ReleaseDataHeadResource(pktHead);
}

int32_t TransTdcEncryptWithSeq(const char *sessionKey, int32_t seqNum, EncrptyInfo *info)
{
    return GetTransTcpDirectMsgInterface()->TransTdcEncryptWithSeq(sessionKey, seqNum, info);
}

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    return GetTransTcpDirectMsgInterface()->ConnSendSocketData(fd, buf, len, timeout);
}

void TransUpdateFdState(int32_t channelId)
{
    return GetTransTcpDirectMsgInterface()->TransUpdateFdState(channelId);
}
}
}
