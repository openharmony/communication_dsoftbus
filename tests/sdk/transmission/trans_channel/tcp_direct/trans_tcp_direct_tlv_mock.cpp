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

#include "trans_tcp_direct_tlv_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transTcpDirectInterface;
TransTcpDirectInterfaceMock::TransTcpDirectInterfaceMock()
{
    g_transTcpDirectInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectInterfaceMock::~TransTcpDirectInterfaceMock()
{
    g_transTcpDirectInterface = nullptr;
}

static TransTcpDirectInterface *GetTransTcpDirectInterface()
{
    return reinterpret_cast<TransTcpDirectInterface *>(g_transTcpDirectInterface);
}

extern "C" {
int32_t TransAssembleTlvData(DataHead *pktHead, uint8_t type, uint8_t *buffer, uint8_t bufferLen, int32_t *bufferSize)
{
    return GetTransTcpDirectInterface()->TransAssembleTlvData(pktHead, type, buffer, bufferLen, bufferSize);
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing)
{
    return GetTransTcpDirectInterface()->ClientGetSessionIdByChannelId(channelId, channelType, sessionId, isClosing);
}

int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer)
{
    return GetTransTcpDirectInterface()->ClientGetSessionCallbackAdapterById(sessionId, callbackAdapter, isServer);
}

int32_t DeleteDataSeqInfoList(uint32_t dataSeq, int32_t channelId)
{
    return GetTransTcpDirectInterface()->DeleteDataSeqInfoList(dataSeq, channelId);
}

int32_t ClientGetSessionNameByChannelId(int32_t channelId, int32_t channelType, char *sessionName, int32_t len)
{
    return GetTransTcpDirectInterface()->ClientGetSessionNameByChannelId(channelId, channelType, sessionName, len);
}

int32_t SetIpTos(int fd, uint32_t tos)
{
    return GetTransTcpDirectInterface()->SetIpTos(fd, tos);
}

int32_t AddPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    return GetTransTcpDirectInterface()->AddPendingPacket(channelId, seqNum, type);
}

int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck)
{
    return GetTransTcpDirectInterface()->GetSupportTlvAndNeedAckById(channelId, channelType, supportTlv, needAck);
}

void ReleaseTlvValueBuffer(DataHead *pktHead)
{
    return GetTransTcpDirectInterface()->ReleaseTlvValueBuffer(pktHead);
}

int32_t DataSeqInfoListAddItem(uint32_t dataSeq, int32_t channelId, int32_t socketId, int32_t channelType)
{
    return GetTransTcpDirectInterface()->DataSeqInfoListAddItem(dataSeq, channelId, socketId, channelType);
}

int32_t ClientTransTdcOnDataReceived(int32_t channelId, const void *data, uint32_t len, SessionPktType type)
{
    return GetTransTcpDirectInterface()->ClientTransTdcOnDataReceived(channelId, data, len, type);
}

int32_t SetMintpSocketTos(int32_t fd, uint32_t tos)
{
    return GetTransTcpDirectInterface()->SetMintpSocketTos(fd, tos);
}

int32_t SetPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    return GetTransTcpDirectInterface()->SetPendingPacket(channelId, seqNum, type);
}

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    return GetTransTcpDirectInterface()->ConnSendSocketData(fd, buf, len, timeout);
}

int32_t ConnSetTcpKeepalive(int32_t fd, int32_t seconds, int32_t keepAliveIntvl, int32_t keepAliveCount)
{
    return GetTransTcpDirectInterface()->ConnSetTcpKeepalive(fd, seconds, keepAliveIntvl, keepAliveCount);
}

int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millsec)
{
    return GetTransTcpDirectInterface()->ConnSetTcpUserTimeOut(fd, millsec);
}

int32_t StartTimeSyncWithSocketInner(const char *pkgName, const TimeSyncSocketInfo *socketInfo,
    TimeSyncAccuracy accuracy, TimeSyncPeriod period, ITimeSyncCbWithSocket *cbWithSocket)
{
    return GetTransTcpDirectInterface()->StartTimeSyncWithSocketInner(
        pkgName, socketInfo, accuracy, period, cbWithSocket);
}
}
}
