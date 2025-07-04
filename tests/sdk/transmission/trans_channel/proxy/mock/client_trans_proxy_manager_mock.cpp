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

#include "client_trans_proxy_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_clientTransProxyManagerInterface;
ClientTransProxyManagerInterfaceMock::ClientTransProxyManagerInterfaceMock()
{
    g_clientTransProxyManagerInterface = reinterpret_cast<void *>(this);
}

ClientTransProxyManagerInterfaceMock::~ClientTransProxyManagerInterfaceMock()
{
    g_clientTransProxyManagerInterface = nullptr;
}

static ClientTransProxyManagerInterface *GetClientTransProxyManagerInterface()
{
    return reinterpret_cast<ClientTransProxyManagerInterface *>(g_clientTransProxyManagerInterface);
}

extern "C" {
int32_t ClinetTransProxyFileManagerInit(void)
{
    return GetClientTransProxyManagerInterface()->ClinetTransProxyFileManagerInit();
}

SoftBusList *CreateSoftBusList(void)
{
    return GetClientTransProxyManagerInterface()->CreateSoftBusList();
}

int32_t PendingInit(int32_t type)
{
    return GetClientTransProxyManagerInterface()->PendingInit(type);
}
uint32_t SoftBusHtoLl(uint32_t value)
{
    return GetClientTransProxyManagerInterface()->SoftBusHtoLl(value);
}
uint32_t SoftBusHtoNl(uint32_t value)
{
    return GetClientTransProxyManagerInterface()->SoftBusHtoNl(value);
}

uint32_t SoftBusNtoHl(uint32_t value)
{
    return GetClientTransProxyManagerInterface()->SoftBusNtoHl(value);
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing)
{
    return GetClientTransProxyManagerInterface()->ClientGetSessionIdByChannelId(
        channelId, channelType, sessionId, isClosing);
}

int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer)
{
    return GetClientTransProxyManagerInterface()->ClientGetSessionCallbackAdapterById(
        sessionId, callbackAdapter, isServer);
}

int32_t DeleteDataSeqInfoList(uint32_t dataSeq, int32_t channelId)
{
    return GetClientTransProxyManagerInterface()->DeleteDataSeqInfoList(dataSeq, channelId);
}

int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck)
{
    return GetClientTransProxyManagerInterface()->GetSupportTlvAndNeedAckById(
        channelId, channelType, supportTlv, needAck);
}

int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    return GetClientTransProxyManagerInterface()->ServerIpcSendMessage(channelId, channelType, data, len, msgType);
}

int32_t TransProxySessionDataLenCheck(uint32_t dataLen, SessionPktType type)
{
    return GetClientTransProxyManagerInterface()->TransProxySessionDataLenCheck(dataLen, type);
}

int32_t TransProxyPackTlvBytes(
    ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info)
{
    return GetClientTransProxyManagerInterface()->TransProxyPackTlvBytes(dataInfo, sessionKey, flag, seq, info);
}

uint8_t *TransProxyPackData(
    ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType, uint32_t cnt, uint32_t *dataLen)
{
    return GetClientTransProxyManagerInterface()->TransProxyPackData(dataInfo, sliceNum, pktType, cnt, dataLen);
}

int32_t ProcPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    return GetClientTransProxyManagerInterface()->ProcPendingPacket(channelId, seqNum, type);
}

int32_t AddPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    return GetClientTransProxyManagerInterface()->AddPendingPacket(channelId, seqNum, type);
}

int32_t TransProxyDecryptPacketData(int32_t seq, ProxyDataInfo *dataInfo, const char *sessionKey)
{
    return GetClientTransProxyManagerInterface()->TransProxyDecryptPacketData(seq, dataInfo, sessionKey);
}

int32_t DataSeqInfoListAddItem(uint32_t dataSeq, int32_t channelId, int32_t socketId, int32_t channelType)
{
    return GetClientTransProxyManagerInterface()->DataSeqInfoListAddItem(dataSeq, channelId, socketId, channelType);
}
}
}
