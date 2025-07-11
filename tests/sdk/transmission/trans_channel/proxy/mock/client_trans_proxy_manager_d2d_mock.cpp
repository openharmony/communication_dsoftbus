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

#include "client_trans_proxy_manager_d2d_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transD2DInterface;
TransClientProxyD2DInterfaceMock::TransClientProxyD2DInterfaceMock()
{
    g_transD2DInterface = reinterpret_cast<void *>(this);
}

TransClientProxyD2DInterfaceMock::~TransClientProxyD2DInterfaceMock()
{
    g_transD2DInterface = nullptr;
}

static TransClientProxyManagerD2DInterface *GetProxyManagerD2DInterface()
{
    return reinterpret_cast<TransClientProxyManagerD2DInterface *>(g_transD2DInterface);
}

extern "C" {
int32_t ClientGetChannelBusinessTypeByChannelId(int32_t channelId, int32_t *businessType)
{
    return GetProxyManagerD2DInterface()->ClientGetChannelBusinessTypeByChannelId(channelId, businessType);
}

int32_t TransProxyPackD2DBytes(ProxyDataInfo *dataInfo, const char *sessionKey, const char *sessionIv,
    SessionPktType flag)
{
    return GetProxyManagerD2DInterface()->TransProxyPackD2DBytes(dataInfo, sessionKey, sessionIv, flag);
}

uint8_t *TransProxyPackD2DData(ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType,
    uint32_t cnt, uint32_t *dataLen)
{
    return GetProxyManagerD2DInterface()->TransProxyPackD2DData(dataInfo, sliceNum, pktType, cnt, dataLen);
}

int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    return GetProxyManagerD2DInterface()->ServerIpcSendMessage(channelId, channelType, data, len, msgType);
}

int32_t TransProxyProcessD2DData(ProxyDataInfo *dataInfo, const PacketD2DHead *dataHead,
    const char *data, int32_t businessType)
{
    return GetProxyManagerD2DInterface()->TransProxyProcessD2DData(dataInfo, dataHead, data, businessType);
}

int32_t TransProxyDecryptD2DData(int32_t businessType, ProxyDataInfo *dataInfo, const char *sessionKey,
    const char *sessionBytesIv, const unsigned char *sessionMsgIv)
{
    return GetProxyManagerD2DInterface()->TransProxyDecryptD2DData(businessType, dataInfo, sessionKey,
        sessionBytesIv, sessionMsgIv);
}

int32_t TransProxySessionDataLenCheck(uint32_t dataLen, SessionPktType type)
{
    return GetProxyManagerD2DInterface()->TransProxySessionDataLenCheck(dataLen, type);
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing)
{
    return GetProxyManagerD2DInterface()->ClientGetSessionIdByChannelId(channelId, channelType, sessionId, isClosing);
}

int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer)
{
    return GetProxyManagerD2DInterface()->ClientGetSessionCallbackAdapterById(sessionId, callbackAdapter, isServer);
}

int32_t DeleteDataSeqInfoList(uint32_t dataSeq, int32_t channelId)
{
    return GetProxyManagerD2DInterface()->DeleteDataSeqInfoList(dataSeq, channelId);
}

int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck)
{
    return GetProxyManagerD2DInterface()->GetSupportTlvAndNeedAckById(
        channelId, channelType, supportTlv, needAck);
}

int32_t DataSeqInfoListAddItem(uint32_t dataSeq, int32_t channelId, int32_t socketId, int32_t channelType)
{
    return GetProxyManagerD2DInterface()->DataSeqInfoListAddItem(dataSeq, channelId, socketId, channelType);
}
}
}
