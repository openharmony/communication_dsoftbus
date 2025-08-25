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

#include "softbus_proxychannel_control_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_softbusProxychannelControlPagingInterface;
SoftbusProxychannelControlPagingInterfaceMock::SoftbusProxychannelControlPagingInterfaceMock()
{
    g_softbusProxychannelControlPagingInterface = reinterpret_cast<void *>(this);
}

SoftbusProxychannelControlPagingInterfaceMock::~SoftbusProxychannelControlPagingInterfaceMock()
{
    g_softbusProxychannelControlPagingInterface = nullptr;
}

static SoftbusProxychannelControlPagingInterface *GetSoftbusProxychannelControlPagingInterface()
{
    return reinterpret_cast<SoftbusProxychannelControlPagingInterface *>(g_softbusProxychannelControlPagingInterface);
}

extern "C" {
int32_t TransProxyGetSendMsgChanInfo(int32_t channelId, ProxyChannelInfo *chanInfo)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyGetSendMsgChanInfo(channelId, chanInfo);
}

char *TransPagingPackHandShakeMsg(ProxyChannelInfo *info)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransPagingPackHandShakeMsg(info);
}

int32_t TransPagingPackMessage(PagingProxyMessage *msg, ProxyDataInfo *dataInfo, ProxyChannelInfo *chan, bool needHash)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransPagingPackMessage(msg, dataInfo, chan, needHash);
}

int32_t TransProxyTransSendMsg(uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyTransSendMsg(
        connectionId, buf, len, priority, pid);
}

int32_t ConvertBytesToHexString(
    char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return GetSoftbusProxychannelControlPagingInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t AuthFindApplyKey(
    const RequestBusinessInfo *info, uint8_t *applyKey, char *accountHash, uint32_t accountHashLen)
{
    return GetSoftbusProxychannelControlPagingInterface()->AuthFindApplyKey(
        info, applyKey, accountHash, accountHashLen);
}

char *TransPagingPackHandshakeAckMsg(ProxyChannelInfo *chan)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransPagingPackHandshakeAckMsg(chan);
}
}
}
