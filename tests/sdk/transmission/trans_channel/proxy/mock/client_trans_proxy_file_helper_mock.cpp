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

#include "client_trans_proxy_file_helper_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_clientTransProxyFileHelperInterface;
ClientTransProxyFileHelperInterfaceMock::ClientTransProxyFileHelperInterfaceMock()
{
    g_clientTransProxyFileHelperInterface = reinterpret_cast<void *>(this);
}

ClientTransProxyFileHelperInterfaceMock::~ClientTransProxyFileHelperInterfaceMock()
{
    g_clientTransProxyFileHelperInterface = nullptr;
}

static ClientTransProxyFileHelperInterface *GetClientTransProxyFileHelperInterface()
{
    return reinterpret_cast<ClientTransProxyFileHelperInterface *>(g_clientTransProxyFileHelperInterface);
}

extern "C" {
int32_t ClientTransProxyPackAndSendData(int32_t channelId, const void* data, uint32_t len,
    ProxyChannelInfoDetail* info, SessionPktType pktType)
{
    return GetClientTransProxyFileHelperInterface()->ClientTransProxyPackAndSendData(
        channelId, data, len, info, pktType);
}
int32_t ClientTransProxyGetInfoByChannelId(int32_t channelId, ProxyChannelInfoDetail *info)
{
    return GetClientTransProxyFileHelperInterface()->ClientTransProxyGetInfoByChannelId(channelId, info);
}
uint32_t SoftBusLtoHl(uint32_t value)
{
    return GetClientTransProxyFileHelperInterface()->SoftBusLtoHl(value);
}

uint32_t SoftBusHtoLl(uint32_t value)
{
    return GetClientTransProxyFileHelperInterface()->SoftBusHtoLl(value);
}

uint64_t SoftBusLtoHll(uint64_t value)
{
    return GetClientTransProxyFileHelperInterface()->SoftBusLtoHll(value);
}

uint64_t SoftBusHtoLll(uint64_t value)
{
    return GetClientTransProxyFileHelperInterface()->SoftBusHtoLll(value);
}
uint32_t SoftBusNtoHl(uint32_t value)
{
    return GetClientTransProxyFileHelperInterface()->SoftBusNtoHl(value);
}
uint16_t SoftBusHtoLs(uint16_t value)
{
    return GetClientTransProxyFileHelperInterface()->SoftBusHtoLs(value);
}
int64_t SoftBusPreadFile(int32_t fd, void *buf, uint64_t readBytes, uint64_t offset)
{
    return GetClientTransProxyFileHelperInterface()->SoftBusPreadFile(fd, buf, readBytes, offset);
}
uint16_t RTU_CRC(const unsigned char *puchMsg, uint16_t usDataLen)
{
    return GetClientTransProxyFileHelperInterface()->RTU_CRC(puchMsg, usDataLen);
}

int32_t FrameIndexToType(uint64_t index, uint64_t frameNumber)
{
    return GetClientTransProxyFileHelperInterface()->FrameIndexToType(index, frameNumber);
}
}
}
