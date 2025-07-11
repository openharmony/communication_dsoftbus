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

#include "softbus_proxychannel_manager_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_softbusProxychannelManagerPagingInterface;
SoftbusProxychannelManagerPagingInterfaceMock::SoftbusProxychannelManagerPagingInterfaceMock()
{
    g_softbusProxychannelManagerPagingInterface = reinterpret_cast<void *>(this);
}

SoftbusProxychannelManagerPagingInterfaceMock::~SoftbusProxychannelManagerPagingInterfaceMock()
{
    g_softbusProxychannelManagerPagingInterface = nullptr;
}

static SoftbusProxychannelManagerPagingInterface *GetSoftbusProxychannelManagerPagingInterface()
{
    return reinterpret_cast<SoftbusProxychannelManagerPagingInterface *>(g_softbusProxychannelManagerPagingInterface);
}

extern "C" {
void TransProxyPagingHandshakeMsgToLoop(int32_t channelId, uint8_t *authKey, uint32_t keyLen)
{
    return GetSoftbusProxychannelManagerPagingInterface()->TransProxyPagingHandshakeMsgToLoop(
        channelId, authKey, keyLen);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
    uint32_t inLen)
{
    return GetSoftbusProxychannelManagerPagingInterface()->ConvertBytesToHexString(
        outBuf, outBufLen, inBuf, inLen);
}

int32_t AuthGenApplyKey(
    const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId, const GenApplyKeyCallback *genCb)
{
    return GetSoftbusProxychannelManagerPagingInterface()->AuthGenApplyKey(info, requestId, connId, genCb);
}

cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length)
{
    return GetSoftbusProxychannelManagerPagingInterface()->cJSON_ParseWithLength(value, buffer_length);
}

int32_t TransPagingAckHandshake(ProxyChannelInfo *chan, int32_t retCode)
{
    return GetSoftbusProxychannelManagerPagingInterface()->TransPagingAckHandshake(chan, retCode);
}

int32_t OnProxyChannelBind(int32_t channelId, const AppInfo *appInfo)
{
    return GetSoftbusProxychannelManagerPagingInterface()->OnProxyChannelBind(channelId, appInfo);
}

int32_t OnProxyChannelClosed(int32_t channelId, const AppInfo *appInfo)
{
    return GetSoftbusProxychannelManagerPagingInterface()->OnProxyChannelClosed(channelId, appInfo);
}
}
}
