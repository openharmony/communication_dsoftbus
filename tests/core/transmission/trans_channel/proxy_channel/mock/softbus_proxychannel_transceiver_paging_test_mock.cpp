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

#include "softbus_proxychannel_transceiver_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_softbusProxychannelTransceiverPagingInterface;
SoftbusProxychannelTransceiverPagingInterfaceMock::SoftbusProxychannelTransceiverPagingInterfaceMock()
{
    g_softbusProxychannelTransceiverPagingInterface = reinterpret_cast<void *>(this);
}

SoftbusProxychannelTransceiverPagingInterfaceMock::~SoftbusProxychannelTransceiverPagingInterfaceMock()
{
    g_softbusProxychannelTransceiverPagingInterface = nullptr;
}

static SoftbusProxychannelTransceiverPagingInterface *GetSoftbusProxychannelTransceiverPagingInterface()
{
    return reinterpret_cast<SoftbusProxychannelTransceiverPagingInterface *>(
        g_softbusProxychannelTransceiverPagingInterface);
}

extern "C" {
int32_t TransParseMessageHeadType(char *data, int32_t len, ProxyMessage *msg)
{
    return GetSoftbusProxychannelTransceiverPagingInterface()->TransParseMessageHeadType(data, len, msg);
}

int32_t TransPagingParseMessage(char *data, int32_t len, ProxyMessage *msg)
{
    return GetSoftbusProxychannelTransceiverPagingInterface()->TransPagingParseMessage(data, len, msg);
}

int32_t TransProxyGetChannelByCheckInfo(const PagingListenCheckInfo *checkInfo, ProxyChannelInfo *chan, bool isClient)
{
    return GetSoftbusProxychannelTransceiverPagingInterface()->TransProxyGetChannelByCheckInfo(
        checkInfo, chan, isClient);
}

bool TransHasAndUpdatePagingListenPacked(ProxyChannelInfo *info)
{
    return GetSoftbusProxychannelTransceiverPagingInterface()->TransHasAndUpdatePagingListenPacked(info);
}

int32_t TransProxyPagingChannelOpened(ProxyChannelInfo *chan)
{
    return GetSoftbusProxychannelTransceiverPagingInterface()->TransProxyPagingChannelOpened(chan);
}

int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
{
    return GetSoftbusProxychannelTransceiverPagingInterface()->LnnAsyncCallbackDelayHelper(
        looper, callback, para, delayMillis);
}
}
}
