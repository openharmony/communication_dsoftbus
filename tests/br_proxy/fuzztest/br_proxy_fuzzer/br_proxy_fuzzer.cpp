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

#include "br_proxy_fuzzer.h"

#include <cstddef>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>
#include <cstring>

#include "gtest/gtest.h"
#include "br_proxy_test_mock.h"
#include "br_proxy.h"

namespace OHOS {
static void FillBrProxyChannelInfo(FuzzedDataProvider &provider, BrProxyChannelInfo *channelInfo)
{
    std::string peerBRMacAddr = provider.ConsumeRandomLengthString(BR_MAC_LEN);
    std::string peerBRUuid = provider.ConsumeRandomLengthString(UUID_LEN);
    if (strcpy_s(channelInfo->peerBRMacAddr, BR_MAC_LEN, peerBRMacAddr.c_str()) != 0) {
        return;
    }
    if (strcpy_s(channelInfo->peerBRUuid, UUID_LEN, peerBRUuid.c_str()) != 0) {
        return;
    }
    channelInfo->recvPri = provider.ConsumeIntegral<int32_t>();
    channelInfo->recvPriSet = provider.ConsumeBool();
}

static int32_t onChannelOpened(int32_t sessionId, int32_t channelId, int32_t result)
{
    return SOFTBUS_OK;
}

static void onDataReceived(int32_t channelId, const char *data, uint32_t dataLen)
{
}

static void onChannelStatusChanged(int32_t channelId, int32_t state)
{
}

static BrProxyChannelInfo g_channelInfo = {
    .peerBRMacAddr = "F0:FA:C7:13:56:BC",
    .peerBRUuid = "0000FEEA-0000-1000-8000-00805F9B34FB",
    .recvPri = 1,
    .recvPriSet = true,
};

static IBrProxyListener g_listener = {
    .onChannelOpened = onChannelOpened,
    .onDataReceived = onDataReceived,
    .onChannelStatusChanged = onChannelStatusChanged,
};

void OpenBrProxyTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    BrProxyChannelInfo channelInfo;
    IBrProxyListener listener = {
        .onChannelOpened = onChannelOpened,
        .onDataReceived = onDataReceived,
        .onChannelStatusChanged = onChannelStatusChanged,
    };
    (void)memset_s(&channelInfo, sizeof(BrProxyChannelInfo), 0, sizeof(BrProxyChannelInfo));
    FillBrProxyChannelInfo(provider, &channelInfo);

    (void)OpenBrProxy(channelId, &channelInfo, &listener);
    (void)OpenBrProxy(channelId, &g_channelInfo, &g_listener);
}

void CloseBrProxyTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)CloseBrProxy(channelId);
}

void SendBrProxyDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    uint32_t dataLen = provider.ConsumeIntegralInRange<uint32_t>(0, BR_PROXY_SEND_MAX_LEN);
    std::string data =  provider.ConsumeRandomLengthString(dataLen);
    char myData[BR_PROXY_SEND_MAX_LEN + 1];
    if (strcpy_s(myData, sizeof(myData), data.c_str()) != 0) {
        return;
    }

    (void)SendBrProxyData(channelId, myData, dataLen);
}

void SetListenerStateTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    bool isEnable = provider.ConsumeBool();
    ListenerType type = static_cast<ListenerType>(provider.ConsumeIntegralInRange<uint32_t>(0, 2));

    (void)SetListenerState(channelId, type, isEnable);
}

void IsProxyChannelEnabledTest(FuzzedDataProvider &provider)
{
    int32_t uid = provider.ConsumeIntegral<int32_t>();

    (void)IsProxyChannelEnabled(uid);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::OpenBrProxyTest(provider);
    OHOS::CloseBrProxyTest(provider);
    OHOS::SendBrProxyDataTest(provider);
    OHOS::SetListenerStateTest(provider);
    OHOS::IsProxyChannelEnabledTest(provider);

    return 0;
}