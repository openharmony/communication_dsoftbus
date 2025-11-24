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

#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <pthread.h>

#include "conn_log.h"
#include "proxy_negotiate_channel.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
namespace OHOS {
static ITransProxyPipelineListener g_proxyListener = {};
static bool g_alreadyInit = false;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static constexpr int WAIT_CLEAE_TIME = 500;
static int g_maxCoverageRunTime = 1;

void SetUpEnvironment(OHOS::SoftBus::WifiDirectInterfaceMock &mock)
{
    pthread_mutex_lock(&g_lock);
    if (!g_alreadyInit) {
        EXPECT_CALL(mock, TransProxyPipelineRegisterListener(_, _))
            .WillRepeatedly([](TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener) {
                g_proxyListener = *const_cast<ITransProxyPipelineListener *>(listener);
                return SOFTBUS_OK;
            });
        EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
        EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(mock, LnnGetLocalStrInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
        OHOS::SoftBus::CoCProxyNegotiateChannel::Init();
        g_alreadyInit = true;
    }
    pthread_mutex_unlock(&g_lock);
}

void DataReceivedFuzzTest(FuzzedDataProvider &provider, const uint8_t *data, size_t size)
{
    auto channelId = provider.ConsumeIntegral<int32_t>();
    auto *dataStr = reinterpret_cast<char *>(const_cast<uint8_t *>(data));
    g_proxyListener.onDataReceived(channelId, dataStr, size);
    SoftBusSleepMs(WAIT_CLEAE_TIME);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr || size < sizeof(int32_t)) {
        CONN_LOGE(CONN_TEST, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (OHOS::g_maxCoverageRunTime == 1) {
        testing::InitGoogleTest();
        auto result = RUN_ALL_TESTS();
        OHOS::g_maxCoverageRunTime += 1;
        CONN_LOGI(CONN_ACTION, "result=%{public}d", result);
    }

    OHOS::SoftBus::WifiDirectInterfaceMock mock;
    OHOS::SetUpEnvironment(mock);
    FuzzedDataProvider provider(data, size);
    OHOS::DataReceivedFuzzTest(provider, data, size);
    return SOFTBUS_OK;
}