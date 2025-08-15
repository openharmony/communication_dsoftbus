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
#include <pthread.h>

#include "auth_negotiate_channel.h"
#include "conn_log.h"
#include "softbus_common.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
namespace OHOS {
static AuthTransListener g_authListener = {};
static bool g_alreadyInit = false;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static OHOS::SoftBus::WifiDirectInterfaceMock mock;
static constexpr int WAIT_CLEAE_TIME = 500;

void SetUpEnvironment()
{
    pthread_mutex_lock(&g_lock);
    if (!g_alreadyInit) {
        EXPECT_CALL(mock, RegAuthTransListener(_, _))
            .WillRepeatedly([](int32_t module, const AuthTransListener *listener) {
                g_authListener = *const_cast<AuthTransListener *>(listener);
                return SOFTBUS_OK;
            });
        EXPECT_CALL(mock, LnnGetFeatureCapabilty).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(mock, IsFeatureSupport).WillRepeatedly(Return(true));
        EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline).WillRepeatedly(Return(true));
        EXPECT_CALL(mock, AuthPostTransData).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(mock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
        OHOS::SoftBus::AuthNegotiateChannel::Init();
        g_alreadyInit = true;
    }
    pthread_mutex_unlock(&g_lock);
}

void DataReceivedFuzzTest(FuzzedDataProvider &provider, const uint8_t *data, size_t size)
{
    AuthHandle handle = { 0 };
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();
    AuthTransData authData = {
        .module = provider.ConsumeIntegral<int32_t>(),
        .flag = provider.ConsumeIntegral<int32_t>(),
        .seq = provider.ConsumeIntegral<int64_t>(),
        .len = static_cast<uint32_t>(size),
        .data = data,
    };

    g_authListener.onDataReceived(handle, &authData);
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
    OHOS::SetUpEnvironment();
    FuzzedDataProvider provider(data, size);
    OHOS::DataReceivedFuzzTest(provider, data, size);
    return SOFTBUS_OK;
}