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

#include "data/interface_manager.h"
#include "p2p_adapter_mock.h"
#include "p2p_entity_mock.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"
#include "wifi_direct_p2p_adapter.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
namespace OHOS {
static bool g_alreadyInit = false;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static constexpr int WAIT_CLEAR_TIME = 500;
static constexpr int DEFAULT_CHANNEL = 36;

void SetUpEnvironment()
{
    pthread_mutex_lock(&g_lock);
    if (!g_alreadyInit) {
        SoftBus::P2pAdapterMock adapterMock;
        SoftBus::P2pEntityMock entityMock;
        EXPECT_CALL(adapterMock, GetRecommendChannel).WillOnce(Return(DEFAULT_CHANNEL));
        EXPECT_CALL(adapterMock, GetCoexConflictCode).WillOnce(Return(SOFTBUS_OK));
        EXPECT_CALL(adapterMock, GetGroupConfig(_)).WillOnce([](std::string &groupConfigString) {
            groupConfigString = "test\nFF:FF:FF:FF:FF:FF\ntest\n5180";
            return SOFTBUS_OK;
        });
        EXPECT_CALL(adapterMock, GetIpAddress).WillOnce(Return(SOFTBUS_OK));
        SoftBus::P2pOperationResult createResult{};
        createResult.errorCode_ = SOFTBUS_OK;
        EXPECT_CALL(entityMock, CreateGroup).WillOnce(Return(createResult));
        g_alreadyInit = true;
    }
    pthread_mutex_unlock(&g_lock);
}

void OnP2pStateChange(int32_t retCode)
{
    (void)retCode;
}

void CreateGroupOwnerFuzzTest(FuzzedDataProvider &provider, size_t size)
{
    struct GroupOwnerConfig config = {
        .frequency = provider.ConsumeIntegral<int32_t>(),
    };
    std::string pkgName =  provider.ConsumeBytesAsString(size);
    struct GroupOwnerResult result;
    SoftBus::WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner(
        pkgName.c_str(), &config, &result, OnP2pStateChange);
    SoftBusSleepMs(WAIT_CLEAR_TIME);
}

void DestroyGroupOwnerFuzzTest(FuzzedDataProvider &provider, size_t size)
{
    std::string pkgName =  provider.ConsumeBytesAsString(size);
    SoftBus::WifiDirectP2pAdapter::GetInstance()->ConnDestroyGoOwner(pkgName.c_str());
    SoftBusSleepMs(WAIT_CLEAR_TIME);
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
    OHOS::CreateGroupOwnerFuzzTest(provider, size);
    OHOS::DestroyGroupOwnerFuzzTest(provider, size);
    return SOFTBUS_OK;
}