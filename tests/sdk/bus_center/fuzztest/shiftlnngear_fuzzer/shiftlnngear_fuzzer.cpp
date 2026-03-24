/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "shiftlnngear_fuzzer.h"

#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

using namespace std;
namespace {
class TestEnv {
public:
    TestEnv()
    {
        isInited_ = true;
    }
    ~TestEnv()
    {
        isInited_ = false;
    }

    bool IsEnvInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_ = false;
};
} // namespace

namespace OHOS {
static char *callerId = nullptr;
static constexpr char *networkId = nullptr;
static constexpr char TEST_PKG_NAME1[] = "com.softbus.test";
static GearMode g_mode;

static void GenRanDiscInfo(FuzzedDataProvider &provider)
{
    g_mode.cycle = (ModeCycle)provider.ConsumeIntegralInRange<uint32_t>(HIGH_FREQ_CYCLE, DEFAULT_FREQ_CYCLE);
    g_mode.duration = (ModeDuration)provider.ConsumeIntegralInRange<uint32_t>(DEFAULT_DURATION, LONG_DURATION);
    g_mode.wakeupFlag = provider.ConsumeBool();
    uint32_t callerIdLen = provider.ConsumeIntegralInRange<uint32_t>(1, CALLER_ID_MAX_LEN);
    std::string providerData = provider.ConsumeBytesAsString(callerIdLen);
    callerId = static_cast<char *>(SoftBusCalloc(callerIdLen));
    if (callerId == nullptr) {
        return;
    }
    int32_t ret = strncpy_s(callerId, callerIdLen, providerData.data(),
        providerData.size() >= callerIdLen ? callerIdLen - 1 : providerData.size());
    callerId[callerIdLen - 1] = '\0';
    if (ret != EOK) {
        SoftBusFree(callerId);
        callerId = nullptr;
    }
};

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider &provider)
{
    GenRanDiscInfo(provider);
    ShiftLNNGear(TEST_PKG_NAME1, callerId, networkId, &g_mode);
    if (callerId != nullptr) {
        SoftBusFree(callerId);
        callerId = nullptr;
    }
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    static TestEnv env;
    if (!env.IsEnvInited()) {
        return -1;
    }
    /* Run your code on data */
    SetAccessTokenPermission("shiftLnnGearFuzzTest");
    FuzzedDataProvider provider(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(provider);
    return 0;
}
