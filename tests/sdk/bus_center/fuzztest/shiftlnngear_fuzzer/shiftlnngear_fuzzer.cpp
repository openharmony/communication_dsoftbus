/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <securec.h>

#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
    static const int32_t MAX_SIZE_WAKEUP_MODE = 2;
    static const int32_t MAX_SIZE_GEARMODE_MODE = 3;
    static const int32_t GEARMODE_MODE_TYPE_0 = 0;
    static const int32_t GEARMODE_MODE_TYPE_1 = 1;
    static const int32_t GEARMODE_MODE_TYPE_2 = 2;
    static char *callerId = nullptr;
    static constexpr char *networkId = nullptr;
    static constexpr char TEST_PKG_NAME1[] = "com.softbus.test";
    static GearMode g_mode;

    static void GenRanDiscInfo(const uint8_t* data, size_t size)
    {
        switch (size % MAX_SIZE_GEARMODE_MODE) {
            case GEARMODE_MODE_TYPE_0:
                g_mode.cycle = HIGH_FREQ_CYCLE;
                break;
            case GEARMODE_MODE_TYPE_1:
                g_mode.cycle = MID_FREQ_CYCLE;
                break;
            case GEARMODE_MODE_TYPE_2:
                g_mode.cycle = LOW_FREQ_CYCLE;
                break;
            default:
                break;
        }
        switch (size % MAX_SIZE_GEARMODE_MODE) {
            case GEARMODE_MODE_TYPE_0:
                g_mode.duration = DEFAULT_DURATION;
                break;
            case GEARMODE_MODE_TYPE_1:
                g_mode.duration = NORMAL_DURATION;
                break;
            case GEARMODE_MODE_TYPE_2:
                g_mode.duration = LONG_DURATION;
                break;
            default:
                break;
        }
        g_mode.wakeupFlag = (size % MAX_SIZE_WAKEUP_MODE) ? true : false;
        size_t callerIdLen = size % CALLER_ID_MAX_LEN + 1;
        callerId = static_cast<char *>(malloc(callerIdLen));
        if (callerId == nullptr) {
            return;
        }
        int32_t ret = strncpy_s(callerId,
                                callerIdLen, (const char *)data, size >= callerIdLen ? callerIdLen - 1 : size);
        if (ret != EOK) {
            return;
        }
    };

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return true;
        }
        GenRanDiscInfo(data, size);
        ShiftLNNGear(TEST_PKG_NAME1, callerId, networkId, &g_mode);
        if (callerId != nullptr) {
            free(callerId);
            callerId = nullptr;
        }
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    SetAccessTokenPermission("shiftLnnGearFuzzTest");
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
