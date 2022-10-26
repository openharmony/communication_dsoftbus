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

#include "starttimesync_fuzzer.h"
#include <cstddef>
#include <securec.h>
#include "softbus_bus_center.h"
#include "softbus_errcode.h"

namespace OHOS {
    static void OnTimeSyncResult(const TimeSyncResultInfo *info, int32_t retCode)
    {
        (void)info;
        (void)retCode;
    }

    static ITimeSyncCb g_timeSyncCb = {
        .onTimeSyncResult = OnTimeSyncResult,
    };

    bool StartTimeSyncTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return true;
        }

        TimeSyncAccuracy timeAccuracy = SUPER_HIGH_ACCURACY;
        TimeSyncPeriod period = NORMAL_PERIOD;

        StartTimeSync((const char *)data, (const char *)data, timeAccuracy, period, &g_timeSyncCb);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::StartTimeSyncTest(data, size);
    return 0;
}
