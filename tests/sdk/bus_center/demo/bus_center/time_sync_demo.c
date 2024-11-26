/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/**
 * @file time_sync_demo.c
 *
 * @brief Provides the sample code for start the time synchronize with specific target node.
 *
 * @since 1.0
 * @version 1.0
 */

#include <stdint.h>

#include "softbus_bus_center.h"
#include "softbus_common.h"

static void onTimeSyncDone(const TimeSyncResultInfo *info, int32_t retCode)
{
    if (retCode != 0) {
        printf("[demo]onTimeSyncDone failed\n");
    }
}

static ITimeSyncCb g_timeSyncCB = {
    .onTimeSyncResult = onTimeSyncDone,
};

int32_t main(void)
{
    const char *pkgName = "pkgName.demo";
    const char *networkId = "765432101234567898765432123456789876543210123654789876543210123";
    TimeSyncAccuracy accuracy = SUPER_HIGH_ACCURACY;
    TimeSyncPeriod period = NORMAL_PERIOD;

    /*
     * 1. Device A calls StartTimeSync() to start the time synchronize with specific target node.
     */
    int32_t ret = StartTimeSync(pkgName, networkId, accuracy, period, &g_timeSyncCB);
    if (ret != 0) {
        printf("[demo]StartTimeSync fail");
        return ret;
    }
    /*
     * 2. When finish StartTimeSync, device A return the result via onTimeSyncDone().
     */

    /*
     * 3. If StartTimeSync() return ok, device A calls StopTimeSync() to stop the time synchronize.
     */
    ret = StopTimeSync(pkgName, networkId);
    if (ret != 0) {
        printf("[demo]StopTimeSync fail");
        return ret;
    }
    return ret;
}
