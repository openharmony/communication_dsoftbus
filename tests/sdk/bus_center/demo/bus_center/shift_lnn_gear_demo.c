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
 * @file shift_lnn_gear_demo.c
 *
 * @brief Provides the sample code for modify heartbeat parameters and trigger a temporary heartbeat.
 *
 * @since 1.0
 * @version 1.0
 */

#include <stdint.h>

#include "softbus_bus_center.h"
#include "softbus_common.h"

int32_t main(void)
{
    const char *pkgName = "pkgName.demo";
    const char *callerId = "1";
    const char *networkId = "765432101234567898765432123456789876543210123654789876543210123";
    GearMode mode = { .cycle = MID_FREQ_CYCLE, .duration = DEFAULT_DURATION, .wakeupFlag = false };
    // Modify heartbeat parameters and trigger a temporary heartbeat.
    if (ShiftLNNGear(pkgName, callerId, networkId, &mode) != 0) {
        printf("[demo]ShiftLNNGear fail");
        return -1;
    }
    return 0;
}
