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

#include "softbus_adapter_range.h"
#include <math.h>
#include <stdlib.h>
#include "softbus_adapter_log.h"

#define MOCK_POWER (-17)
#define DB_BASE (10.0)
#define DB_COEFFICIENT (20.0)

int SoftBusBleRange(SoftBusRangeParam *param, int32_t *range)
{
    if (param == NULL || range == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusBleRange param is null.");
        return -1;
    }

    *range = (int32_t)pow(DB_BASE, param->rssi * -1 / DB_COEFFICIENT);
    return 0;
}

int SoftBusGetBlePower(int8_t *power)
{
    if (power == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusGetBlePower param is null.");
        return -1;
    }
    *power = MOCK_POWER;
    return 0;
}