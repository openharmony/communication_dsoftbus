/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_node_weight.h"

#include <string.h>

#include "bus_center_manager.h"
#include "lnn_device_info.h"
#include "lnn_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_error_code.h"

#define MAX_WEIGHT_VALUE        1000
#define BASE_WEIGHT_PHONE_VALUE 2000
#define BASE_WEIGHT_PAD_VALUE   3000
#define BASE_WEIGHT_TV_VALUE    8000
#define BASE_WEIGHT_AUDIO_VALUE 7000
#define BASE_WEIGHT_CAR_VALUE   5000
#define BASE_WEIGHT_PC_VALUE    4000

int32_t LnnGetLocalWeight(void)
{
    static int32_t weight;
    static bool isGenWeight = false;
    uint8_t randVal = 0;

    if (isGenWeight) {
        return weight;
    }
    if (SoftBusGenerateRandomArray(&randVal, sizeof(randVal)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "generate random weight fail");
        return randVal;
    }
    weight = (int32_t)((randVal * MAX_WEIGHT_VALUE) / UINT8_MAX);
    int32_t localDevTypeId = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId) != SOFTBUS_OK) {
        localDevTypeId = 0;
    }
    switch (localDevTypeId) {
        case TYPE_PHONE_ID:
            weight += BASE_WEIGHT_PHONE_VALUE;
            break;
        case TYPE_PAD_ID:
            weight += BASE_WEIGHT_PAD_VALUE;
            break;
        case TYPE_TV_ID:
            weight += BASE_WEIGHT_TV_VALUE;
            break;
        case TYPE_AUDIO_ID:
            weight += BASE_WEIGHT_AUDIO_VALUE;
            break;
        case TYPE_CAR_ID:
            weight += BASE_WEIGHT_CAR_VALUE;
            break;
        case TYPE_PC_ID:
            weight += BASE_WEIGHT_PC_VALUE;
            break;
        default:
            break;
    }
    LNN_LOGD(LNN_BUILDER, "generate local weight=%{public}d", weight);
    isGenWeight = true;
    return weight;
}

int32_t LnnCompareNodeWeight(int32_t weight1, const char *masterUdid1, int32_t weight2,
    const char *masterUdid2)
{
    if (weight1 != weight2) {
        return weight1 - weight2;
    }
    if (masterUdid1 == NULL || masterUdid2 == NULL) {
        LNN_LOGE(LNN_BUILDER, "nullptr");
        return weight1 - weight2;
    }
    return strcmp(masterUdid1, masterUdid2);
}