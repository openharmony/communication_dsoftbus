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

#include "softbus_adapter_crypto.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define MAX_WEIGHT_VALUE 1000

int32_t LnnGetLocalWeight(void)
{
    static int32_t weight;
    static bool isGenWeight = false;
    uint8_t randVal = 0;

    if (isGenWeight) {
        return weight;
    }
    if (SoftBusGenerateRandomArray(&randVal, sizeof(randVal)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate random weight fail");
        return randVal;
    }
    weight = (randVal * MAX_WEIGHT_VALUE) / UINT8_MAX;
    isGenWeight = true;
    return weight;
}

int32_t LnnCompareNodeWeight(int32_t weight1, const char *masterUdid1,
    int32_t weight2, const char *masterUdid2)
{
    if (weight1 != weight2) {
        return weight1 - weight2;
    }
    return strcmp(masterUdid1, masterUdid2);
}