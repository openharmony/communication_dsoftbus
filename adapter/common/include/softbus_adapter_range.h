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

#ifndef SOFTBUS_ADAPTER_RANGE_H
#define SOFTBUS_ADAPTER_RANGE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SOFTBUS_DEV_IDENTITY_LEN 96
// valid value of power is [-128, 10], 11 is considered to be illegal.
#define SOFTBUS_ILLEGAL_BLE_POWER 11

typedef struct {
    int32_t rssi;
    int8_t power;
    char identity[SOFTBUS_DEV_IDENTITY_LEN];
} SoftBusRangeParam;

int SoftBusBleRange(SoftBusRangeParam *param, int32_t *range);
int SoftBusGetBlePower(int8_t *power);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_ADAPTER_RANGE_H */