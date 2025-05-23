/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef DATA_LEVEL_INNER_H
#define DATA_LEVEL_INNER_H

#include <stdint.h>
#include "ble_range.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    uint16_t dynamicLevel;
    uint16_t staticLevel;
    uint32_t switchLevel;
    uint16_t switchLength;
} DataLevelInfo;

typedef struct {
    RangeMedium medium;
    float distance;
    char networkId[NETWORK_ID_BUF_LEN];
    uint32_t length;
    uint8_t *addition;
} RangeResultInnerInfo;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* DATA_LEVEL_INNER_H */

