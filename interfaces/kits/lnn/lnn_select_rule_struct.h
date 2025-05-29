/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef LNN_SELECT_RULE_STRUCT_H
#define LNN_SELECT_RULE_STRUCT_H

#include "stdint.h"
#include "stdbool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UNACCEPT_SCORE 20

typedef enum {
    HIGH_BAND_WIDTH = 0,
    MIDDLE_HIGH_BAND_WIDTH,
    MIDDLE_LOW_BAND_WIDTH,
    LOW_BAND_WIDTH,
    BW_TYPE_BUTT,
} BandWidthType;

typedef enum {
    CUSTOM_QOS_MESH = 0,
    CUSTOM_QOS_DB,
    CUSTOM_QOS_RTT,
    CUSTOM_QOS_BUTT,
} CustomQos;

typedef struct {
    bool available;
    int32_t (*linkFeatureCheck)(const char *networkId);
    int32_t (*getLinkScore)(const char *networkId, uint32_t expectedBw);
} LinkAttribute;

#ifdef __cplusplus
}
#endif
#endif // LNN_SELECT_RULE_H