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

#ifndef LNN_SELECT_RULE_H
#define LNN_SELECT_RULE_H

#include "softbus_common.h"
#include "lnn_lane_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UNACCEPT_SCORE 20

typedef struct {
    bool available;
    bool (*IsEnable)(const char *networkId);
    int32_t (*GetLinkScore)(const char *networkId, uint32_t expectedBw);
} LinkAttribute;

LinkAttribute *GetLinkAttrByLinkType(LaneLinkType linkType);

#ifdef __cplusplus
}
#endif
#endif