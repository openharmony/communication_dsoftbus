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

#ifndef LNN_FEATURE_CAPABILITY_H
#define LNN_FEATURE_CAPABILITY_H

#include "softbus_bus_center.h"
#include "lnn_feature_capability_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

uint64_t LnnGetFeatureCapabilty(void);
bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit);
int32_t LnnSetFeatureCapability(uint64_t *feature, FeatureCapability capaBit);
int32_t LnnClearFeatureCapability(uint64_t *feature, FeatureCapability capaBit);

#ifdef __cplusplus
}
#endif

#endif // LNN_FEATURE_CAPABILITY_H
