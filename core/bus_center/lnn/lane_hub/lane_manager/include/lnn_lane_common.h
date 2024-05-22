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

#ifndef LNN_LANE_COMMON_H
#define LNN_LANE_COMMON_H

#include "lnn_map.h"
#include "lnn_lane_link.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LaneInfoProcess(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile);
int32_t LnnCreateData(Map *map, uint32_t key, const void *value, uint32_t valueSize);
void *LnnReadData(const Map *map, uint32_t key);
void LnnDeleteData(Map *map, uint32_t key);
uint64_t LnnGetSysTimeMs(void);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_COMMON_H