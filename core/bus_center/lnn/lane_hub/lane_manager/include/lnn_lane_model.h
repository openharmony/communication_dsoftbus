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

#ifndef LNN_LANE_MODEL_H
#define LNN_LANE_MODEL_H

#include "lnn_lane_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t linkType  : 6; /* LaneLinkType */
    uint32_t transType : 4;
    uint32_t priority  : 4;
    uint32_t reserved  : 18;
} LaneGenerateParam;

int32_t InitLaneModel(void);
void DeinitLaneModel(void);
uint32_t GenerateLaneProfileId(const LaneGenerateParam *param);
int32_t GetLaneProfile(uint32_t profileId, LaneProfile *profile);
int32_t GetLaneIdList(uint32_t profileId, uint64_t **laneIdList, uint32_t *listNum);
uint32_t GetActiveProfileNum(void);
int32_t BindLaneIdToProfile(uint64_t laneId, LaneProfile *profile);
void UnbindLaneIdFromProfile(uint64_t laneId, uint32_t profileId);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_MODEL_H