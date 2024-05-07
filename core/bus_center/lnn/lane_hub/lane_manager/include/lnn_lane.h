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

#ifndef LNN_LANE_H
#define LNN_LANE_H

#include <stdint.h>
#include "lnn_lane_def.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LANE_REQ_ID_NUM 4096
#define MAX_LANE_ID_NUM 1024
#define NET_IF_NAME_MAX_LEN 16

typedef struct {
    void (*OnLaneIdEnabled)(uint64_t laneId, uint32_t laneProfileId);
    void (*OnLaneIdDisabled)(uint64_t laneId, uint32_t laneProfileId);
} ILaneIdStateListener;

void RegisterLaneIdListener(const ILaneIdStateListener *listener);
void UnregisterLaneIdListener(const ILaneIdStateListener *listener);
int32_t InitLane(void);
void DeinitLane(void);
void FreeLaneReqId(uint32_t laneReqId);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_H