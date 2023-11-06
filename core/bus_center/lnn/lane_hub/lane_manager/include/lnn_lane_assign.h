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

#ifndef LNN_LANE_ASSIGN_H
#define LNN_LANE_ASSIGN_H

#include <stdint.h>
#include "lnn_lane.h"
#include "lnn_lane_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*Init)(const ILaneIdStateListener *listener);
    void (*Deinit)(void);
    int32_t (*AllocLane)(uint32_t laneId, const LaneRequestOption *request, const ILaneListener *listener);
    int32_t (*allocLaneByQos)(uint32_t laneId, const LaneRequestOption *request, const ILaneListener *listener);
    int32_t (*FreeLane)(uint32_t laneId);
} LaneInterface;

#ifdef __cplusplus
}
#endif
#endif