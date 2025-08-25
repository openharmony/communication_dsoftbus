/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef LNN_LANE_INTERFACE_H
#define LNN_LANE_INTERFACE_H

#include <stdint.h>
#include "lnn_lane_interface_struct.h"
#include "session.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
extern "C" {
#endif

LnnLaneManager* GetLaneManager(void);

int32_t LnnQueryLaneResource(const LaneQueryInfo *queryInfo, const QosInfo *qosInfo);
uint32_t ApplyLaneReqId(LaneType type);
int32_t LnnRequestLane(uint32_t laneReqId, const LaneRequestOption *request, const ILaneListener *listener);
int32_t LnnFreeLane(uint32_t laneReqId);
int32_t GetMacInfoByLaneId(uint64_t laneId, LnnMacInfo *macInfo);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_INTERFACE_H