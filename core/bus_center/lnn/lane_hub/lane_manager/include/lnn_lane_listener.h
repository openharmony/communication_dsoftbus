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

#ifndef LNN_LANE_LISTENER_H
#define LNN_LANE_LISTENER_H

#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t UnRegisterLaneListener(LaneType type);
int32_t RegisterLaneListener(LaneType type, const LaneStatusListener *listener);
int32_t AddLaneBusinessInfoItem(LaneType laneType, uint64_t laneId);
int32_t DelLaneBusinessInfoItem(LaneType laneType, uint64_t laneId);
int32_t InitLaneListener(void);
void DeinitLaneListener(void);
int32_t LaneLinkupNotify(const char *peerUdid, const LaneLinkInfo *laneLinkInfo);
int32_t LaneLinkdownNotify(const char *peerUdid, const LaneLinkInfo *laneLinkInfo);
int32_t UpdateLaneBusinessInfoItem(uint64_t oldLaneId, uint64_t newLaneId);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_LISTENER_H
