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

#ifndef LNN_TRANS_LANE_H
#define LNN_TRANS_LANE_H

#include "lnn_lane_assign.h"
#include "lnn_lane_listener.h"
#include "lnn_trans_lane_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

LaneInterface *TransLaneGetInstance(void);
int32_t GetTransReqInfoByLaneReqId(uint32_t laneReqId, TransReqInfo *reqInfo);
int32_t PostDelayDestroyMessage(uint32_t laneReqId, uint64_t laneId, uint64_t delayMillis);
int32_t PostDetectTimeoutMessage(uint32_t detectId, uint64_t delayMillis);
void RemoveDetectTimeoutMessage(uint32_t detectId);
int32_t PostLaneStateChangeMessage(LaneState state, const char *peerUdid, const LaneLinkInfo *laneLinkInfo);
int32_t PostNotifyFreeLaneResult(uint32_t laneReqId, int32_t errCode, uint64_t delayMillis);
void RemoveDelayDestroyMessage(uint64_t laneId);
void DelLogicAndLaneRelationship(uint64_t laneId);
int32_t UpdateReqListLaneId(uint64_t oldLaneId, uint64_t newLaneId);
int32_t UpdateNotifyInfoBylaneReqId(uint32_t laneReqId, bool isNotifyFree);
int32_t HandleLaneQosChange(const LaneLinkInfo *laneLinkInfo);
int32_t UpdateFreeLaneStatus(uint32_t laneReqId);
int32_t DeleteRequestNode(uint32_t laneReqId);
bool CheckVirtualLinkByLaneReqId(uint32_t laneReqId);

#ifdef __cplusplus
}
#endif
#endif // LNN_TRANS_LANE_H
