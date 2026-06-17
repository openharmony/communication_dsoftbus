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

#ifndef LNN_TRANS_FREE_LANE_H
#define LNN_TRANS_FREE_LANE_H

#include "lnn_lane_link.h"
#include "message_handler.h"

#ifdef __cplusplus
extern "C" {
#endif

void NotifyFreeLaneResult(uint32_t laneReqId, int32_t errCode);
void HandleDelayDestroyLink(SoftBusMessage *msg);
void HandleNotifyFreeLaneResult(SoftBusMessage *msg);
int32_t FreeLane(uint32_t laneReqId);
void FreeUnusedLink(uint32_t laneReqId, const LaneLinkInfo *linkInfo);
void ReleaseUndeliverableLink(uint32_t laneReqId, uint64_t laneId);

#ifdef __cplusplus
}
#endif
#endif // LNN_TRANS_FREE_LANE_H
