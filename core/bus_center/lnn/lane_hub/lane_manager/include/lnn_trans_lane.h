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
#include "lnn_lane_link.h"
#include "lnn_lane_listener.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    TransOption info;
    ILaneListener listener;
} ExtraReqInfo;

typedef struct {
    ListNode node;
    uint32_t laneReqId;
    uint64_t laneId;
    LaneAllocInfo allocInfo;
    LaneAllocListener listener;
    bool isWithQos;
    bool isCanceled;
    bool isNotified;
    ExtraReqInfo extraInfo;
} TransReqInfo;

LaneInterface *TransLaneGetInstance(void);
int32_t GetTransReqInfoByLaneReqId(uint32_t laneReqId, TransReqInfo *reqInfo);
int32_t PostDelayDestroyMessage(uint32_t laneReqId, uint64_t laneId, uint64_t delayMillis);
int32_t PostDetectTimeoutMessage(uint32_t detectId, uint64_t delayMillis);
void RemoveDetectTimeoutMessage(uint32_t detectId);
int32_t PostLaneStateChangeMessage(LaneState state, const char *peerUdid, const LaneLinkInfo *laneLinkInfo);

#ifdef __cplusplus
}
#endif
#endif // LNN_TRANS_LANE_H
