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

#ifndef TRANS_AUTH_LANE_PENDING_CTL_H
#define TRANS_AUTH_LANE_PENDING_CTL_H

#include "trans_lane_pending_ctl.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    bool bSucc;
    bool isFinished;
    bool accountInfo;
    char *sessionName;
    int32_t errCode;
    uint32_t laneReqId;
    int32_t channelId;
    ListNode node;
    LaneConnInfo connInfo;
} TransAuthWithParaNode;

int32_t TransAuthWithParaReqLanePendingInit(void);
void TransAuthWithParaReqLanePendingDeinit(void);
int32_t TransAuthWithParaAddLaneReqToList(uint32_t laneReqId, const char *sessionName,
    bool accountInfo, int32_t channelId);
int32_t TransAuthWithParaDelLaneReqById(uint32_t laneReqId);
int32_t TransUpdateAuthWithParaLaneConnInfo(uint32_t laneHandle, bool bSucc, const LaneConnInfo *connInfo,
    int32_t errCode);
int32_t TransAuthWithParaGetLaneReqByLaneReqId(uint32_t laneReqId, TransAuthWithParaNode *paraNode);


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
