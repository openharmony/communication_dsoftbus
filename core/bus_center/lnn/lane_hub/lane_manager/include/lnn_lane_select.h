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

#ifndef LNN_LANE_SELECT_H
#define LNN_LANE_SELECT_H

#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    LaneTransType transType;
    QosInfo qosRequire;
    LanePreferredLinkList list;
    uint64_t allocedLaneId;
    //OldInfo
    uint32_t expectedBw;
} LaneSelectParam;


int32_t SelectLane(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList, uint32_t *listNum);

int32_t SelectExpectLanesByQos(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList);

int32_t SelectAuthLane(const char *networkId, LanePreferredLinkList *request, LanePreferredLinkList *recommendList);

int32_t GetErrCodeOfLink(const char *networkId, LaneLinkType linkType);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_SELECT_H