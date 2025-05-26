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

#ifndef LNN_TRANS_LANE_STRUCT_H
#define LNN_TRANS_LANE_STRUCT_H

#include "common_list.h"
#include "lnn_lane_interface_struct.h"
#include "stdint.h"
#include "stdbool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool isSupportIpv6;
    uint32_t actionAddr;
    TransOption info;
    ILaneListener listener;
} ExtraReqInfo;

typedef struct {
    bool isWithQos;
    bool isCanceled;
    bool isNotified;
    bool notifyFree;
    bool hasNotifiedFree;
    uint32_t laneReqId;
    LaneAllocInfo allocInfo;
    uint64_t laneId;
    ListNode node;
    LaneAllocListener listener;
    ExtraReqInfo extraInfo;
} TransReqInfo;

#ifdef __cplusplus
}
#endif
#endif // LNN_TRANS_LANE_STRUCT_H
