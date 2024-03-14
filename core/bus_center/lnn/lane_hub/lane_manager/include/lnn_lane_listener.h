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
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ListNode node;
    LaneType laneType;
    LaneLinkInfo laneLinkInfo;
    uint32_t ref;
} LaneTypeInfo;

typedef struct {
    uint32_t laneTypeNum;
    LaneTypeInfo laneTypeInfoList[LANE_TYPE_BUTT];
} LaneTypeInfoResult;

typedef struct {
    char peerUdid[UDID_BUF_LEN];
    uint32_t laneId;
    LaneLinkType type;
} LaneStatusInfo;

typedef struct {
    void (*onLaneOnLine)(LaneStatusInfo *laneStatusInfoOn);
    void (*onLaneOffLine)(LaneStatusInfo *laneStatusInfoOff);
    void (*onLaneStateChange)(LaneStatusInfoChange *laneStatusInfoChange);
} LaneStatusListener;

typedef struct {
    ListNode node;
    LaneStatusListener laneStatusListen;
    LaneType type;
} LaneListenerInfo;

int32_t UnRegisterLaneListener(const LaneType type);
int32_t RegisterLaneListener(const LaneType type, const LaneStatusListener *listener);
int32_t AddLaneTypeInfo(const LaneLinkInfo *linkInfo);
int32_t DelLaneTypeInfoItem(uint32_t laneReqId);
int32_t LnnOnWifiDirectDeviceOnLineNotify(const LaneLinkInfo *linkInfo);
int32_t InitLaneListener(void);

#ifdef __cplusplus
}
#endif
#endif
