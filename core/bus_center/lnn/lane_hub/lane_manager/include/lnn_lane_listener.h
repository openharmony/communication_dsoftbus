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
    char peerIp[IP_LEN];
    LaneType laneType;
} LaneTypeInfo;

typedef struct {
    char peerUuid[UUID_BUF_LEN];
    uint32_t laneId;
    LaneLinkType type;
    enum WifiDirectRole role;
} LaneStatusListenerInfo;

typedef struct {
    void (*onLaneOnLine)(LaneStatusListenerInfo *laneStatusListenerInfo);
    void (*onLaneOffLine)(LaneStatusListenerInfo *laneStatusListenerInfo);
    void (*onLaneStateChange)(LaneStatusListenerInfo *laneStatusListenerInfo);
} LaneStatusListener;

typedef struct {
    ListNode node;
    LaneStatusListener laneStatusListen;
    LaneType type; 
} LaneListenerInfo;

int32_t UnRegisterLaneListener(const LaneType type);
int32_t registerLaneListener(const LaneType type, const LaneStatusListener *listener);

int32_t FindLaneListenerInfoByLaneType(const LaneType type, LaneListenerInfo *outLaneListener);
int32_t CreateLaneTypeInfoByLaneId(const uint32_t laneId, const LaneLinkInfo *linkInfo);
int32_t DelLaneTypeInfoItem(const char *peerIp);
int32_t FindLaneTypeInfoByPeerIp(const char *peerIp, LaneTypeInfo *laneTypeInfo);
int32_t InitLaneListener(void);
int32_t LnnReqLinkListener(void);

#ifdef __cplusplus
}
#endif
#endif
