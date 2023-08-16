/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef LNN_LANE_INFO_H
#define LNN_LANE_INFO_H

#include <stdint.h>

#include "session.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "lnn_lane_def.h"
#ifdef __cplusplus
extern "C" {
#endif

#define LNN_REQUEST_MAX_LANE_NUM 1
#define MAX_LANE_QUALITY_SCORE 100
#define PASSING_LANE_QUALITY_SCORE 80
#define THRESHOLD_LANE_QUALITY_SCORE 60
#define LANE_COUNT_THRESHOLD 5
#define LNN_LANE_P2P_MAX_NUM 4

typedef struct {
    bool isSupportUdp;
    bool isProxy;
    ConnectionAddr conOption;
    LnnLaneP2pInfo *p2pInfo;
} LnnLaneInfo;

typedef void (*LnnLaneMonitorCallback)(int32_t laneId, int32_t socre);

typedef struct {
    uint32_t linkTypeNum;
    LinkType linkType[LINK_TYPE_MAX];
} LnnPreferredLinkList;

ConnectionAddrType LnnGetLaneType(int32_t laneId);
void LnnReleaseLane(int32_t laneId);
bool LnnUpdateLaneRemoteInfo(const char *netWorkId, LnnLaneLinkType type, bool mode);
int32_t LnnLanesInit(void);
void LnnSetLaneSupportUdp(const char *netWorkId, int32_t laneId, bool isSupport);
int32_t LnnRegisterLaneMonitor(LnnLaneMonitorCallback callback);
int32_t LnnGetLaneScore(int32_t laneId);
void TriggerLaneMonitor(void);
void LnnLaneSetNetworkIdAndPid(int32_t laneId, const char *networkId, int32_t pid);
int32_t LnnUpdateLaneP2pInfo(const LnnLaneP2pInfo *info);

#ifdef __cplusplus
}
#endif
#endif /* LNN_LANE_INFO_H */