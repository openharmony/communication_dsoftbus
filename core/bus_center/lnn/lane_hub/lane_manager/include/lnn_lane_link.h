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

#ifndef LNN_LANE_LINK_H
#define LNN_LANE_LINK_H

#include <stdint.h>
#include "lnn_lane_def.h"
#include "lnn_lane_link_conflict.h"
#include "lnn_lane_link_struct.h"
#include "bus_center_info_key.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitLaneLink(void);
void DeinitLaneLink(void);
int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb);
int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type);

void LaneDeleteP2pAddress(const char *networkId, bool isDestroy);
void LaneAddP2pAddress(const char *networkId, const char *ipAddr, uint16_t port);

void LaneAddP2pAddressByIp(const char *ipAddr, uint16_t port);
void LaneUpdateP2pAddressByIp(const char *ipAddr, const char *networkId);
void DetectEnableWifiDirectApply(void);
void DetectDisableWifiDirectApply(void);

int32_t FindLaneResourceByLinkAddr(const LaneLinkInfo *info, LaneResource *resource);
int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource);
int32_t CheckLaneResourceNumByLinkType(const char *peerUdid, LaneLinkType type, int32_t *laneNum);
int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide);
int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide);
int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resource);
int32_t UpdateLaneResourceLaneId(uint64_t oldLaneId, uint64_t newLaneId, const char *peerUdid);
uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType);
int32_t ClearLaneResourceByLaneId(uint64_t laneId);
int32_t GetAllDevIdWithLinkType(LaneLinkType type, char **devIdList, uint8_t *devIdCnt);
int32_t QueryOtherLaneResource(const DevIdentifyInfo *inputInfo, LaneLinkType type);
bool FindLaneResourceByDevInfo(const DevIdentifyInfo *inputInfo, LaneLinkType type);
int32_t GetAllLinkWithDevId(const char *peerUdid, LaneLinkType **linkList, uint8_t *linkCnt);
bool CheckLaneLinkExistByType(LaneLinkType linkType);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_LINK_H