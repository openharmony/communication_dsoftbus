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

#ifndef LNN_SELECT_RULE_H
#define LNN_SELECT_RULE_H

#include "lnn_lane_interface.h"
#include "lnn_lane_select.h"
#include "lnn_select_rule_struct.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t UpdateP2pAvailability(const char *peerUdid, bool isSupportP2p);
int32_t GetWlanLinkedFrequency(void);
LinkAttribute *GetLinkAttrByLinkType(LaneLinkType linkType);
int32_t DecideAvailableLane(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList);
int32_t DecideDefaultLink(const char *networkId, LaneTransType transType, LaneLinkType *resList, uint32_t *resNum);
int32_t DecideCustomLink(const char *networkId, CustomQos customQos, LaneLinkType *resList, uint32_t *resNum);
int32_t FinalDecideLinkType(const char *networkId, LaneLinkType *linkList,
    uint32_t listNum, LanePreferredLinkList *recommendList);
int32_t LaneCheckLinkValid(const char *networkId, LaneLinkType linkType, LaneTransType transType);
int32_t DecideReuseLane(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList);
bool IsEnhancedWifiDirectSupported(const char *networkId);
int32_t InitLaneSelectRule(void);
void DeinitLaneSelectRule(void);
int32_t GetAllSupportReuseBandWidth(const char *peerNetworkId, LaneTransType transType,
    uint32_t **supportBw, uint8_t *bwCnt);
int32_t GetSupportBandWidth(const char *peerNetworkId, LaneTransType transType, uint32_t *supportBw);

#ifdef __cplusplus
}
#endif
#endif // LNN_SELECT_RULE_H