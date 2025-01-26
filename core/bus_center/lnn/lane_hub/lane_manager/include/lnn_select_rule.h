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

#include "softbus_common.h"
#include "lnn_lane_select.h"
#include "lnn_lane_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UNACCEPT_SCORE 20

typedef enum {
    HIGH_BAND_WIDTH = 0,
    MIDDLE_HIGH_BAND_WIDTH,
    MIDDLE_LOW_BAND_WIDTH,
    LOW_BAND_WIDTH,
    BW_TYPE_BUTT,
} BandWidthType;

typedef enum {
    CUSTOM_QOS_MESH = 0,
    CUSTOM_QOS_DB,
    CUSTOM_QOS_RTT,
    CUSTOM_QOS_BUTT,
} CustomQos;

typedef struct {
    bool available;
    int32_t (*linkCapCheck)(const char *networkId);
    int32_t (*getLinkScore)(const char *networkId, uint32_t expectedBw);
} LinkAttribute;

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

#ifdef __cplusplus
}
#endif
#endif // LNN_SELECT_RULE_H