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

#ifndef LNN_LANE_GUIDE_LINK_H
#define LNN_LANE_GUIDE_LINK_H

#include <stdint.h>
#

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GUIDE_LINK_ENHANCE_P2P = 1, // auth
    GUIDE_LINK_P2P, // auth
    GUIDE_LINK_WIFI, // auth
    GUIDE_LINK_BLE_TRIGGER, // trigger
    GUIDE_LINK_BLE_DIRECT, // proxy
    GUIDE_LINK_BR, // auth
    GUIDE_LINK_BUTT,
} LaneGuideLinkType;

typedef enum {
    BLE_TRIGGER = 1,
    TRIGGER_TYPE_BUTT = 0xFF,
} TriggerType;

typedef struct {
    LaneGuideLinkType guideType;
    union {
        AuthHandle authGuideInfo;
        int32_t proxyChannel;
        TriggerType triggerGuideInfo;
    } guideInfo;
} LaneGuideLinkInfo;

typedef struct {
    void (*onGuideLinkSuccess)(int32_t requestId, const LaneGuideLinkInfo *info);
    void (*onGuideLinkFail)(int32_t requestId, int32_t errCode);
} LaneGuideLinkListener;

int32_t GetGuideLinkRequestId(void);
int32_t OpenPreferGuideLink(int32_t requestId, const char *networkId,
    const LaneGuideLinkListener *listener);
int32_t OpenRetryGuideLink(int32_t requestId, const char *networkId,
    LaneGuideLinkType *usedGuideLink, const LaneGuideLinkListener *listener);
int32_t CloseGuideLink(int32_t requestId, const LaneGuideLinkInfo *linkInfo);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_GUIDE_LINK_H