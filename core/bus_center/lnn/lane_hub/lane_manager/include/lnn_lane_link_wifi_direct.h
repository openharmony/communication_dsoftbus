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

#ifndef LNN_LANE_LINK_WIFI_DIRECT_H
#define LNN_LANE_LINK_WIFI_DIRECT_H

#include "common_list.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link_conflict.h"
#include "softbus_common.h"
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FORCE_DOWN_LANE = 0,
    FORCE_DOWN_TRANS,
    FORCE_DOWN_BUTT,
} ForceDownType;

typedef struct {
    char forceDownDevId[NETWORK_ID_BUF_LEN];
    uint32_t p2pRequestId;
    uint32_t forceDownReqId;
    LaneLinkType forceDownLink;
    uint32_t authRequestId;
    ForceDownType downType;
    AuthHandle authHandle;
    SoftBusCond cond;
    ListNode node;
} ForceDownInfo;

int32_t InitLinkWifiDirect(void);
void DeInitLinkWifiDirect(void);
int32_t HandleForceDownWifiDirect(const char *networkId, LinkConflictType conflictType, uint32_t p2pRequestId);
int32_t HandleForceDownWifiDirectTrans(const char *udidhashStr, LinkConflictType conflictType);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_LINK_WIFI_DIRECT_H
