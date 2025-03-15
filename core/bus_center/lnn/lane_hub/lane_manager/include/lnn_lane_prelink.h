/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef LNN_LANE_PRELINK_H
#define LNN_LANE_PRELINK_H

#include <stdint.h>
#include "softbus_common.h"
#include "common_list.h"

#ifdef __cplusplus
 extern "C" {
#endif

#define RESERVED_LEN 16
#define RAW_MAC_LEN 6
#define CHAR_MAC_LEN 18
#define AUTH_UDID_HASH_LEN 8

typedef struct {
    int32_t txChannel;
    uint8_t p2pMac[RAW_MAC_LEN];
    uint8_t chbaMac[RAW_MAC_LEN];
    uint8_t btMac[RAW_MAC_LEN];
    int32_t linkStatus;
    char shortUdidHash[AUTH_UDID_HASH_LEN];
    char reserved[RESERVED_LEN];
} PreLinkPara;

typedef struct {
    ListNode node;
    uint32_t actionId;
    uint32_t laneReqId;
    uint8_t actionMac[RAW_MAC_LEN];
    char shortUdidHash[AUTH_UDID_HASH_LEN];
} ActionBleConNodeInfo;

int32_t GetConcurrencyPeerUdidByActionId(uint32_t actionId, char *peerUdid);
bool HaveConcurrencyBleGuideChannel(uint32_t actionId);
int32_t InitActionBleConcurrency(void);
void DeinitActionBleConcurrency(void);
int32_t LnnTriggerPreLink(const void *msg);

#ifdef __cplusplus
}
#endif

#endif