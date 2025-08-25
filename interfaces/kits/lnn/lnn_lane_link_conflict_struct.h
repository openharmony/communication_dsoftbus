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

#ifndef LNN_LANE_LINK_CONFLICT_STRUCT_H
#define LNN_LANE_LINK_CONFLICT_STRUCT_H

#include "lnn_lane_interface_struct.h"
#include "softbus_common.h"
#include "softbus_def.h"

#define CONFLICT_DEV_IP_LEN 32
#define CONFLICT_UDIDHASH_STR_LEN 16

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONFLICT_THREE_VAP = 0,
    CONFLICT_ROLE,
    CONFLICT_LINK_NUM_LIMITED,
    CONFLICT_SOFTAP,
    CONFLICT_ILLEGAL,
    CONFLICT_BUTT,
} LinkConflictType;

typedef enum {
    IDENTIFY_TYPE_DEV_ID = 0,
    IDENTIFY_TYPE_UDID_HASH,
    IDENTIFY_TYPE_BUTT,
} DevIdentifyType;

typedef struct {
    DevIdentifyType type;
    union {
        char peerDevId[NETWORK_ID_BUF_LEN];
        char udidHash[CONFLICT_UDIDHASH_STR_LEN + 1];
    } devInfo;
} DevIdentifyInfo;

typedef struct {
    uint8_t devIdCnt;
    uint8_t devIpCnt;
    LaneLinkType releaseLink;
    LinkConflictType conflictType;
    DevIdentifyInfo identifyInfo;
    char (*devIdList)[NETWORK_ID_BUF_LEN];
    char (*devIpList)[CONFLICT_DEV_IP_LEN];
    ListNode node;
} LinkConflictInfo;

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_LINK_CONFLICT_STRUCT_H
