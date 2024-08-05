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

#ifndef LNN_LANE_LINK_CONFLICT_H
#define LNN_LANE_LINK_CONFLICT_H

#include "lnn_lane_interface.h"
#include "softbus_common.h"
#include "softbus_def.h"

#define CONFLICT_DEV_IP_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONFLICT_THREE_VAP = 0,
    CONFLICT_ROLE,
    CONFLICT_LINK_NUM_LIMITED,
    CONFLICT_SOFTAP,
    CONFLICT_BUTT,
} LinkConflictType;

typedef struct {
    ListNode node;
    char peerDevId[NETWORK_ID_BUF_LEN];
    LaneLinkType releaseLink;
    LinkConflictType conflictType;
    uint8_t devIdCnt;
    char (*devIdList)[NETWORK_ID_BUF_LEN];
    uint8_t devIpCnt;
    char (*devIpList)[CONFLICT_DEV_IP_LEN];
} LinkConflictInfo;

int32_t InitLaneLinkConflict(void);
void DeinitLaneLinkConflict(void);
LinkConflictType GetConflictTypeWithErrcode(int32_t conflictErrcode);
int32_t AddLinkConflictInfo(const LinkConflictInfo *linkConflictInfo);
int32_t DelLinkConflictInfo(const char *peerDevId, LinkConflictType conflictType);
int32_t FindLinkConflictInfoByDevId(const char *peerDevId, LinkConflictType conflictType,
    LinkConflictInfo *linkConflictInfo);
void RemoveConflictInfoTimelinessMsg(const char *peerDevId, LinkConflictType conflictType);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_LINK_CONFLICT_H
