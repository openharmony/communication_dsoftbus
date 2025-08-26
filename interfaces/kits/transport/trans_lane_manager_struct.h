/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef TRANS_LANE_MANAGER_STRUCT_H
#define TRANS_LANE_MANAGER_STRUCT_H

#include <stdint.h>
#include "common_list.h"
#include "lnn_lane_interface_struct.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    CORE_SESSION_STATE_INIT,
    CORE_SESSION_STATE_WAIT_LANE,
    CORE_SESSION_STATE_LAN_COMPLETE,
    CORE_SESSION_STATE_CHANNEL_OPENED,
    CORE_SESSION_STATE_CANCELLING,
    CORE_SESSION_STATE_BUTT,
} CoreSessionState;

typedef struct {
    ListNode node;
    bool isQosLane;
    char pkgName[PKG_NAME_SIZE_MAX];
    int32_t channelId;
    int32_t channelType;
    int32_t pid;
    uint32_t laneHandle;
    LaneConnInfo laneConnInfo;
} TransLaneInfo;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
