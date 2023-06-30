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

#ifndef TRANS_LANE_MANAGER_H
#define TRANS_LANE_MANAGER_H

#include <stdint.h>
#include "lnn_lane_manager.h"
#include "lnn_lane_interface.h"
#include "softbus_app_info.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t TransLaneMgrInit(void);

void TransLaneMgrDeinit(void);

int32_t TransLaneMgrAddLane(int32_t channelId, int32_t channelType, LaneConnInfo *connInfo, uint32_t laneId,
    AppInfoData *myData);

int32_t TransLaneMgrDelLane(int32_t channelId, int32_t channelType);

void TransLaneMgrDeathCallback(const char *pkgName, int32_t pid);

int32_t TransGetLaneIdByChannelId(int32_t channelId, uint32_t *laneId);

int32_t TransGetChannelInfoByLaneId(uint32_t laneId, int32_t *channelId, int32_t *channelType);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
