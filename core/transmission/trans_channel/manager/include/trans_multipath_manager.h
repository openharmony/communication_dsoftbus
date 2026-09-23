/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef TRANS_MULTIPATH_MANAGER_H
#define TRANS_MULTIPATH_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

#include "common_list.h"
#include "softbus_app_info.h"
#include "softbus_trans_def.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* ========== SocketChannelInfo multipath state management ========== */

int32_t TransMultipathUpdateChannel(
    const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType);

int32_t TransMultipathUpdateLane(
    const char *sessionName, int32_t sessionId, uint32_t laneHandle, bool isQosLane, bool isAsync);

/* ========== Second link allocation ========== */

bool TransMultipathNeedReallocSecondLane(int32_t channelId);

void TransMultipathGetReallocList(ListNode *multipathReallocList);

int32_t TransMultipathOpenSecondChannel(int32_t channelId, uint64_t laneId);

/* ========== Multipath initialization on channel open ========== */

int32_t TransMultipathInitFirstChannel(const SessionParam *param, AppInfo *appInfo);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // TRANS_MULTIPATH_MANAGER_H
