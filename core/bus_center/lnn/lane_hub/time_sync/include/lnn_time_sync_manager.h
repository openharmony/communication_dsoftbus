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

#ifndef LNN_TIME_SYNC_MANAGER_H
#define LNN_TIME_SYNC_MANAGER_H

#include "bus_center_event.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnStartTimeSync(const char *pkgName, int32_t callingPid, const char *targetNetworkId,
    TimeSyncAccuracy accuracy, TimeSyncPeriod period);
int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid);

int32_t LnnInitTimeSync(void);
void LnnDeinitTimeSync(void);

#ifdef __cplusplus
}
#endif

#endif