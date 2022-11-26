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

#ifndef LNN_TIME_SYNC_IMPL_H
#define LNN_TIME_SYNC_IMPL_H

#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*onTimeSyncImplComplete)(const char *networkId, double offset, int retCode);
} TimeSyncImplCallback;

int32_t LnnTimeSyncImplInit(void);
void LnnTimeSyncImplDeinit(void);

int32_t LnnStartTimeSyncImpl(const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, const TimeSyncImplCallback *callback);
int32_t LnnStopTimeSyncImpl(const char *targetNetworkId);

#ifdef __cplusplus
}
#endif

#endif