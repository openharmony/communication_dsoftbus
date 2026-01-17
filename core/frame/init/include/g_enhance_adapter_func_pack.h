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
#ifndef G_ENHANCE_ADAPTER_FUNC_PACK_H
#define G_ENHANCE_ADAPTER_FUNC_PACK_H

#include <stdint.h>
#include "softbus_adapter_range.h"
#include "softbus_adapter_sle_common_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DISC_COMMUNITY
int SoftBusGetBlePowerPacked(int8_t *power);
#endif /* DISC_COMMUNITY */

int SoftBusBleRangePacked(SoftBusRangeParam *param, int32_t *range);
int32_t SoftBusAddSleStateListenerPacked(const SoftBusSleStateListener *listener, int32_t *listenerId);
bool IsSleEnabledPacked(void);
void SoftBusRemoveSleStateListenerPacked(int listenerId);
int32_t GetSleRangeCapacityPacked(void);
int32_t GetLocalSleAddrPacked(char *sleAddr, uint32_t sleAddrLen);

int32_t SoftBusRegRangeCbPacked(SoftBusRangeModule module, const SoftBusRangeCallback *callback);
void SoftBusUnregRangeCbPacked(SoftBusRangeModule module);
void RegisterRadarCbForOpenSrcPacked(void *callback);
void SoftbusSleAdapterInitPacked(void);
void SoftbusSleAdapterDeInitPacked(void);
int32_t SoftbusMcuTimerInitPacked(void);
void SoftbusMcuTimerDeinitPacked(void);
#ifdef __cplusplus
}
#endif

#endif