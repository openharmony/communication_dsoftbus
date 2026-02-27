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

#ifndef G_ENHANCE_ADAPTER_FUNC_H
#define G_ENHANCE_ADAPTER_FUNC_H

#include "stdint.h"
#include "softbus_adapter_range.h"
#include "softbus_config_type.h"
#include "softbus_adapter_sle_common_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*SoftBusRegRangeCbFunc)(SoftBusRangeModule module, const SoftBusRangeCallback *callback);
typedef void (*SoftBusUnregRangeCbFunc)(SoftBusRangeModule module);
typedef int (*SoftBusBleRangeFunc)(SoftBusRangeParam *param, int32_t *range);
typedef int (*SoftBusGetBlePowerFunc)(int8_t *power);
typedef int32_t (*SoftBusAddSleStateListenerFunc)(const SoftBusSleStateListener *listener, int32_t *listenerId);
typedef bool (*IsSleEnabledFunc)(void);
typedef void (*SoftBusRemoveSleStateListenerFunc)(int listenerId);
typedef int32_t (*GetSleRangeCapacityFunc)(void);
typedef int32_t (*GetLocalSleAddrFunc)(char *sleAddr, uint32_t sleAddrLen);
typedef void (*SoftbusBleAdapterInitFunc)(void);
typedef void (*SoftbusBleAdapterDeInitFunc)(void);
typedef void (*RegisterRadarCbForOpenSrcFunc)(void *callback);
typedef void (*SoftbusSleAdapterInit)(void);
typedef void (*SoftbusSleAdapterDeInit)(void);
typedef int32_t (*SoftbusMcuTimerInitFunc)(void);
typedef void (*SoftbusMcuTimerDeinitFunc)(void);

typedef struct TagAdapterEnhanceFuncList {
    SoftBusRegRangeCbFunc softBusRegRangeCb;
    SoftBusUnregRangeCbFunc softBusUnregRangeCb;
    SoftBusBleRangeFunc softBusBleRange;
    SoftBusGetBlePowerFunc softBusGetBlePower;
    SoftBusAddSleStateListenerFunc softBusAddSleStateListener;
    IsSleEnabledFunc isSleEnabled;
    SoftBusRemoveSleStateListenerFunc softBusRemoveSleStateListener;
    GetSleRangeCapacityFunc getSleRangeCapacity;
    GetLocalSleAddrFunc getLocalSleAddr;
    SoftbusBleAdapterInitFunc softbusBleAdapterInit;
    SoftbusBleAdapterDeInitFunc softbusBleAdapterDeInit;
    RegisterRadarCbForOpenSrcFunc registerRadarCbForOpenSrc;
    SoftbusSleAdapterInit softbusSleAdapterInit;
    SoftbusSleAdapterDeInit softbusSleAdapterDeInit;
    SoftbusMcuTimerInitFunc softbusMcuTimerInit;
    SoftbusMcuTimerDeinitFunc softbusMcuTimerDeinit;
} AdapterEnhanceFuncList;

AdapterEnhanceFuncList *AdapterEnhanceFuncListGet(void);
int32_t AdapterRegisterEnhanceFunc(void *soHandle);

#ifdef __cplusplus
}
#endif

#endif