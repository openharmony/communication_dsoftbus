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
#include "g_enhance_adapter_func_pack.h"

#include "g_enhance_adapter_func.h"
#include "softbus_init_common.h"
#include "softbus_adapter_range.h"

void RegisterRadarCbForOpenSrcPacked(void *callback)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->registerRadarCbForOpenSrc) != SOFTBUS_OK) {
        return;
    }
    return pfnAdapterEnhanceFuncList->registerRadarCbForOpenSrc(callback);
}

#ifdef DISC_COMMUNITY
int SoftBusGetBlePowerPacked(int8_t *power)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softBusGetBlePower) != SOFTBUS_OK) {
        return SoftBusGetBlePower(power);
    }
    return pfnAdapterEnhanceFuncList->softBusGetBlePower(power);
}
#endif /* DISC_COMMUNITY */

int SoftBusBleRangePacked(SoftBusRangeParam *param, int32_t *range)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softBusBleRange) != SOFTBUS_OK) {
        return SoftBusBleRange(param, range);
    }
    return pfnAdapterEnhanceFuncList->softBusBleRange(param, range);
}

int32_t SoftBusRegRangeCbPacked(SoftBusRangeModule module, const SoftBusRangeCallback *callback)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softBusRegRangeCb) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAdapterEnhanceFuncList->softBusRegRangeCb(module, callback);
}

void SoftBusUnregRangeCbPacked(SoftBusRangeModule module)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softBusUnregRangeCb) != SOFTBUS_OK) {
        return;
    }
    return pfnAdapterEnhanceFuncList->softBusUnregRangeCb(module);
}

int32_t SoftBusAddSleStateListenerPacked(const SoftBusSleStateListener *listener, int32_t *listenerId)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softBusAddSleStateListener) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnAdapterEnhanceFuncList->softBusAddSleStateListener(listener, listenerId);
}

bool IsSleEnabledPacked(void)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->isSleEnabled) != SOFTBUS_OK) {
        return false;
    }
    return pfnAdapterEnhanceFuncList->isSleEnabled();
}

void SoftBusRemoveSleStateListenerPacked(int listenerId)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softBusRemoveSleStateListener) != SOFTBUS_OK) {
        return;
    }
    return pfnAdapterEnhanceFuncList->softBusRemoveSleStateListener(listenerId);
}

int32_t GetSleRangeCapacityPacked(void)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->getSleRangeCapacity) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnAdapterEnhanceFuncList->getSleRangeCapacity();
}

int32_t GetLocalSleAddrPacked(char *sleAddr, uint32_t sleAddrLen)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->getLocalSleAddr) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnAdapterEnhanceFuncList->getLocalSleAddr(sleAddr, sleAddrLen);
}

void SoftbusSleAdapterInitPacked(void)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softbusSleAdapterInit) != SOFTBUS_OK) {
        return;
    }
    return pfnAdapterEnhanceFuncList->softbusSleAdapterInit();
}

void SoftbusSleAdapterDeInitPacked(void)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softbusSleAdapterDeInit) != SOFTBUS_OK) {
        return;
    }
    return pfnAdapterEnhanceFuncList->softbusSleAdapterDeInit();
}

int32_t SoftbusMcuTimerInitPacked(void)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softbusMcuTimerInit) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnAdapterEnhanceFuncList->softbusMcuTimerInit();
}

void SoftbusMcuTimerDeinitPacked(void)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (AdapterCheckFuncPointer((void *)pfnAdapterEnhanceFuncList->softbusMcuTimerDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnAdapterEnhanceFuncList->softbusMcuTimerDeinit();
}