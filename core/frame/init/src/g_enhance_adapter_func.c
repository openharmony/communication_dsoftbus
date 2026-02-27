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

#include "g_enhance_adapter_func.h"

#include <securec.h>
#include <dlfcn.h>
AdapterEnhanceFuncList g_adapterEnhanceFuncList = { NULL };

AdapterEnhanceFuncList *AdapterEnhanceFuncListGet(void)
{
    return &g_adapterEnhanceFuncList;
}

int32_t AdapterRegisterEnhanceFunc(void *soHandle)
{
    g_adapterEnhanceFuncList.softBusRegRangeCb = dlsym(soHandle, "SoftBusRegRangeCb");
    g_adapterEnhanceFuncList.softBusUnregRangeCb = dlsym(soHandle, "SoftBusUnregRangeCb");
    g_adapterEnhanceFuncList.softBusBleRange = dlsym(soHandle, "SoftBusBleRange");
    g_adapterEnhanceFuncList.softBusGetBlePower = dlsym(soHandle, "SoftBusGetBlePower");
    g_adapterEnhanceFuncList.softBusAddSleStateListener = dlsym(soHandle, "SoftBusAddSleStateListener");
    g_adapterEnhanceFuncList.isSleEnabled = dlsym(soHandle, "IsSleEnabled");
    g_adapterEnhanceFuncList.softBusRemoveSleStateListener = dlsym(soHandle, "SoftBusRemoveSleStateListener");
    g_adapterEnhanceFuncList.getSleRangeCapacity = dlsym(soHandle, "GetSleRangeCapacity");
    g_adapterEnhanceFuncList.getLocalSleAddr = dlsym(soHandle, "GetLocalSleAddr");
    g_adapterEnhanceFuncList.softbusBleAdapterInit = dlsym(soHandle, "SoftbusBleAdapterInit");
    g_adapterEnhanceFuncList.softbusBleAdapterDeInit = dlsym(soHandle, "SoftbusBleAdapterDeInit");
    g_adapterEnhanceFuncList.registerRadarCbForOpenSrc = dlsym(soHandle, "RegisterRadarCbForOpenSrc");
    g_adapterEnhanceFuncList.softbusSleAdapterInit = dlsym(soHandle, "SoftbusSleAdapterInit");
    g_adapterEnhanceFuncList.softbusSleAdapterDeInit = dlsym(soHandle, "SoftbusSleAdapterDeInit");
    g_adapterEnhanceFuncList.softbusMcuTimerInit = dlsym(soHandle, "SoftbusMcuTimerInit");
    g_adapterEnhanceFuncList.softbusMcuTimerDeinit = dlsym(soHandle, "SoftbusMcuTimerDeinit");
    return SOFTBUS_OK;
}