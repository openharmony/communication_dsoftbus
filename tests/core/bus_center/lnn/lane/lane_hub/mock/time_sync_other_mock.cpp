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

#include "time_sync_other_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_timeSyncOtherDepsInterface;
TimeSyncOtherDepsInterfaceMock::TimeSyncOtherDepsInterfaceMock()
{
    g_timeSyncOtherDepsInterface = reinterpret_cast<void *>(this);
}

TimeSyncOtherDepsInterfaceMock::~TimeSyncOtherDepsInterfaceMock()
{
    g_timeSyncOtherDepsInterface = nullptr;
}

static TimeSyncOtherDepsInterface *GetTimeSyncOtherDepsInterface()
{
    return reinterpret_cast<TimeSyncOtherDepsInterface *>(g_timeSyncOtherDepsInterface);
}

extern "C" {
int32_t LnnStartTimeSyncImplPacked(const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, const TimeSyncImplCallback *callback)
{
    return GetTimeSyncOtherDepsInterface()->LnnStartTimeSyncImplPacked(targetNetworkId, accuracy, period, callback);
}

int32_t LnnStopTimeSyncImplPacked(const char *targetNetworkId)
{
    return GetTimeSyncOtherDepsInterface()->LnnStopTimeSyncImplPacked(targetNetworkId);
}

SoftBusLooper *GetLooper(int32_t looper)
{
    return GetTimeSyncOtherDepsInterface()->GetLooper(looper);
}

void LnnNotifyTimeSyncResult(const char *pkgName, int32_t pid, const TimeSyncResultInfo *info, int32_t retCode)
{
    return GetTimeSyncOtherDepsInterface()->LnnNotifyTimeSyncResult(pkgName, pid, info, retCode);
}

int32_t LnnTimeSyncImplInitPacked(void)
{
    return GetTimeSyncOtherDepsInterface()->LnnTimeSyncImplInitPacked();
}

void LnnTimeSyncImplDeinitPacked(void)
{
    return GetTimeSyncOtherDepsInterface()->LnnTimeSyncImplDeinitPacked();
}

void *LnnMapGet(const Map *map, const char *key)
{
    return GetTimeSyncOtherDepsInterface()->LnnMapGet(map, key);
}
}
} // namespace OHOS