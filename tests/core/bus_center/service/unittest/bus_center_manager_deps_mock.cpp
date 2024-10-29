/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bus_center_manager_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_busCenterManagerDepsInterface;
BusCenterManagerDepsInterfaceMock::BusCenterManagerDepsInterfaceMock()
{
    g_busCenterManagerDepsInterface = reinterpret_cast<void *>(this);
}

BusCenterManagerDepsInterfaceMock::~BusCenterManagerDepsInterfaceMock()
{
    g_busCenterManagerDepsInterface = nullptr;
}

static BusCenterManagerDepsInterface *GetBusCenterManagerDepsInterface()
{
    return reinterpret_cast<BusCenterManagerDepsInterface *>(g_busCenterManagerDepsInterface);
}

extern "C" {
bool GetWatchdogFlag(void)
{
    return GetBusCenterManagerDepsInterface()->GetWatchdogFlag();
}

SoftBusLooper *GetLooper(int32_t looper)
{
    return GetBusCenterManagerDepsInterface()->GetLooper(looper);
}

SoftBusLooper *CreateNewLooper(const char *name)
{
    return GetBusCenterManagerDepsInterface()->CreateNewLooper(name);
}

int32_t LnnInitNetLedger(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitNetLedger();
}

int32_t LnnInitDecisionCenter(uint32_t version)
{
    return GetBusCenterManagerDepsInterface()->LnnInitDecisionCenter(version);
}

int32_t LnnInitBusCenterEvent(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitBusCenterEvent();
}

int32_t LnnInitEventMonitor(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitEventMonitor();
}

int32_t LnnInitDiscoveryManager(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitDiscoveryManager();
}

int32_t LnnInitNetworkManager(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitNetworkManager();
}

int32_t LnnInitNetBuilder(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitNetBuilder();
}

int32_t LnnInitMetaNode(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitMetaNode();
}

bool IsActiveOsAccountUnlocked(void)
{
    return GetBusCenterManagerDepsInterface()->IsActiveOsAccountUnlocked();
}

void RestoreLocalDeviceInfo(void)
{
    return GetBusCenterManagerDepsInterface()->RestoreLocalDeviceInfo();
}

void SoftBusRunPeriodicalTask(const char *name, void (*task)(void), uint64_t interval, uint64_t delay)
{
    return GetBusCenterManagerDepsInterface()->SoftBusRunPeriodicalTask(name, task, interval, delay);
}

int32_t LnnInitLaneHub(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitLaneHub();
}

int32_t InitDecisionCenter(void)
{
    return GetBusCenterManagerDepsInterface()->InitDecisionCenter();
}

int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
{
    return GetBusCenterManagerDepsInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

void LnnCoapConnectInit(void)
{
    return GetBusCenterManagerDepsInterface()->LnnCoapConnectInit();
}

int32_t LnnInitNetLedgerDelay(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitNetLedgerDelay();
}

int32_t LnnInitEventMoniterDelay(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitEventMoniterDelay();
}

int32_t LnnInitNetworkManagerDelay(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitNetworkManagerDelay();
}

int32_t LnnInitNetBuilderDelay(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitNetBuilderDelay();
}

int32_t LnnInitLaneHubDelay(void)
{
    return GetBusCenterManagerDepsInterface()->LnnInitLaneHubDelay();
}
}
} // namespace OHOS
