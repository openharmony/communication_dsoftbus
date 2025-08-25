/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0g_ledger_Interface
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "event_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_eventinterface;

EventInterfaceMock::EventInterfaceMock()
{
    g_eventinterface = reinterpret_cast<void *>(this);
}

EventInterfaceMock::~EventInterfaceMock()
{
    g_eventinterface = nullptr;
}

static EventInterface *GetEventInterface()
{
    return reinterpret_cast<EventInterfaceMock *>(g_eventinterface);
}

extern "C" {
int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetEventInterface()->LnnRegisterEventHandler(event, handler);
}

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect)
{
    return GetEventInterface()->LnnNotifyDiscoveryDevice(addr, infoReport, isNeedConnect);
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetEventInterface()->LnnUnregisterEventHandler(event, handler);
}

void LnnDeinitBusCenterEvent(void)
{
    return GetEventInterface()->LnnDeinitBusCenterEvent();
}

int32_t LnnInitBusCenterEvent(void)
{
    return GetEventInterface()->LnnInitBusCenterEvent();
}
}

int32_t EventInterfaceMock::ActionifLnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    if (event == LNN_EVENT_TYPE_MAX || handler == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_event_handlers.emplace(event, handler);
    return SOFTBUS_OK;
}

void LnnNotifySensorHubReportEvent(SoftBusLpEventType type)
{
    return GetEventInterface()->LnnNotifySensorHubReportEvent(type);
}
} // namespace OHOS
