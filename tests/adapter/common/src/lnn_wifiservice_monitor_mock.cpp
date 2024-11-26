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

#include "lnn_wifiservice_monitor_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
void *g_interface = nullptr;

LnnWifiServiceMonitorInterfaceMock::LnnWifiServiceMonitorInterfaceMock()
{
    g_interface = reinterpret_cast<void *>(this);
}

LnnWifiServiceMonitorInterfaceMock::~LnnWifiServiceMonitorInterfaceMock()
{
    if (g_interface != nullptr) {
        free(g_interface);
        g_interface = nullptr;
    }
}

static LnnWifiServiceMonitorInterface *GetLnnWifiServiceMonitorInterface()
{
    return reinterpret_cast<LnnWifiServiceMonitorInterface *>(g_interface);
}

extern "C" {
SoftBusLooper *GetLooper(int32_t looper)
{
    return GetLnnWifiServiceMonitorInterface()->GetLooper(looper);
}

void LnnNotifyWlanStateChangeEvent(void *state)
{
    return GetLnnWifiServiceMonitorInterface()->LnnNotifyWlanStateChangeEvent(state);
}

int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para)
{
    return GetLnnWifiServiceMonitorInterface()->LnnAsyncCallbackHelper(looper, callback, para);
}

bool SoftBusIsWifiActive(void)
{
    return GetLnnWifiServiceMonitorInterface()->SoftBusIsWifiActive();
}

int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info)
{
    return GetLnnWifiServiceMonitorInterface()->SoftBusGetLinkedInfo(info);
}

int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetLnnWifiServiceMonitorInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}
}
} // namespace OHOS