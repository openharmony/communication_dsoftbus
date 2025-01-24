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

#include "lnn_settingdata_event_monitor_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_settingDataEventMonitorDepsInterface;
SettingDataEventMonitorDepsInterfaceMock::SettingDataEventMonitorDepsInterfaceMock()
{
    g_settingDataEventMonitorDepsInterface = reinterpret_cast<void *>(this);
}

SettingDataEventMonitorDepsInterfaceMock::~SettingDataEventMonitorDepsInterfaceMock()
{
    g_settingDataEventMonitorDepsInterface = nullptr;
}

static SettingDataEventMonitorDepsInterface *GetSettingDataEventMonitorDepsInterface()
{
    return reinterpret_cast<SettingDataEventMonitorDepsInterface *>(g_settingDataEventMonitorDepsInterface);
}

extern "C" {
SoftBusLooper *GetLooper(int32_t looper)
{
    return GetSettingDataEventMonitorDepsInterface()->GetLooper(looper);
}

int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para)
{
    return GetSettingDataEventMonitorDepsInterface()->LnnAsyncCallbackHelper(looper, callback, para);
}

int32_t GetActiveOsAccountIds(void)
{
    return GetSettingDataEventMonitorDepsInterface()->GetActiveOsAccountIds();
}
}
} // namespace OHOS
