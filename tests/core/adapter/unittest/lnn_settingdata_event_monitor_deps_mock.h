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

#ifndef LNN_SETTINGDATA_EVENT_MONITOR_DEPS_MOCK_H
#define LNN_SETTINGDATA_EVENT_MONITOR_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <securec.h>

#include "lnn_async_callback_utils.h"
#include "message_handler.h"
#include "softbus_utils.h"

namespace OHOS {
class SettingDataEventMonitorDepsInterface {
public:
    SettingDataEventMonitorDepsInterface() {};
    virtual ~SettingDataEventMonitorDepsInterface() {};

    virtual SoftBusLooper *GetLooper(int32_t looper) = 0;
    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
};

class SettingDataEventMonitorDepsInterfaceMock : public SettingDataEventMonitorDepsInterface {
public:
    SettingDataEventMonitorDepsInterfaceMock();
    ~SettingDataEventMonitorDepsInterfaceMock() override;

    MOCK_METHOD1(GetLooper, SoftBusLooper * (int));
    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t (SoftBusLooper *, LnnAsyncCallbackFunc, void *));
    MOCK_METHOD0(GetActiveOsAccountIds, int32_t (void));
};
} // namespace OHOS
#endif // LNN_SETTINGDATA_EVENT_MONITOR_DEPS_MOCK_H
