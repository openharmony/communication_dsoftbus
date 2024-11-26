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

#ifndef LNN_WIFISERVICE_MONITOR_MOCK_H
#define LNN_WIFISERVICE_MONITOR_MOCK_H

#include "message_handler.h"
#include "softbus_wifi_api_adapter.h"
#include <gmock/gmock.h>
#include <mutex>

typedef void (*LnnAsyncCallbackFunc)(void *para);

namespace OHOS {
class LnnWifiServiceMonitorInterface {
public:
    LnnWifiServiceMonitorInterface() {};
    virtual ~LnnWifiServiceMonitorInterface() {};

    virtual SoftBusLooper *GetLooper(int32_t looper) = 0;
    virtual void LnnNotifyWlanStateChangeEvent(void *state) = 0;
    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para) = 0;
    virtual bool SoftBusIsWifiActive(void) = 0;
    virtual int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
};
class LnnWifiServiceMonitorInterfaceMock : public LnnWifiServiceMonitorInterface {
public:
    LnnWifiServiceMonitorInterfaceMock();
    ~LnnWifiServiceMonitorInterfaceMock() override;

    MOCK_METHOD1(GetLooper, SoftBusLooper *(int32_t));
    MOCK_METHOD1(LnnNotifyWlanStateChangeEvent, void(void *));
    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *));
    MOCK_METHOD0(SoftBusIsWifiActive, bool(void));
    MOCK_METHOD1(SoftBusGetLinkedInfo, int32_t(SoftBusWifiLinkedInfo *));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
};
} // namespace OHOS
#endif // LNN_WIFISERVICE_MONITOR_MOCK_H