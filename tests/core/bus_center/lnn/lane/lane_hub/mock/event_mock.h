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
#ifndef EVENT_MOCK_H
#define EVENT_MOCK_H

#include "bus_center_event_struct.h"
#include "lnn_net_builder_struct.h"
#include "map"
#include "softbus_error_code.h"
#include <gmock/gmock.h>

namespace OHOS {
class EventInterface {
public:
    EventInterface() {};
    virtual ~EventInterface() {};

    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual int32_t LnnNotifyDiscoveryDevice(
        const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect) = 0;
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual void LnnDeinitBusCenterEvent(void) = 0;
    virtual int32_t LnnInitBusCenterEvent(void) = 0;
    virtual void LnnNotifySensorHubReportEvent(SoftBusLpEventType type) = 0;
};

class EventInterfaceMock : public EventInterface {
public:
    EventInterfaceMock();
    ~EventInterfaceMock() override;

    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD3(LnnNotifyDiscoveryDevice, int32_t(const ConnectionAddr *, const LnnDfxDeviceInfoReport *, bool));
    MOCK_METHOD2(LnnUnregisterEventHandler, void(LnnEventType, LnnEventHandler));
    MOCK_METHOD0(LnnDeinitBusCenterEvent, void(void));
    MOCK_METHOD0(LnnInitBusCenterEvent, int32_t(void));
    MOCK_METHOD1(LnnNotifySensorHubReportEvent, void(SoftBusLpEventType));
    static int32_t ActionifLnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
    static inline std::map<LnnEventType, LnnEventHandler> g_event_handlers;
};

extern "C" {
    int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
    int32_t LnnNotifyDiscoveryDevice(
        const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect);
    void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler);
    void LnnDeinitBusCenterEvent(void);
    int32_t LnnInitBusCenterEvent(void);
    void LnnNotifySensorHubReportEvent(SoftBusLpEventType type);
}
} // namespace OHOS
#endif // EVENT_MOCK_H
