/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_NETWORK_MANAGER_MOCK_H
#define LNN_NETWORK_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"

namespace OHOS {
class LnnNetworkManagerInterface {
public:
    LnnNetworkManagerInterface() {};
    virtual ~LnnNetworkManagerInterface() {};
    virtual int32_t RegistIPProtocolManager(void) = 0;
    virtual int32_t LnnInitPhysicalSubnetManager(void) = 0;
    virtual void LnnOnOhosAccountChanged(void) =0;
    virtual void LnnHbOnAuthGroupCreated(int32_t groupType) = 0;
    virtual void LnnStopDiscovery(void) = 0;
    virtual int32_t LnnStartDiscovery(void) = 0;
    virtual void SetCallLnnStatus(bool flag) = 0;
    virtual void LnnHbOnAuthGroupDeleted(void) =0;
};

class LnnNetworkManagerInterfaceMock : public LnnNetworkManagerInterface {
public:
    LnnNetworkManagerInterfaceMock();
    ~LnnNetworkManagerInterfaceMock() override;
    MOCK_METHOD0(RegistIPProtocolManager, int32_t (void));
    MOCK_METHOD0(LnnInitPhysicalSubnetManager, int32_t (void));
    MOCK_METHOD0(LnnOnOhosAccountChanged, void (void));
    MOCK_METHOD1(LnnHbOnAuthGroupCreated, void (int32_t));
    MOCK_METHOD0(LnnStopDiscovery, void (void));
    MOCK_METHOD0(LnnStartDiscovery, int32_t (void));
    MOCK_METHOD1(SetCallLnnStatus, void (bool));
    MOCK_METHOD0(LnnHbOnAuthGroupDeleted, void (void));
};
} // namespace OHOS
#endif // LNN_NETWORK_MANAGER_MOCK_H