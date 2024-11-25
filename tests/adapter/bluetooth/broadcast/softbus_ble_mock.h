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

#ifndef SOFTBUS_BLE_MGR_MOCK_H
#define SOFTBUS_BLE_MGR_MOCK_H

#include "gmock/gmock.h"

#include "softbus_adapter_bt_common.h"
#include "softbus_ble_gatt.h"
#include "softbus_broadcast_adapter_interface.h"
#include "softbus_broadcast_manager.h"

class BleGattInterface {
public:
    virtual void SoftbusBleAdapterInit() = 0;
    virtual int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener) = 0;
    virtual int32_t SoftBusRemoveBtStateListener(int32_t listenerId) = 0;
};

class ManagerMock : public BleGattInterface {
public:
    static ManagerMock *GetMock();

    ManagerMock();
    ~ManagerMock();

    MOCK_METHOD(void, SoftbusBleAdapterInit, (), (override));
    MOCK_METHOD(int32_t, SoftBusAddBtStateListener, (const SoftBusBtStateListener *listener), (override));
    MOCK_METHOD(int32_t, SoftBusRemoveBtStateListener, (int32_t listenerId), (override));

    static const SoftbusBroadcastCallback *broadcastCallback;
    static const SoftbusScanCallback *scanCallback;
    static inline const SoftbusScanCallback *softbusScanCallback {};
    static inline const SoftbusBroadcastCallback *softbusBroadcastCallback {};

private:
    static ManagerMock *managerMock;
};

#endif /* SOFTBUS_BLE_MGR_MOCK_H */