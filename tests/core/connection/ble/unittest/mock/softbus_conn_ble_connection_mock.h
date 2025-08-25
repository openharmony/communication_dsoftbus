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

#ifndef CONNECTION_BR_MOCK_H
#define CONNECTION_BR_MOCK_H

#include <gmock/gmock.h>
#include <mutex>
#include "cJSON.h"

#include "conn_log.h"
#include "disc_interface.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_config_type.h"
#include "softbus_conn_ble_connection.h"
#include "ohos_bt_def.h"
#include "ohos_bt_gatt_client.h"


namespace OHOS {
class ConnectionBleInterface {
public:
    ConnectionBleInterface() {};
    virtual ~ConnectionBleInterface() {};
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num) = 0;
    virtual int32_t ConvertBtMacToBinary(const char *strMac, uint32_t strMacLen, uint8_t *binMac,
        uint32_t binMacLen) = 0;
    virtual int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr) = 0;
    virtual int32_t BleGattcDisconnect(int32_t clientId) = 0;
    virtual int32_t SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int32_t number) = 0;
    virtual int32_t SoftBusGattsStopService(int32_t srvcHandle) = 0;
    virtual int32_t SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int32_t connId) = 0;
    virtual int32_t SoftbusGattcRefreshServices(int32_t clientId) = 0;
    virtual int32_t SoftbusGattcSearchServices(int32_t clientId) = 0;
    virtual bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int *target) = 0;
    virtual int BleGattsAddService(int serverId, BtUuid srvcUuid, bool isPrimary, int number) = 0;
    virtual int BleGattcUnRegister(int clientId) = 0;
    virtual int BleGattcSetPriority(int clientId, const BdAddr *bdAddr, BtGattPriority priority) = 0;
    virtual int32_t BleHiDumperRegister(void) = 0;
};

class ConnectionBleInterfaceMock : public ConnectionBleInterface {
public:
    ConnectionBleInterfaceMock();
    ~ConnectionBleInterfaceMock() override;
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int));
    MOCK_METHOD4(ConvertBtMacToBinary, int32_t (const char *, uint32_t, uint8_t *, uint32_t));
    MOCK_METHOD2(SoftbusGattcConnect, int32_t (int32_t, SoftBusBtAddr *));
    MOCK_METHOD1(BleGattcDisconnect, int32_t (int));
    MOCK_METHOD3(SoftBusGattsAddService, int32_t (SoftBusBtUuid, bool, int));
    MOCK_METHOD1(SoftBusGattsStopService, int32_t (int));
    MOCK_METHOD2(SoftBusGattsDisconnect, int32_t (SoftBusBtAddr, int));
    MOCK_METHOD1(SoftbusGattcRefreshServices, int32_t (int32_t));
    MOCK_METHOD1(SoftbusGattcSearchServices, int32_t (int32_t));
    MOCK_METHOD3(GetJsonObjectSignedNumberItem, bool (const cJSON *, const char * const, int32_t *));
    MOCK_METHOD(int, BleGattsAddService, (int, BtUuid, bool, int), (override));
    MOCK_METHOD(int, BleGattcUnRegister, (int), (override));
    MOCK_METHOD(int, BleGattcSetPriority, (int, const BdAddr *, BtGattPriority), (override));
    MOCK_METHOD(int32_t, BleHiDumperRegister, (), (override));
};
} // namespace OHOS
#endif // CONNECTION_BLE_MOCK_H