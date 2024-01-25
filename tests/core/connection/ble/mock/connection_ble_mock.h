/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


namespace OHOS {
class ConnectionBleInterface {
public:
    ConnectionBleInterface() {};
    virtual ~ConnectionBleInterface() {};
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int num) = 0;
    virtual int32_t ConvertBtMacToBinary(const char *strMac, uint32_t strMacLen, uint8_t *binMac,
        uint32_t binMacLen) = 0;
    virtual int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr) = 0;
    virtual int BleGattcDisconnect(int clientId) = 0;
    virtual int SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int number) = 0;
    virtual int SoftBusGattsStopService(int srvcHandle) = 0;
    virtual int SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int connId) = 0;
    virtual int32_t SoftbusGattcRefreshServices(int32_t clientId) = 0;
    virtual int32_t SoftbusGattcSearchServices(int32_t clientId) = 0;
    virtual bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int *target) = 0;
};

class ConnectionBleInterfaceMock : public ConnectionBleInterface {
public:
    ConnectionBleInterfaceMock();
    ~ConnectionBleInterfaceMock() override;
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int));
    MOCK_METHOD4(ConvertBtMacToBinary, int32_t (const char *, uint32_t, uint8_t *, uint32_t));
    MOCK_METHOD2(SoftbusGattcConnect, int32_t (int32_t, SoftBusBtAddr *));
    MOCK_METHOD1(BleGattcDisconnect, int (int));
    MOCK_METHOD3(SoftBusGattsAddService, int (SoftBusBtUuid, bool, int));
    MOCK_METHOD1(SoftBusGattsStopService, int (int));
    MOCK_METHOD2(SoftBusGattsDisconnect, int (SoftBusBtAddr, int));
    MOCK_METHOD1(SoftbusGattcRefreshServices, int32_t (int32_t));
    MOCK_METHOD1(SoftbusGattcSearchServices, int32_t (int32_t));
    MOCK_METHOD3(GetJsonObjectSignedNumberItem, bool (const cJSON *, const char * const, int *));
};
} // namespace OHOS
#endif // CONNECTION_BLE_MOCK_H