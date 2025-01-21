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

#ifndef CONNECTION_BLE_CLIENT_MOCK_H
#define CONNECTION_BLE_CLIENT_MOCK_H

#include <gmock/gmock.h>

#include "conn_log.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_adapter_ble_gatt_client.h"
#include "bus_center_info_key.h"


namespace OHOS {
class ConnectionBleClientInterface {
public:
    ConnectionBleClientInterface() {};
    virtual ~ConnectionBleClientInterface() {};
    virtual int32_t SoftbusGattcSetFastestConn(int32_t clientId) = 0;
    virtual int32_t SoftbusGattcRefreshServices(int32_t clientId) = 0;
    virtual int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr) = 0;
    virtual uint8_t *ConnGattTransRecv(
        uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen) = 0;
    virtual int32_t SoftbusGattcGetService(int32_t clientId, SoftBusBtUuid *serverUuid) = 0;
    virtual int32_t SoftbusGattcSearchServices(int32_t clientId) = 0;
    virtual int32_t SoftbusGattcRegisterNotification(int32_t clientId,
        SoftBusBtUuid *serverUuid, SoftBusBtUuid *charaUuid, SoftBusBtUuid *descriptorUuid) = 0;
    virtual int32_t SoftbusGattcConfigureMtuSize(int32_t clientId, int32_t mtuSize) = 0;
    virtual int32_t SoftbusBleGattcDisconnect(int32_t clientId, bool refreshGatt) = 0;
    virtual int32_t SoftbusGattcWriteCharacteristic(int32_t clientId, SoftBusGattcData *clientData) = 0;
    virtual int32_t SoftbusGattcSetPriority(int32_t clientId, SoftBusBtAddr *addr,
        SoftbusBleGattPriority priority) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t ConnBlePostBytesInner(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq,
    PostBytesFinishAction postBytesFinishAction) = 0;
    virtual int32_t BleHiDumperRegister(void) = 0;
};

class ConnectionBleClientInterfaceMock : public ConnectionBleClientInterface {
public:
    ConnectionBleClientInterfaceMock();
    ~ConnectionBleClientInterfaceMock() override;
    MOCK_METHOD(int32_t, SoftbusGattcSetFastestConn, (int32_t), (override));
    MOCK_METHOD(int32_t, SoftbusGattcRefreshServices, (int32_t), (override));
    MOCK_METHOD(int32_t, SoftbusGattcConnect, (int32_t, SoftBusBtAddr *), (override));
    MOCK_METHOD(uint8_t *, ConnGattTransRecv, (uint32_t, uint8_t *, uint32_t,
        ConnBleReadBuffer *, uint32_t *), (override));
    MOCK_METHOD(int32_t, SoftbusGattcGetService, (int32_t, SoftBusBtUuid *), (override));
    MOCK_METHOD(int32_t, SoftbusGattcSearchServices, (int32_t), (override));
    MOCK_METHOD(int32_t, SoftbusGattcRegisterNotification, (int32_t, SoftBusBtUuid *,
        SoftBusBtUuid *, SoftBusBtUuid *));
    MOCK_METHOD(int32_t, SoftbusGattcConfigureMtuSize, (int32_t, int));
    MOCK_METHOD(int32_t, SoftbusBleGattcDisconnect, (int32_t, bool));
    MOCK_METHOD(int32_t, SoftbusGattcWriteCharacteristic, (int32_t, SoftBusGattcData *));
    MOCK_METHOD(int32_t, SoftbusGattcSetPriority, (int32_t, SoftBusBtAddr *,
        SoftbusBleGattPriority));
    MOCK_METHOD(int32_t, LnnGetLocalStrInfo, (InfoKey, char *, uint32_t));
    MOCK_METHOD(int32_t, LnnGetLocalNumInfo, (InfoKey, int32_t *));
    MOCK_METHOD(int32_t, ConnBlePostBytesInner, (uint32_t connectionId, uint8_t *data,
        uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq, PostBytesFinishAction));
    MOCK_METHOD(int32_t, BleHiDumperRegister, (), (override));

    static uint8_t *ConnGattTransRecvReturnConnModule(
        uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen);
    static uint8_t *ConnGattTransRecvReturnConnModule1(
        uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen);
    static uint8_t *ConnGattTransRecvReturnOldNearby(
        uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen);
    static uint8_t *ConnGattTransRecvReturnDefult(
        uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen);
    static uint8_t *ActionOfConnGattTransRecv(
        uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen);
};
} // namespace OHOS
#endif // CONNECTION_BLE_CLIENT_MOCK_H