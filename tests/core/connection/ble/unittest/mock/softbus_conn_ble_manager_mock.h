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

#ifndef CONNECTION_BLE_MANAGER_MOCK_H
#define CONNECTION_BLE_MANAGER_MOCK_H

#include "cJSON.h"
#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event.h"
#include "conn_log.h"
#include "disc_interface.h"
#include "message_handler.h"
#include "softbus_adapter_ble_gatt_client.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_config_type.h"
#include "softbus_conn_ble_connection.h"

namespace OHOS {
class ConnectionBleManagerInterface {
public:
    ConnectionBleManagerInterface() {};
    virtual ~ConnectionBleManagerInterface() {};

    virtual int32_t ConnBlePostBytesInner(uint32_t connectionId, uint8_t *data, uint32_t dataLen, int32_t pid,
        int32_t flag, int32_t module, int64_t seq, PostBytesFinishAction postBytesFinishAction) = 0;
    virtual int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature) = 0;
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual int64_t ConnBlePackCtlMessage(
        BleCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outLen) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;

    virtual int32_t SoftBusGattsAddDescriptor(int32_t srvcHandle, SoftBusBtUuid descUuid, int32_t permissions) = 0;
    virtual int32_t SoftBusGattsAddCharacteristic(
        int32_t srvcHandle, SoftBusBtUuid characUuid, int32_t properties, int32_t permissions) = 0;
    virtual int32_t SoftBusGattsStartService(int32_t srvcHandle) = 0;
    virtual int32_t SoftBusGattsSendResponse(SoftBusGattsResponse *param) = 0;
    virtual ConnBleConnection *LegacyBleCreateConnection(
        const char *addr, ConnSideType side, int32_t underlayerHandle, bool fastestConnectEnable) = 0;
    virtual int32_t LegacyBleSaveConnection(ConnBleConnection *connection) = 0;
    virtual int32_t ConnGattClientConnect(ConnBleConnection *connection) = 0;
    virtual int32_t ConnGattClientDisconnect(ConnBleConnection *connection, bool grace, bool refreshGatt) = 0;
    virtual int32_t ConnGattClientSend(
        ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module) = 0;
    virtual int32_t ConnGattClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority) = 0;
    virtual int32_t ConnGattServerStartService() = 0;
    virtual int32_t ConnGattServerStopService() = 0;
    virtual int32_t ConnGattServerSend(
        ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module) = 0;
    virtual int32_t ConnGattServerConnect(ConnBleConnection *connection) = 0;
    virtual int32_t ConnGattServerDisconnect(ConnBleConnection *connection) = 0;
    virtual int32_t ConnGattInitClientModule(SoftBusLooper *looper, const ConnBleClientEventListener *listener) = 0;
    virtual int32_t ConnGattInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *listener) = 0;
    virtual bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const str, int32_t *target) = 0;
    virtual bool GetJsonObjectNumber16Item(const cJSON *json, const char * const str, uint16_t *target) = 0;
    virtual int32_t BleHiDumperRegister(void) = 0;
};

class ConnectionBleManagerInterfaceMock : public ConnectionBleManagerInterface {
public:
    ConnectionBleManagerInterfaceMock();
    ~ConnectionBleManagerInterfaceMock() override;

    MOCK_METHOD2(SoftbusGattcConnect, int32_t(int32_t, SoftBusBtAddr *));
    MOCK_METHOD1(BleGattcDisconnect, int(int));
    MOCK_METHOD3(SoftBusGattsAddService, int(SoftBusBtUuid, bool, int));
    MOCK_METHOD1(SoftBusGattsStopService, int(int));

    MOCK_METHOD1(SoftbusGattcRefreshServices, int32_t(int32_t));
    MOCK_METHOD1(SoftbusGattcSearchServices, int32_t(int32_t));

    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t(const char *, InfoKey, char *, uint32_t));

    MOCK_METHOD(int32_t, ConnBlePostBytesInner,
        (uint32_t, uint8_t *, uint32_t, int32_t, int32_t, int32_t, int64_t, PostBytesFinishAction), (override));
    MOCK_METHOD(int32_t, LnnGetConnSubFeatureByUdidHashStr, (const char *, uint64_t *), (override));
    MOCK_METHOD(
        int64_t, ConnBlePackCtlMessage, (BleCtlMessageSerializationContext, uint8_t **, uint32_t *), (override));
    MOCK_METHOD(int32_t, LnnGetLocalStrInfo, (InfoKey, char *, uint32_t), (override));
    MOCK_METHOD(int32_t, LnnGetLocalNumInfo, (InfoKey, int32_t *), (override));

    MOCK_METHOD(int, SoftBusGattsAddDescriptor, (int, SoftBusBtUuid, int), (override));
    MOCK_METHOD(int, SoftBusGattsAddCharacteristic, (int, SoftBusBtUuid, int, int), (override));
    MOCK_METHOD(int, SoftBusGattsStartService, (int), (override));
    MOCK_METHOD(int, SoftBusGattsSendResponse, (SoftBusGattsResponse *), (override));
    MOCK_METHOD(
        ConnBleConnection *, LegacyBleCreateConnection, (const char *, ConnSideType, int32_t, bool), (override));
    MOCK_METHOD(int32_t, LegacyBleSaveConnection, (ConnBleConnection *), (override));
    MOCK_METHOD(int32_t, ConnGattClientConnect, (ConnBleConnection *), (override));
    MOCK_METHOD(int32_t, ConnGattClientDisconnect, (ConnBleConnection *, bool, bool), (override));
    MOCK_METHOD(int32_t, ConnGattClientSend, (ConnBleConnection *, const uint8_t *, uint32_t, int32_t), (override));
    MOCK_METHOD(int32_t, ConnGattClientUpdatePriority, (ConnBleConnection *, ConnectBlePriority), (override));
    MOCK_METHOD(int32_t, ConnGattServerStartService, (), (override));
    MOCK_METHOD(int32_t, ConnGattServerStopService, (), (override));
    MOCK_METHOD(int32_t, ConnGattServerSend, (ConnBleConnection *, const uint8_t *, uint32_t, int32_t), (override));
    MOCK_METHOD(int32_t, ConnGattServerConnect, (ConnBleConnection *), (override));
    MOCK_METHOD(int32_t, ConnGattServerDisconnect, (ConnBleConnection *), (override));
    MOCK_METHOD(int32_t, ConnGattInitClientModule,
        (SoftBusLooper *, const ConnBleClientEventListener *), (override));
    MOCK_METHOD(int32_t, ConnGattInitServerModule,
        (SoftBusLooper *, const ConnBleServerEventListener *), (override));
    MOCK_METHOD(bool, GetJsonObjectSignedNumberItem, (const cJSON *json, const char * const str, int32_t *target),
        (override));
    MOCK_METHOD(
        bool, GetJsonObjectNumber16Item, (const cJSON *json, const char * const str, uint16_t *target), (override));
    MOCK_METHOD(int32_t, BleHiDumperRegister, (), (override));

    static bool ActionOfGetdelta(const cJSON *json, const char * const str, int32_t *target);
    static bool ActionOfGetPeerRc1(const cJSON *json, const char * const str, int32_t *target);
    static bool ActionOfGetPeerRc0(const cJSON *json, const char * const str, int32_t *target);
};
} // namespace OHOS
#endif // CONNECTION_BLE_MANAGER_MOCK_H