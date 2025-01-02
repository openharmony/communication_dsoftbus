/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <cstdio>
#include <cstring>

#include <gtest/gtest.h>
#include <securec.h>
#include "softbus_feature_config.h"
#include "softbus_conn_ble_client.h"
#include "conn_log.h"
#include "bus_center_event.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_ble_conflict.h"
#include "bus_center_info_key.h"
#include "softbus_conn_ble_manager.h"
#include "ble_protocol_interface_factory.h"
#include "softbus_conn_ble_client_mock.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

static SoftBusGattcCallback *gattCb = NULL;
namespace OHOS {

extern "C" {
int32_t ConnGattServerStartService(void)
{
    return SOFTBUS_OK;
}

int32_t ConnGattServerStopService(void)
{
    return SOFTBUS_OK;
}

int32_t ConnGattServerDisconnect(ConnBleConnection *connection)
{
    return SOFTBUS_OK;
}

int32_t ConnGattServerConnect(ConnBleConnection *connection)
{
    return SOFTBUS_OK;
}

int32_t ConnGattServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    return SOFTBUS_OK;
}

int32_t SoftbusGattcRegisterCallback(SoftBusGattcCallback *cb, int32_t clientId)
{
    gattCb = cb;
    return SOFTBUS_OK;
}

int32_t ConnBleInitTransModule(ConnBleTransEventListener *listener)
{
    return SOFTBUS_OK;
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    return SOFTBUS_OK;
}

void SoftbusBleConflictRegisterListener(SoftBusBleConflictListener *listener)
{
    (void)listener;
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return SOFTBUS_OK;
}

int32_t ConnGattInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *listener)
{
    return SOFTBUS_OK;
}

int32_t InitSoftbusAdapterClient(void)
{
    return SOFTBUS_OK;
}
uint32_t ConnGetHeadSize(void)
{
    return SOFTBUS_OK;
}

void SoftbusBleConflictNotifyDateReceive(int32_t underlayerHandle, const uint8_t *data, uint32_t dataLen)
{
    (void)underlayerHandle;
    (void)data;
    (void)dataLen;
}

void SoftbusBleConflictNotifyDisconnect(const char *addr, const char *udid)
{
    (void)addr;
    (void)udid;
}

int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature)
{
    (void)udidHashStr;
    (void)connSubFeature;
    return SOFTBUS_OK;
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    (void)event;
    (void)handler;
    return SOFTBUS_OK;
}

void SoftbusBleConflictNotifyConnectResult(uint32_t requestId, int32_t underlayerHandle, bool status)
{
    (void)requestId;
    (void)underlayerHandle;
    (void)status;
}

int32_t ConnBleTransConfigPostLimit(const LimitConfiguration *configuration)
{
    (void)configuration;
    return SOFTBUS_OK;
}

int64_t ConnBlePackCtlMessage(BleCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outDataLen)
{
    (void)ctx;
    (void)outData;
    (void)outDataLen;
    return SOFTBUS_OK;
}

int32_t SoftbusGattcUnRegister(int32_t clientId)
{
    (void)clientId;
    return SOFTBUS_OK;
}

int32_t SoftbusGattcRegister(void)
{
    int32_t id = 100;
    return id;
}
}

void OnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnReusedConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    (void)connectionId;
    (void)moduleId;
    (void)seq;
    (void)data;
    (void)len;
}

class ClientConnectionTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown();
};

void ClientConnectionTest::SetUp()
{
    SoftbusConfigInit();
    ConnectCallback connectCb = {
        .OnConnected = OnConnected,
        .OnReusedConnected = OnReusedConnected,
        .OnDisconnected = OnDisconnected,
        .OnDataReceived = OnDataReceived,
    };
    LooperInit();
    ConnInitBle(&connectCb);
    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect).
        WillRepeatedly(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
}

void ClientConnectionTest::TearDown()
{
    LooperDeinit();
}

/*
* @tc.name: ClientConnectionTest001
* @tc.desc: Test ConnectionStateCallback for disconenct.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, ConnectionStateCallback001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 100, false);

    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusGattcConnect).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ConnGattClientConnect(connection);

    EXPECT_EQ(SOFTBUS_OK, ret);
    connection->fastestConnectEnable = true;
    connection->connectionRc = 0;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, SoftbusGattcConnect).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(bleMock, SoftbusGattcSetFastestConn).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ConnGattClientConnect(connection);
    uint64_t delta = 500;
    SoftBusSleepMs(BLE_FAST_CONNECT_TIMEOUT + delta); // to call timeout event
    EXPECT_EQ(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR, ret);
}
/*
* @tc.name: ClientConnectionTest002
* @tc.desc: Test ConnectionStateCallback for disconenct.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, ConnectionStateCallback002, TestSize.Level1)
{
    const char *addr = "11:22:33:44:77:99";
    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 130, false);
    ASSERT_NE(nullptr, connection);

    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusGattcSetFastestConn).WillRepeatedly(Return(
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    EXPECT_CALL(bleMock, SoftbusGattcConnect).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ConnGattClientConnect(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    connection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    gattCb->connectionStateCallback(connection->underlayerHandle, 5, SOFTBUS_OK);
    gattCb->connectionStateCallback(0, SOFTBUS_BT_CONNECT, SOFTBUS_OK);

    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect).WillRepeatedly(Return(
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    gattCb->connectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_DISCONNECT,
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);

    connection->state = BLE_CONNECTION_STATE_SERVICE_SEARCHING;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    gattCb->connectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_DISCONNECT,
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);
    gattCb->connectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_CONNECT,
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);

    gattCb->connectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_CONNECT,
        SOFTBUS_OK);
    SoftBusSleepMs(1500);
}

/*
* @tc.name: ServiceCompleteCallback001
* @tc.desc: Test ConnectionStateCallback for connect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, ServiceCompleteCallback001, TestSize.Level1)
{
    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect).WillRepeatedly(Return(
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    const char *addr = "11:22:33:44:55:12";
    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 100, false);
    EXPECT_NE(NULL, connection);

    connection->fastestConnectEnable = true;
    connection->connectionRc = 0;
    connection->state = BLE_CONNECTION_STATE_SERVICE_SEARCHED;
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    gattCb->serviceCompleteCallback(10, SOFTBUS_OK);
    gattCb->serviceCompleteCallback(connection->underlayerHandle, SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);
    gattCb->serviceCompleteCallback(connection->underlayerHandle, SOFTBUS_OK);
    connection->state = BLE_CONNECTION_STATE_SERVICE_SEARCHING;

    const char *bleAddr = "11:22:33:44:55:33";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 2, false);
    EXPECT_NE(NULL, connection);
    bleConnection->state = BLE_CONNECTION_STATE_SERVICE_SEARCHING;
    bleConnection->retrySearchServiceCnt = 0;
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, SoftbusGattcGetService)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcRegisterNotification)
        .WillRepeatedly(Return(SOFTBUS_OK));
    gattCb->serviceCompleteCallback(bleConnection->underlayerHandle, SOFTBUS_OK);

    EXPECT_CALL(bleMock, SoftbusGattcGetService)
        .WillRepeatedly(Return(  SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_GET_SERVICE_ERR));
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_INTERNAL_ERR));
    gattCb->serviceCompleteCallback(bleConnection->underlayerHandle, SOFTBUS_OK);

    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_INTERNAL_ERR));
    gattCb->serviceCompleteCallback(bleConnection->underlayerHandle, SOFTBUS_OK);
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices)
        .WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusSleepMs(500);
}

/*
* @tc.name: ServiceCompleteCallback002
* @tc.desc: Test ConnectionStateCallback for connect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, ServiceCompleteCallback002, TestSize.Level1)
{
    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    const char *bleAddr = "11:22:33:44:55:00";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 3, false);
    EXPECT_NE(NULL, bleConnection);
    bleConnection->retrySearchServiceCnt = 0;
    bleConnection->state = BLE_CONNECTION_STATE_SERVICE_SEARCHING;
    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, SoftbusGattcGetService)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcRegisterNotification)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_INTERNAL_ERR));
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices)
        .WillOnce(Return(SOFTBUS_CONN_BLE_INTERNAL_ERR));
    gattCb->serviceCompleteCallback(bleConnection->underlayerHandle, SOFTBUS_OK);
    SoftBusSleepMs(500);
    
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices)
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices)
        .WillOnce(Return(SOFTBUS_CONN_BLE_INTERNAL_ERR));
    bleConnection->retrySearchServiceCnt = 0;
    bleConnection->state = BLE_CONNECTION_STATE_SERVICE_SEARCHING;
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    gattCb->serviceCompleteCallback(bleConnection->underlayerHandle, SOFTBUS_OK);
    SoftBusSleepMs(500);
}

/*
* @tc.name: RegistNotificationCallback001
* @tc.desc: Test ConnectionStateCallback for connect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, RegistNotificationCallback001, TestSize.Level1)
{
    gattCb->registNotificationCallback(100, SOFTBUS_OK);
    const char *bleAddr = "11:22:33:44:55:66";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 4, false);
    EXPECT_NE(NULL, bleConnection);
    bleConnection->retrySearchServiceCnt = 0;
    bleConnection->state = BLE_CONNECTION_STATE_CONNECTED;
    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices)
        .WillRepeatedly(Return(SOFTBUS_OK));
    gattCb->registNotificationCallback(bleConnection->underlayerHandle, SOFTBUS_CONN_BLE_INTERNAL_ERR);
    SoftBusSleepMs(500);

    bleConnection->retrySearchServiceCnt = 5;
    bleConnection->state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    gattCb->registNotificationCallback(bleConnection->underlayerHandle, SOFTBUS_CONN_BLE_INTERNAL_ERR);
    SoftBusSleepMs(500);
}

/*
* @tc.name: RegistNotificationCallback002
* @tc.desc: Test ConnectionStateCallback for connect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, RegistNotificationCallback002, TestSize.Level1)
{
    const char *bleAddr = "11:22:33:44:44:99";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 5, false);
    EXPECT_NE(NULL, bleConnection);
    bleConnection->retrySearchServiceCnt = 0;
    bleConnection->state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusGattcRegisterNotification)
        .WillOnce(Return(SOFTBUS_OK));
    gattCb->registNotificationCallback(bleConnection->underlayerHandle, SOFTBUS_OK);
    SoftBusSleepMs(500);

    bleConnection->retrySearchServiceCnt = 0;
    bleConnection->state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_CALL(bleMock, SoftbusGattcRegisterNotification)
        .WillOnce(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_ERR));
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices)
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices)
        .WillOnce(Return(SOFTBUS_OK));
    gattCb->registNotificationCallback(bleConnection->underlayerHandle, SOFTBUS_OK);
    SoftBusSleepMs(500);
}

/*
* @tc.name: RegistNotificationCallback003
* @tc.desc: Test RegistNotificationCallback for connect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, RegistNotificationCallback003, TestSize.Level1)
{
    const char *bleAddr = "11:22:33:44:44:37";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 16, false);
    EXPECT_NE(NULL, bleConnection);

    bleConnection->state = BLE_CONNECTION_STATE_NET_NOTIFICATING;
    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    EXPECT_CALL(bleMock, SoftbusGattcConfigureMtuSize)
        .WillOnce(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONFIGURE_MTU_ERR));
    gattCb->registNotificationCallback(bleConnection->underlayerHandle, SOFTBUS_OK);
    SoftBusSleepMs(500);
    
    const char *addr = "11:22:33:44:44:37";
    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 17, false);
    EXPECT_NE(NULL, connection);

    connection->state = BLE_CONNECTION_STATE_NET_NOTIFICATING;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, SoftbusGattcConfigureMtuSize)
        .WillOnce(Return(SOFTBUS_OK));
    gattCb->registNotificationCallback(connection->underlayerHandle, SOFTBUS_OK);
    SoftBusSleepMs(500);

    connection->state = BLE_CONNECTION_STATE_CLOSED;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    gattCb->registNotificationCallback(connection->underlayerHandle, SOFTBUS_OK);
    SoftBusSleepMs(500);
}


/*
* @tc.name: NotificationReceiveCallback001
* @tc.desc: Test NotificationReceiveCallback
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, NotificationReceiveCallback001, TestSize.Level1)
{
    const char *bleAddr = "11:00:33:44:44:99";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 5, false);
    EXPECT_NE(NULL, bleConnection);

    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusGattcNotify param = {
        .dataLen = 50,
        .charaUuid.uuidLen = strlen(SOFTBUS_SERVICE_UUID),
    };
    param.charaUuid.uuid = (char *)SoftBusCalloc(param.charaUuid.uuidLen + 1);
    ASSERT_NE(nullptr, param.charaUuid.uuid);
    ret = strcpy_s(param.charaUuid.uuid, param.charaUuid.uuidLen + 1, SOFTBUS_SERVICE_UUID);
    EXPECT_EQ(EOK, ret);

    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param,
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_ERR);
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);
    SoftBusFree(param.charaUuid.uuid);
    param.charaUuid.uuid = nullptr;

    param.charaUuid.uuidLen = strlen(SOFTBUS_CHARA_BLECONN_UUID);
    param.charaUuid.uuid = (char *)SoftBusCalloc(param.charaUuid.uuidLen + 1);
    ASSERT_NE(nullptr, param.charaUuid.uuid);
    ret = strcpy_s(param.charaUuid.uuid, param.charaUuid.uuidLen + 1, SOFTBUS_CHARA_BLECONN_UUID);
    EXPECT_EQ(EOK, ret);
    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattTransRecv).WillOnce(Return(nullptr));
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);

    SoftBusFree(param.charaUuid.uuid);
    param.charaUuid.uuid = nullptr;
    param.charaUuid.uuidLen = strlen(SOFTBUS_CHARA_BLENET_UUID);
    param.charaUuid.uuid = (char *)SoftBusCalloc(param.charaUuid.uuidLen + 1);
    ASSERT_NE(nullptr, param.charaUuid.uuid);
    ret = strcpy_s(param.charaUuid.uuid, param.charaUuid.uuidLen + 1, SOFTBUS_CHARA_BLENET_UUID);
    EXPECT_EQ(EOK, ret);
    SoftBusSleepMs(500);
    EXPECT_CALL(bleMock, ConnGattTransRecv).WillOnce(Return(nullptr));
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);
}

/*
* @tc.name: NotificationReceiveCallback002
* @tc.desc: Test NotificationReceiveCallback
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, NotificationReceiveCallback002, TestSize.Level1)
{
    const char *bleAddr = "11:22:33:44:44:99";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 6, false);
    EXPECT_NE(NULL, bleConnection);

    bleConnection->buffer.seq = 0;
    bleConnection->buffer.total = 0;
    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusGattcNotify param = {
        .dataLen = 50,
        .charaUuid.uuidLen = strlen(SOFTBUS_CHARA_BLECONN_UUID),
    };
    param.charaUuid.uuid = (char *)SoftBusCalloc(param.charaUuid.uuidLen + 1);
    ret = strcpy_s(param.charaUuid.uuid, param.charaUuid.uuidLen + 1, SOFTBUS_CHARA_BLECONN_UUID);
    EXPECT_EQ(EOK, ret);

    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattTransRecv)
        .WillOnce(ConnectionBleClientInterfaceMock::ConnGattTransRecvReturnConnModule);
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);

    EXPECT_CALL(bleMock, ConnGattTransRecv)
        .WillOnce(ConnectionBleClientInterfaceMock::ConnGattTransRecvReturnOldNearby);
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);

    EXPECT_CALL(bleMock, ConnGattTransRecv).WillOnce(ConnectionBleClientInterfaceMock::ConnGattTransRecvReturnDefult);
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);
}

/*
* @tc.name: NotificationReceiveCallback002
* @tc.desc: Test NotificationReceiveCallback
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, NotificationReceiveCallback003, TestSize.Level1)
{
    const char *bleAddr = "11:22:33:44:22:99";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 7, false);
    EXPECT_NE(NULL, bleConnection);

    bleConnection->buffer.seq = 0;
    bleConnection->buffer.total = 0;
    bleConnection->state = BLE_CONNECTION_STATE_CONNECTED;
    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusGattcNotify param = {
        .dataLen = 50,
        .charaUuid.uuidLen = strlen(SOFTBUS_CHARA_BLENET_UUID),
    };
    param.charaUuid.uuid = (char *)SoftBusCalloc(param.charaUuid.uuidLen + 1);
    ret = strcpy_s(param.charaUuid.uuid, param.charaUuid.uuidLen + 1, SOFTBUS_CHARA_BLENET_UUID);
    EXPECT_EQ(EOK, ret);

    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattTransRecv)
        .WillOnce(ConnectionBleClientInterfaceMock::ConnGattTransRecvReturnConnModule);
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);

    bleConnection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, ConnGattTransRecv).WillOnce(ConnectionBleClientInterfaceMock::ActionOfConnGattTransRecv);
    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);
}


/*
* @tc.name: NotificationReceiveCallback004
* @tc.desc: Test NotificationReceiveCallback
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, NotificationReceiveCallback004, TestSize.Level1)
{
    const char *bleAddr = "11:22:33:44:22:03";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 8, false);
    EXPECT_NE(NULL, bleConnection);

    bleConnection->buffer.seq = 0;
    bleConnection->buffer.total = 0;
    bleConnection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusGattcNotify param = {
        .dataLen = 50,
        .charaUuid.uuidLen = strlen(SOFTBUS_CHARA_BLENET_UUID),
    };
    param.charaUuid.uuid = (char *)SoftBusCalloc(param.charaUuid.uuidLen + 1);
    ret = strcpy_s(param.charaUuid.uuid, param.charaUuid.uuidLen + 1, SOFTBUS_CHARA_BLENET_UUID);
    EXPECT_EQ(EOK, ret);

    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattTransRecv)
        .WillOnce(ConnectionBleClientInterfaceMock::ConnGattTransRecvReturnConnModule1);
    gattCb->notificationReceiveCallback(bleConnection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);

    const char *addr = "11:22:33:44:22:06";
    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 9, false);
    EXPECT_NE(NULL, connection);
    connection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, ConnGattTransRecv)
        .WillOnce(ConnectionBleClientInterfaceMock::ConnGattTransRecvReturnConnModule);
    gattCb->notificationReceiveCallback(connection->underlayerHandle, &param, SOFTBUS_OK);
    SoftBusSleepMs(500);
}

/*
* @tc.name: ConfigureMtuSizeCallback001
* @tc.desc: Test ConfigureMtuSizeCallback
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, ConfigureMtuSizeCallback001, TestSize.Level1)
{
    gattCb->configureMtuSizeCallback(100, 20, SOFTBUS_OK);
    SoftBusSleepMs(500);

    const char *bleAddr = "11:22:33:44:22:05";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 10, false);
    EXPECT_NE(NULL, bleConnection);
    int32_t ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    gattCb->configureMtuSizeCallback(bleConnection->underlayerHandle, 20, SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);
    SoftBusSleepMs(500);

    gattCb->configureMtuSizeCallback(bleConnection->underlayerHandle, 20, SOFTBUS_OK);
    SoftBusSleepMs(500);
    const char *addr = "11:22:33:44:22:06";
    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 11, false);
    EXPECT_NE(NULL, connection);
    connection->state = BLE_CONNECTION_STATE_MTU_SETTING;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(bleMock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    
    gattCb->configureMtuSizeCallback(connection->underlayerHandle, 21, SOFTBUS_OK);
        SoftBusSleepMs(500);
}

/*
* @tc.name: ConfigureMtuSizeCallback002
* @tc.desc: Test ConfigureMtuSizeCallback
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, ConfigureMtuSizeCallback002, TestSize.Level1)
{
    const char *addr = "11:22:33:44:22:05";
    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 12, false);
    EXPECT_NE(NULL, connection);
    connection->state = BLE_CONNECTION_STATE_MTU_SETTING;
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, LnnGetLocalNumInfo)
        .WillOnce(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    gattCb->configureMtuSizeCallback(connection->underlayerHandle, 21, SOFTBUS_OK);
    SoftBusSleepMs(500);

    const char *bleAddr = "11:22:33:44:22:56";
    ConnBleConnection *bleConnection = ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, 13, false);
    EXPECT_NE(NULL, bleConnection);
    bleConnection->state = BLE_CONNECTION_STATE_MTU_SETTING;
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_OK));
    gattCb->configureMtuSizeCallback(bleConnection->underlayerHandle, 21, SOFTBUS_OK);
    SoftBusSleepMs(500);

    const char *addrBle = "11:22:33:44:22:56";
    ConnBleConnection *connectionBle = ConnBleCreateConnection(addrBle, BLE_GATT, CONN_SIDE_CLIENT, 14, false);
    EXPECT_NE(NULL, connectionBle);
    connectionBle->state = BLE_CONNECTION_STATE_MTU_SETTING;
    ret = ConnBleSaveConnection(connectionBle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    gattCb->configureMtuSizeCallback(connectionBle->underlayerHandle, 22, SOFTBUS_OK);
    SoftBusSleepMs(500);
}

/*
* @tc.name: ClientConnectionTest001
* @tc.desc: Test ConnectionStateCallback for disconenct.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, ConnectionStateCallback003, TestSize.Level1)
{
    const char *addr = "12:23:33:44:55:67";
    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 110, false);
    ASSERT_NE(nullptr, connection);
    NiceMock<ConnectionBleClientInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices).WillRepeatedly(Return(SOFTBUS_OK));

    connection->fastestConnectEnable = true;
    connection->connectionRc = 0;
    connection->retrySearchServiceCnt = BLE_CLIENT_MAX_RETRY_SEARCH_SERVICE_TIMES;
    connection->state = BLE_CONNECTION_STATE_CONNECTING;
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    gattCb->connectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_CONNECT, SOFTBUS_OK);

    EXPECT_CALL(bleMock, SoftbusGattcSearchServices)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SEARCH_SERVICE_ERR));
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices)
        .WillRepeatedly(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SEARCH_SERVICE_ERR));
    gattCb->connectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_CONNECT, SOFTBUS_OK);
    
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices).WillRepeatedly(Return(SOFTBUS_OK));
    gattCb->connectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_CONNECT, SOFTBUS_OK);
    SoftBusSleepMs(500);
}
}