/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_ble_conflict.h"
#include "bus_center_info_key.h"
#include "softbus_conn_ble_manager.h"
#include "ble_protocol_interface_factory.h"
#include "connection_ble_client_mock.h"

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

int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    return SOFTBUS_OK;
}

void SoftbusBleConflictRegisterListener(SoftBusBleConflictListener *listener)
{
    (void)listener;
}

int32_t ConnBlePostBytesInner(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq,
    PostBytesFinishAction postBytesFinishAction)
{
    return SOFTBUS_OK;
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return SOFTBUS_OK;
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
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

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    (void)info;
    (void)key;
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
    void TearDown() {}
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
    SoftBusSleepMs(3500); // to call timeout event
    EXPECT_EQ(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR, ret);

    EXPECT_CALL(bleMock, SoftbusGattcSetFastestConn).WillRepeatedly(Return(
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    EXPECT_CALL(bleMock, SoftbusGattcConnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ConnGattClientConnect(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    connection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    gattCb->ConnectionStateCallback(connection->underlayerHandle, 5, SOFTBUS_OK);
    gattCb->ConnectionStateCallback(0, SOFTBUS_BT_CONNECT, SOFTBUS_OK);

    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect).WillRepeatedly(Return(
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    gattCb->ConnectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_DISCONNECT,
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);

    connection->state = BLE_CONNECTION_STATE_SERVICE_SEARCHING;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    gattCb->ConnectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_DISCONNECT,
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);
    gattCb->ConnectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_CONNECT,
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);

    gattCb->ConnectionStateCallback(connection->underlayerHandle, SOFTBUS_BT_CONNECT,
        SOFTBUS_OK);
}

/*
* @tc.name: ClientConnectionTest001
* @tc.desc: Test ConnectionStateCallback for connect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientConnectionTest, ConnectionStateCallback002, TestSize.Level1)
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

    gattCb->ServiceCompleteCallback(10, SOFTBUS_OK);
    gattCb->ServiceCompleteCallback(connection->underlayerHandle, SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR);
    SoftBusSleepMs(500);
}
}
