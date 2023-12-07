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

#include "connection_ble_mock.h"

#include <cstdio>
#include <cstring>

#include <gtest/gtest.h>
#include <securec.h>

#include "common_list.h"
#include "conn_log.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_conn_ble_server.h"
#include "softbus_conn_ble_client.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_connection.h"

using namespace testing::ext;
using namespace testing;
using namespace std;
namespace OHOS {

SoftBusGattsCallback *g_callback = nullptr;

extern "C" int SoftBusRegisterGattsCallbacks(SoftBusGattsCallback *callback)
{
    g_callback = callback;
    return SOFTBUS_OK;
}

extern "C"  GattService *CreateService(void)
{
    char array[16];
    GattService *gattService = (GattService *)SoftBusCalloc(sizeof(GattService));
    CONN_CHECK_AND_RETURN_RET_LOGE(gattService != NULL, NULL, CONN_BLE, "calloc gatt service failed");
    SoftBusBtUuid serviceUuid = {
        .uuid = array,
        .uuidLen = sizeof(array)/sizeof(array[0]),
    };
    SoftBusBtUuid connCharacteristicUuid = {
        .uuid = array,
        .uuidLen = sizeof(array)/sizeof(array[0]),
    };
    SoftBusBtUuid netUuid = {
        .uuid = array,
        .uuidLen = sizeof(array)/sizeof(array[0]),
    };
    SoftBusBtUuid descriptorUuid = {
        .uuid = array,
        .uuidLen = sizeof(array)/sizeof(array[0]),
    };
    gattService->serviceUuid = serviceUuid;
    gattService->connCharacteristicUuid = connCharacteristicUuid;
    gattService->netUuid = netUuid;
    gattService->descriptorUuid = descriptorUuid;
    return gattService;
}

class ServiceConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

void ServiceConnectionTest::SetUpTestCase()
{
    SoftbusConfigInit();
    ConnServerInit();
}

/*
* @tc.name: ServiceConnection001
* @tc.desc: Test ConnGattServerStartService.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection001, TestSize.Level1)
{
    int32_t ret;
    GattService *service = CreateService();
    EXPECT_NE(service, nullptr);
    GattServiceType serviceId = SOFTBUS_GATT_SERVICE;
    NiceMock<ConnectionBleInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftBusGattsAddService(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattServerStartService(service, serviceId);
    EXPECT_EQ(SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_ERR, ret);
}

/*
* @tc.name: ServiceConnection002
* @tc.desc: Test ConnGattServerStopService.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection002, TestSize.Level1)
{
    int32_t ret;
    NiceMock<ConnectionBleInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftBusGattsStopService).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattServerStopService(SOFTBUS_GATT_SERVICE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ServiceConnection003
* @tc.desc: Test ConnGattServerDisconnect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection003, TestSize.Level1)
{
    int32_t ret;
    ConnBleConnection connection;
    NiceMock<ConnectionBleInterfaceMock> bleMock;

    ret = ConnGattServerDisconnect(NULL);
    EXPECT_EQ(SOFTBUS_CONN_BLE_INTERNAL_ERR, ret);

    connection.underlayerHandle = INVALID_UNDERLAY_HANDLE;
    connection.connectionId = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnGattServerDisconnect(&connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    connection.underlayerHandle = 1;
    connection.connectionId = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_CALL(bleMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattServerDisconnect(&connection);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_CALL(bleMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftBusGattsDisconnect).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattServerDisconnect(&connection);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_CALL(bleMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftBusGattsDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ConnGattServerDisconnect(&connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ServiceConnection004
* @tc.desc: Test ConnGattServerConnect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection004, TestSize.Level1)
{
    int32_t ret;
    SoftBusGattWriteRequest writeCbPara;
    ConnBleConnection connection;
    (void)memset_s(&connection, sizeof(ConnBleConnection), 0, sizeof(ConnBleConnection));
    writeCbPara.needRsp = true;
    g_callback->RequestWriteCallback(writeCbPara);
    ret = ConnGattServerConnect(&connection);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    
    writeCbPara.needRsp = false;
    writeCbPara.attrHandle = -1;
    g_callback->RequestWriteCallback(writeCbPara);
    ret = SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    writeCbPara.needRsp = false;
    writeCbPara.attrHandle = 1;
    writeCbPara.connId = 1;
    g_callback->RequestWriteCallback(writeCbPara);
    connection.underlayerHandle = INVALID_UNDERLAY_HANDLE;
    ret = ConnGattServerConnect(&connection);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: ClientConnection001
* @tc.desc: Test ConnGattClientConnect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection001, TestSize.Level1)
{
    int32_t ret;
    ConnBleConnection connection;
    NiceMock<ConnectionBleInterfaceMock> bleMock;

    ret = ConnGattClientConnect(NULL);
    EXPECT_EQ(SOFTBUS_CONN_BLE_INTERNAL_ERR, ret);

    EXPECT_CALL(bleMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattClientConnect(&connection);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    connection.fastestConnectEnable = true;
    EXPECT_CALL(bleMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcConnect).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattClientConnect(&connection);
    EXPECT_EQ(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR, ret);

    SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_CALL(bleMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcConnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ConnGattClientConnect(&connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ClientConnection002
* @tc.desc: Test SwitchNotifacatedHandler.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection002, TestSize.Level1)
{
    int32_t ret;
    ConnBleConnection connection;
    bool grace = true;
    bool refreshGatt = true;
    NiceMock<ConnectionBleInterfaceMock> bleMock;

    ret = ConnGattClientDisconnect(NULL, grace, refreshGatt);
    EXPECT_EQ(SOFTBUS_CONN_BLE_INTERNAL_ERR, ret);

    connection.underlayerHandle = INVALID_UNDERLAY_HANDLE;
    connection.connectionId = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnGattClientDisconnect(&connection, grace, refreshGatt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    connection.underlayerHandle = 1;
    connection.connectionId = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_CALL(bleMock, BleGattcDisconnect).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattClientDisconnect(&connection, grace, refreshGatt);
    EXPECT_EQ(SOFTBUS_GATTC_INTERFACE_FAILED, ret);

    connection.underlayerHandle = 1;
    connection.connectionId = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_CALL(bleMock, BleGattcDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ConnGattClientDisconnect(&connection, grace, refreshGatt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ClientConnection003
* @tc.desc: Test ConnGattClientUpdatePriority.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection003, TestSize.Level1)
{
    int32_t ret;
    ConnBleConnection connection;
    ConnectBlePriority priority;
    NiceMock<ConnectionBleInterfaceMock> bleMock;

    priority = CONN_BLE_PRIORITY_BALANCED;
    ret = ConnGattClientUpdatePriority(NULL, priority);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    connection.underlayerHandle = 1;
    connection.connectionId = 1;
    connection.state = BLE_CONNECTION_STATE_CONNECTING;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnGattClientUpdatePriority(&connection, priority);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    connection.state = BLE_CONNECTION_STATE_SERVICE_SEARCHING;
    EXPECT_CALL(bleMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_ERR));
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnGattClientUpdatePriority(&connection, priority);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
}
