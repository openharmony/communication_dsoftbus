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
#include "connection_ble_mock.h"
#include "common_list.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_server.h"
#include "softbus_conn_ble_server.c"
#include "softbus_conn_ble_client.c"

using namespace testing::ext;
using namespace testing;
namespace OHOS {
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
    int ret;
    NiceMock<ConnectionBleInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftBusGattsAddService).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattServerStartService();
    EXPECT_EQ(SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_ERR, ret);
}

/*
* @tc.name: ServiceConnection002
* @tc.desc: Test ConnGattServerStartService.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection002, TestSize.Level1)
{
    int ret;
    NiceMock<ConnectionBleInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftBusGattsStopService).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattServerStopService();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ServiceConnection003
* @tc.desc: Test ConnGattServerStartService.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection003, TestSize.Level1)
{
    int ret;
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
* @tc.desc: Test ConnGattServerStartService.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection004, TestSize.Level1)
{
    int ret;

    ret = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_ADDING, BLE_SERVER_STATE_SERVICE_ADDING);
    EXPECT_EQ(SOFTBUS_CONN_BLE_SERVER_STATE_UNEXPECTED_ERR, ret);

    ret = UpdateBleServerStateInOrder(BLE_SERVER_STATE_INITIAL, BLE_SERVER_STATE_SERVICE_ADDING);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ServiceConnection005
* @tc.desc: Test ConnGattServerConnect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection005, TestSize.Level1)
{
    int ret;
    ConnBleConnection connection;

    SoftBusMutexInit(&connection.lock, nullptr);
    connection.underlayerHandle = INVALID_UNDERLAY_HANDLE;
    ret = ConnGattServerConnect(&connection);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    connection.underlayerHandle = 1;
    ret = ConnGattServerConnect(&connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ServiceConnection007
* @tc.desc: Test ConnGattServerStartService.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection006, TestSize.Level1)
{
    SoftBusGattWriteRequest writeCbPara;

    writeCbPara.needRsp = true;
    BleRequestWriteCallback(writeCbPara);

    writeCbPara.needRsp = false;
    writeCbPara.attrHandle = -1;
    BleRequestWriteCallback(writeCbPara);

    writeCbPara.needRsp = false;
    writeCbPara.attrHandle = 1;
    writeCbPara.connId = 1;
    BleRequestWriteCallback(writeCbPara);
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
    int ret;
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
}