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
#include "softbus_conn_ble_manager.c"

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
* @tc.desc: Test BleGattcNotificationReceiveCallback.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection002, TestSize.Level1)
{
    int32_t underlayerHandle = 1;
    SoftBusBtAddr addr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
    };
    BleConnectServerCallback(underlayerHandle, &addr);
}

/*
* @tc.name: ServiceConnection003
* @tc.desc: Test ConnGattServerStopService.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection003, TestSize.Level1)
{
    int ret;
    NiceMock<ConnectionBleInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, SoftBusGattsStopService).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattServerStopService();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ServiceConnection004
* @tc.desc: Test BleServiceDeleteMsgHandler.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection004, TestSize.Level1)
{
    CommonStatusMsgContext ctx;
    ctx.status = -1;
    BleServiceDeleteMsgHandler(&ctx);
}

/*
* @tc.name: ServiceConnection005
* @tc.desc: Test ConnGattServerDisconnect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection005, TestSize.Level1)
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
* @tc.name: ServiceConnection006
* @tc.desc: Test BleRequestWriteCallback.
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
* @tc.name: ServiceConnection007
* @tc.desc: Test UpdateBleServerStateInOrder.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection007, TestSize.Level1)
{
    int ret;

    ret = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_ADDING, BLE_SERVER_STATE_SERVICE_ADDING);
    EXPECT_EQ(SOFTBUS_CONN_BLE_SERVER_STATE_UNEXPECTED_ERR, ret);

    ret = UpdateBleServerStateInOrder(BLE_SERVER_STATE_INITIAL, BLE_SERVER_STATE_SERVICE_ADDING);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ServiceConnection008
* @tc.desc: Test ConnGattServerConnect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection008, TestSize.Level1)
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
* @tc.name: ServiceConnection009
* @tc.desc: Test BleCompareGattServerLooperEventFunc.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ServiceConnection009, TestSize.Level1)
{
    int ret;
    SoftBusMessage msg;
    SoftBusMessage args;

    msg.what = MSG_SERVER_WAIT_MTU_TIMEOUT;
    args.what = MSG_SERVER_WAIT_DICONNECT_TIMEOUT;
    ret = BleCompareGattServerLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_FAILED, ret);


    msg.what = MSG_SERVER_WAIT_DICONNECT_TIMEOUT;
    args.what = MSG_SERVER_WAIT_DICONNECT_TIMEOUT;
    msg.arg1 = 10;
    args.arg1 = 10;
    ret = BleCompareGattServerLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_SUCCESS, ret);

    msg.what = MSG_SERVER_WAIT_DICONNECT_TIMEOUT;
    args.what = MSG_SERVER_WAIT_DICONNECT_TIMEOUT;
    msg.arg1 = 9;
    args.arg1 = 10;
    ret = BleCompareGattServerLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_SERVER_WAIT_START_SERVER_TIMEOUT;
    args.what = MSG_SERVER_WAIT_START_SERVER_TIMEOUT;
    args.arg1 = 0;
    args.arg2 = 0;
    args.obj = nullptr;
    ret = BleCompareGattServerLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_SUCCESS, ret);
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

/*
* @tc.name: ClientConnection002
* @tc.desc: Test BleGattcConnStateCallback.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection002, TestSize.Level1)
{
    int32_t underlayerHandle = 1;
    int32_t state = SOFTBUS_BT_CONNECT;
    int32_t status = 0;

    BleGattcConnStateCallback(underlayerHandle, state, status);
    state = SOFTBUS_BT_STATUS_SUCCESS;
    BleGattcConnStateCallback(underlayerHandle, state, status);
}

/*
* @tc.name: ClientConnection003
* @tc.desc: Test ConnectedMsgHandler.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection003, TestSize.Level1)
{
    CommonStatusContext ctx;
    ConnBleConnection connection;
    NiceMock<ConnectionBleInterfaceMock> bleMock;

    ctx.underlayerHandle = 1;
    ctx.status = 0;
    SoftBusMutexDestroy(&g_bleManager.connections->lock);
    ConnectedMsgHandler(&ctx);
    ctx.status = -1;
    ctx.underlayerHandle = 1;
    connection.underlayerHandle = 1;
    SoftBusMutexInit(&g_bleManager.connections->lock, nullptr);
    ListInit(&g_bleManager.connections->list);
    ListTailInsert(&g_bleManager.prevents->list, &connection.node);
    ConnectedMsgHandler(&ctx);
}

/*
* @tc.name: ClientConnection004
* @tc.desc: Test RetrySearchService.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection004, TestSize.Level1)
{
    int ret;
    ConnBleConnection connection;
    RetrySearchServiceReason reason;
    connection.state = BLE_CONNECTION_STATE_MTU_SETTING;
    reason = BLE_CLIENT_REGISTER_NOTIFICATION_ERR;
    connection.retrySearchServiceCnt = -1;
    connection.underlayerHandle = 1;
    NiceMock<ConnectionBleInterfaceMock> bleMock;

    SoftBusMutexInit(&connection.lock, nullptr);
    ret = RetrySearchService(&connection, reason);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    SoftBusMutexInit(&connection.lock, nullptr);
    connection.state = BLE_CONNECTION_STATE_CONNECTED;
    reason = BLE_CLIENT_REGISTER_NOTIFICATION_ERR;
    connection.retrySearchServiceCnt = 0;
    connection.underlayerHandle = 1;
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = RetrySearchService(&connection, reason);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    SoftBusMutexInit(&connection.lock, nullptr);
    connection.state = BLE_CONNECTION_STATE_CONNECTED;
    reason = BLE_CLIENT_REGISTER_NOTIFICATION_ERR;
    connection.retrySearchServiceCnt = 0;
    connection.underlayerHandle = 1;
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = RetrySearchService(&connection, reason);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    SoftBusMutexInit(&connection.lock, nullptr);
    connection.state = BLE_CONNECTION_STATE_CONNECTED;
    reason = BLE_CLIENT_REGISTER_NOTIFICATION_ERR;
    connection.retrySearchServiceCnt = 0;
    connection.underlayerHandle = 1;
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices).WillRepeatedly(Return(SOFTBUS_OK));
    ret = RetrySearchService(&connection, reason);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ClientConnection005
* @tc.desc: Test SearchedMsgHandler.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection005, TestSize.Level1)
{
    CommonStatusContext ctx;

    ctx.underlayerHandle = -1;
    ctx.status = 0;
    SearchedMsgHandler(&ctx);

    ctx.underlayerHandle = 1;
    ctx.status = -1;
    SearchedMsgHandler(&ctx);
}

/*
* @tc.name: ClientConnection006
* @tc.desc: Test SwitchNotifacatedHandler.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection006, TestSize.Level1)
{
    int ret;
    ConnBleConnectionState state;
    CommonStatusContext ctx;
    ConnBleConnection connection;
    NiceMock<ConnectionBleInterfaceMock> bleMock;

    state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    ctx.underlayerHandle = 1;
    connection.state = BLE_CONNECTION_STATE_CONN_NOTIFICATED;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = SwitchNotifacatedHandler(state, &ctx, &connection);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CLIENT_STATE_UNEXPECTED_ERR, ret);

    state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    ctx.underlayerHandle = -1;
    connection.state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    connection.retrySearchServiceCnt = 0;
    connection.underlayerHandle = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_CALL(bleMock, SoftbusGattcRefreshServices).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, SoftbusGattcSearchServices).WillRepeatedly(Return(SOFTBUS_OK));
    ret = SwitchNotifacatedHandler(state, &ctx, &connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    ctx.underlayerHandle = 1;
    connection.state = BLE_CONNECTION_STATE_CONN_NOTIFICATING;
    connection.retrySearchServiceCnt = 0;
    connection.underlayerHandle = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = SwitchNotifacatedHandler(state, &ctx, &connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    state = BLE_CONNECTION_STATE_NET_NOTIFICATING;
    ctx.underlayerHandle = -1;
    connection.state = BLE_CONNECTION_STATE_NET_NOTIFICATING;
    connection.retrySearchServiceCnt = 0;
    connection.underlayerHandle = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = SwitchNotifacatedHandler(state, &ctx, &connection);
    EXPECT_EQ(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONFIGURE_MTU_ERR, ret);
}

/*
* @tc.name: ClientConnection007
* @tc.desc: Test SwitchNotifacatedHandler.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection007, TestSize.Level1)
{
    int ret;
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
    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = ConnGattClientDisconnect(&connection, grace, refreshGatt);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    connection.underlayerHandle = 1;
    connection.connectionId = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    EXPECT_CALL(bleMock, SoftbusBleGattcDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ConnGattClientDisconnect(&connection, grace, refreshGatt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ClientConnection008
* @tc.desc: Test ConnGattClientUpdatePriority.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection008, TestSize.Level1)
{
    int ret;
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

/*
* @tc.name: ClientConnection009
* @tc.desc: Test ConnGattClientUpdatePriority.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ServiceConnectionTest, ClientConnection009, TestSize.Level1)
{
    int32_t underlayerHandle = 1;
    int32_t status = -1;
    SoftBusGattcNotify param;
    BleGattcNotificationReceiveCallback(underlayerHandle, &param, status);

    underlayerHandle = 1;
    status = 0;
    param.data = nullptr;
    param.dataLen = 0;
    BleGattcNotificationReceiveCallback(underlayerHandle, &param, status);
}

HWTEST_F(ServiceConnectionTest, ClientConnection0010, TestSize.Level1)
{
    int ret;
    SoftBusMessage msg;
    SoftBusMessage args;

    msg.what = MSG_CLIENT_NOTIFICATED;
    args.what = MSG_CLIENT_DISCONNECTED;
    ret = BleCompareGattClientLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_FAILED, ret);


    msg.what = MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT;
    args.what = MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT;
    msg.arg1 = 10;
    args.arg1 = 10;
    ret = BleCompareGattClientLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_SUCCESS, ret);

    msg.what = MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT;
    args.what = MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT;
    msg.arg1 = 9;
    args.arg1 = 10;
    ret = BleCompareGattClientLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_CLIENT_DISCONNECTED;
    args.what = MSG_CLIENT_DISCONNECTED;
    args.arg1 = 0;
    args.arg2 = 0;
    args.obj = nullptr;
    ret = BleCompareGattClientLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_SUCCESS, ret);
}
}