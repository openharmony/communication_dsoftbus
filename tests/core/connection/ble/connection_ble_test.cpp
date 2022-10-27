/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "common_list.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_ble_connection.c"

using namespace testing::ext;
namespace OHOS {
static uint32_t g_connId;

void ConnectedCB(unsigned int connectionId, const ConnectionInfo *info)
{
    if (info->type == CONNECT_BLE) {
        g_connId = connectionId;
    }
}

void DisConnectCB(unsigned int connectionId, const ConnectionInfo *info) {}
void DataReceivedCB(unsigned int connectionId, ConnModule moduleId, int64_t seq, char *data, int len) {}

class ConnectionBleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

void ConnectionBleTest::SetUpTestCase()
{
    SoftbusConfigInit();
    ConnServerInit();
    LooperInit();
    BleConnLooperInit();
    SoftBusMutexAttr attr;
    attr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&g_connectionLock, &attr);
    BleQueueInit();
}

/*
* @tc.name: ManagerTest001
* @tc.desc: test ConnTypeIsSupport
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, ManagerTest001, TestSize.Level1)
{
    int ret;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ManagerTest001");
    ret = ConnTypeIsSupport(CONNECT_BLE);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: ManagerTest002
* @tc.desc: test invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, ManagerTest002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ManagerTest002");
    int ret = ConnSetConnectCallback(static_cast<ConnModule>(0), nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnConnectDevice(nullptr, 0, nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnDisconnectDevice(0);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnPostBytes(0, nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnStartLocalListening(nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnStopLocalListening(nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ConnUnSetConnectCallback(static_cast<ConnModule>(0));
    EXPECT_EQ(SOFTBUS_OK, SOFTBUS_OK);
}

/*
* @tc.name: ManagerTest003
* @tc.desc: test set unset callback and post disconnect without connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, ManagerTest003, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ManagerTest003");
    ConnectCallback connCb;
    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    int ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
}

/*
* @tc.name: ManagerTest004
* @tc.desc: Test start stop listening.
* @tc.in: Test module, Test number,Test Levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnStartLocalListening and ConnStopLocalListening operates normally.
*/
HWTEST_F(ConnectionBleTest, ManagerTest004, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ManagerTest004");
    ConnectCallback connCb;
    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    int ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LocalListenerInfo info;
    info.type = CONNECT_BLE;
    ret = ConnStartLocalListening(&info);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ConnStopLocalListening(&info);
    EXPECT_NE(ret, SOFTBUS_OK);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
}

/*
* @tc.name: ManagerTest005
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, ManagerTest005, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ManagerTest005");
    int ret = ConnTypeIsSupport(CONNECT_P2P);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);
}

/*
* @tc.name: ManagerTest006
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, ManagerTest006, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ManagerTest006");
    int ret = ConnTypeIsSupport(CONNECT_BR);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: ManagerTest007
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, ManagerTest007, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ManagerTest007");
    int ret = ConnTypeIsSupport(CONNECT_TCP);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: PackRequest
 * @tc.desc: test reference process is valid
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(ConnectionBleTest, PackRequest, TestSize.Level1)
{
    BleConnectionInfo *info = CreateBleConnectionNode();
    info->refCount = CONNECT_REF_INCRESE;
    ListAdd(&g_connection_list, &info->node);
    PackRequest(CONNECT_REF_DECRESE, info->connId);
    EXPECT_EQ(info->state, BLE_CONNECTION_STATE_CLOSING);

    ListDelete(&info->node);
    SoftBusFree(info);
}

/*
 * @tc.name: OnPackResponse
 * @tc.desc: test reference process is valid
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(ConnectionBleTest, OnPackResponse, TestSize.Level1)
{
    BleConnectionInfo *info = CreateBleConnectionNode();
    info->state = BLE_CONNECTION_STATE_CLOSING;
    ListAdd(&g_connection_list, &info->node);
    OnPackResponse(CONNECT_REF_INCRESE, CONNECT_REF_INCRESE, info->connId);
    EXPECT_EQ(info->state, BLE_CONNECTION_STATE_CONNECTED);

    ListDelete(&info->node);
    SoftBusFree(info);
}

/*
 * @tc.name: BleConnectionMsgHandler
 * @tc.desc: test message handle function
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(ConnectionBleTest, BleConnectionMsgHandler, TestSize.Level1)
{
    SoftBusMessage *message = MallocMessage();
    message->what = BLE_CONNECTION_DISCONNECT_OUT;
    BleConnectionMsgHandler(message);

    BleConnectionInfo *info = CreateBleConnectionNode();
    info->state = BLE_CONNECTION_STATE_CLOSED;
    ListAdd(&g_connection_list, &info->node);
    message->arg1 = info->connId;
    BleConnectionMsgHandler(message);
    EXPECT_EQ(info->state, BLE_CONNECTION_STATE_CLOSED);

    FreeMessage(message);
    ListDelete(&info->node);
    SoftBusFree(info);
}

/*
 * @tc.name: BleConnectionRemoveMessageFunc
 * @tc.desc: remove message function
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(ConnectionBleTest, BleConnectionRemoveMessageFunc, TestSize.Level1)
{
    int64_t clientId = INT32_MAX;
    SoftBusMessage *message = MallocMessage();
    message->what = BLE_CONNECTION_DISCONNECT_OUT;
    message->arg1 = clientId;
    BleConnectionRemoveMessageFunc(message, &clientId);
}
}