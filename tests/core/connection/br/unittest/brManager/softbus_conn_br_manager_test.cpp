/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>

#include "common_list.h"
#include "conn_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_manager.h"
#include "softbus_conn_br_manager_test_mock.h"
#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_br_send_queue.h"
#include "softbus_conn_common.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "wrapper_br_interface.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {

static ConnectCallback g_testCallback;
static ConnectFuncInterface *g_brInterface = nullptr;
static bool g_onConnectedCalled = false;
static bool g_onDisconnectedCalled = false;
static bool g_onDataReceivedCalled = false;
static uint32_t g_lastConnectionId = 0;
static int32_t g_lastReason = 0;
static ConnectionInfo g_lastConnInfo = {};

static void TestOnConnectSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    (void)requestId;
}

static void TestOnConnectFailed(uint32_t requestId, int32_t reason)
{
    g_lastReason = reason;
    (void)requestId;
}

static void TestOnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

static void TestOnDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    g_onDisconnectedCalled = true;
    g_lastConnectionId = connectionId;
    (void)info;
}

static void TestOnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    g_onDataReceivedCalled = true;
    g_lastConnectionId = connectionId;
    (void)moduleId;
    (void)seq;
    (void)data;
    (void)len;
}

static void TestOnReusedConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

class BrManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    static bool isInited_;
    static ConnBrConnection* CreateConnectionAndSave(const char *mac, ConnSideType side, int32_t socketHandle);
};

bool BrManagerTest::isInited_ = false;

void BrManagerTest::SetUpTestCase(void)
{
    LooperInit();
    SoftbusConfigInit();
    
    g_testCallback.OnConnected = TestOnConnected;
    g_testCallback.OnReusedConnected = TestOnReusedConnected;
    g_testCallback.OnDisconnected = TestOnDisconnected;
    g_testCallback.OnDataReceived = TestOnDataReceived;
}

void BrManagerTest::TearDownTestCase(void)
{
    if (isInited_) {
        isInited_ = false;
    }
    LooperDeinit();
}

void BrManagerTest::SetUp(void)
{
    g_onConnectedCalled = false;
    g_onDisconnectedCalled = false;
    g_onDataReceivedCalled = false;
    g_lastConnectionId = 0;
    g_lastReason = 0;
    g_brInterface = nullptr;
    (void)memset_s(&g_lastConnInfo, sizeof(g_lastConnInfo), 0, sizeof(g_lastConnInfo));
}

void BrManagerTest::TearDown(void)
{
}

ConnBrConnection* BrManagerTest::CreateConnectionAndSave(const char *mac, ConnSideType side, int32_t socketHandle)
{
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, ActionOfConnBrCreateConnection(_, _, _))
        .WillRepeatedly(Invoke([](const char *addr, ConnSideType s, int32_t handle) -> ConnBrConnection* {
            ConnBrConnection *conn = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
            if (conn != nullptr) {
                static uint32_t g_connectionId = 1;
                conn->connectionId = g_connectionId++;
                conn->side = s;
                conn->socketHandle = handle;
                if (addr != nullptr) {
                    (void)memcpy_s(conn->addr, BT_MAC_LEN, addr, BT_MAC_LEN);
                }
                SoftBusMutexInit(&conn->lock, nullptr);
                ListInit(&conn->node);
                conn->connectionRc = 1;
                conn->state = BR_CONNECTION_STATE_CONNECTING;
            }
            return conn;
        }));
    
    ConnBrConnection *connection = ConnBrCreateConnection(mac, side, socketHandle);
    if (connection != nullptr) {
        ConnBrSaveConnection(connection);
    }
    return connection;
}

/*
* @tc.name: CONN_INIT_BR_FAIL_002
* @tc.desc: Test ConnInitBr - callback null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_INIT_BR_FAIL_002, TestSize.Level1)
{
    g_brInterface = ConnInitBr(nullptr);
    EXPECT_EQ(g_brInterface, nullptr);
}

/*
* @tc.name: CONN_INIT_BR_FAIL_003
* @tc.desc: Test ConnInitBr - invalid callback (OnConnected null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_INIT_BR_FAIL_003, TestSize.Level1)
{
    ConnectCallback invalidCallback = {0};
    invalidCallback.OnConnected = nullptr;
    invalidCallback.OnReusedConnected = TestOnReusedConnected;
    invalidCallback.OnDisconnected = TestOnDisconnected;
    invalidCallback.OnDataReceived = TestOnDataReceived;
    
    g_brInterface = ConnInitBr(&invalidCallback);
    EXPECT_EQ(g_brInterface, nullptr);
}

/*
* @tc.name: CONN_INIT_BR_FAIL_004
* @tc.desc: Test ConnInitBr - invalid callback (OnDisconnected null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_INIT_BR_FAIL_004, TestSize.Level1)
{
    ConnectCallback invalidCallback = {0};
    invalidCallback.OnConnected = TestOnConnected;
    invalidCallback.OnReusedConnected = TestOnReusedConnected;
    invalidCallback.OnDisconnected = nullptr;
    invalidCallback.OnDataReceived = TestOnDataReceived;
    
    g_brInterface = ConnInitBr(&invalidCallback);
    EXPECT_EQ(g_brInterface, nullptr);
}

/*
* @tc.name: CONN_INIT_BR_FAIL_005
* @tc.desc: Test ConnInitBr - invalid callback (OnDataReceived null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_INIT_BR_FAIL_005, TestSize.Level1)
{
    ConnectCallback invalidCallback = {0};
    invalidCallback.OnConnected = TestOnConnected;
    invalidCallback.OnReusedConnected = TestOnReusedConnected;
    invalidCallback.OnDisconnected = TestOnDisconnected;
    invalidCallback.OnDataReceived = nullptr;
    
    g_brInterface = ConnInitBr(&invalidCallback);
    EXPECT_EQ(g_brInterface, nullptr);
}

/*
* @tc.name: CONN_INIT_BR_FAIL_006
* @tc.desc: Test ConnInitBr - init looper fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_INIT_BR_FAIL_006, TestSize.Level1)
{
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, ConnBrConnectionMuduleInit(_, _, _)).WillRepeatedly(Return(SOFTBUS_CONN_BR_INTERNAL_ERR));
    
    g_brInterface = ConnInitBr(&g_testCallback);
    EXPECT_EQ(g_brInterface, nullptr);
}

/*
* @tc.name: CONN_INIT_BR_FAIL_007
* @tc.desc: Test ConnInitBr - init manager fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_INIT_BR_FAIL_007, TestSize.Level1)
{
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, ConnBrConnectionMuduleInit(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnBrTransMuduleInit(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusAddBtStateListener(_, _)).WillRepeatedly(Return(SOFTBUS_CONN_BR_INTERNAL_ERR));
    
    g_brInterface = ConnInitBr(&g_testCallback);
    EXPECT_EQ(g_brInterface, nullptr);
}

/*
* @tc.name: CONN_INIT_BR_FAIL_008
* @tc.desc: Test ConnInitBr - init pending packet fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_INIT_BR_FAIL_008, TestSize.Level1)
{
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, ConnBrConnectionMuduleInit(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnBrTransMuduleInit(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusAddBtStateListener(_, _)).WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, ConnBrInitBrPendingPacket()).WillRepeatedly(Return(SOFTBUS_MALLOC_ERR));
    
    g_brInterface = ConnInitBr(&g_testCallback);
    EXPECT_EQ(g_brInterface, nullptr);
}

/*
* @tc.name: CONN_INIT_BR_SUCCESS_001
* @tc.desc: Test ConnInitBr success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_INIT_BR_SUCCESS_001, TestSize.Level1)
{
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InitSppSocketDriver()).WillRepeatedly(Return(reinterpret_cast<SppSocketDriver *>(1)));
    EXPECT_CALL(mock, SoftBusAddBtStateListener(_, _)).WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, ConnBrConnectionMuduleInit(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnBrTransMuduleInit(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnBrInitBrPendingPacket()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, BrHiDumperRegister()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ActionOfConnBrCreateConnection(_, _, _)).WillRepeatedly(Return(nullptr));
    
    g_brInterface = ConnInitBr(&g_testCallback);
    EXPECT_NE(g_brInterface, nullptr);
    isInited_ = (g_brInterface != nullptr);
}

/*
* @tc.name: INTERFACE_CONNECT_DEVICE_009
* @tc.desc: Test ConnectDevice - invalid param (option null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CONNECT_DEVICE_009, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = g_brInterface->ConnectDevice(nullptr, 1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_CONNECT_DEVICE_010
* @tc.desc: Test ConnectDevice - invalid param (result null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CONNECT_DEVICE_010, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    
    int32_t ret = g_brInterface->ConnectDevice(&option, 1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_CONNECT_DEVICE_011
* @tc.desc: Test ConnectDevice - invalid mac
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CONNECT_DEVICE_011, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    
    ConnectResult result = {
        .OnConnectSuccessed = TestOnConnectSuccessed,
        .OnConnectFailed = TestOnConnectFailed,
    };
    
    int32_t ret = g_brInterface->ConnectDevice(&option, 1, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_CONNECT_DEVICE_FAIL_012
* @tc.desc: Test ConnectDevice - invalid type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CONNECT_DEVICE_FAIL_012, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BLE;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "AA:BB:CC:DD:EE:FF", strlen("AA:BB:CC:DD:EE:FF"));
    
    ConnectResult result = {
        .OnConnectSuccessed = TestOnConnectSuccessed,
        .OnConnectFailed = TestOnConnectFailed,
    };
    
    int32_t ret = g_brInterface->ConnectDevice(&option, 1, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_CONNECT_DEVICE_FAIL_013
* @tc.desc: Test ConnectDevice - invalid callback (OnConnectSuccessed null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CONNECT_DEVICE_FAIL_013, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "AA:BB:CC:DD:EE:FF", strlen("AA:BB:CC:DD:EE:FF"));
    
    ConnectResult result = {
        .OnConnectSuccessed = nullptr,
        .OnConnectFailed = TestOnConnectFailed,
    };
    
    int32_t ret = g_brInterface->ConnectDevice(&option, 1, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_CONNECT_DEVICE_FAIL_014
* @tc.desc: Test ConnectDevice - invalid callback (OnConnectFailed null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CONNECT_DEVICE_FAIL_014, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "AA:BB:CC:DD:EE:FF", strlen("AA:BB:CC:DD:EE:FF"));
    
    ConnectResult result = {
        .OnConnectSuccessed = TestOnConnectSuccessed,
        .OnConnectFailed = nullptr,
    };
    
    int32_t ret = g_brInterface->ConnectDevice(&option, 1, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_CONNECT_DEVICE_SUCCESS_015
* @tc.desc: Test ConnectDevice - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CONNECT_DEVICE_SUCCESS_015, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, ConnBrCreateBrPendingPacket(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ActionOfConnBrCreateConnection(_, _, _))
        .WillRepeatedly(Invoke([](const char *addr, ConnSideType side, int32_t handle) -> ConnBrConnection* {
            ConnBrConnection *conn = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
            if (conn != nullptr) {
                static uint32_t g_connectionId = 100;
                conn->connectionId = g_connectionId++;
                conn->side = side;
                conn->socketHandle = handle;
                if (addr != nullptr) {
                    (void)memcpy_s(conn->addr, BT_MAC_LEN, addr, BT_MAC_LEN);
                }
                SoftBusMutexInit(&conn->lock, nullptr);
                ListInit(&conn->node);
                conn->connectionRc = 1;
            }
            return conn;
        }));
    EXPECT_CALL(mock, ConnBrConnect(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnBrEnqueueNonBlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "AA:BB:CC:DD:EE:FF", strlen("AA:BB:CC:DD:EE:FF"));
    
    ConnectResult result = {
        .OnConnectSuccessed = TestOnConnectSuccessed,
        .OnConnectFailed = TestOnConnectFailed,
    };
    
    int32_t ret = g_brInterface->ConnectDevice(&option, 1, &result);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: INTERFACE_POST_BYTES_016
* @tc.desc: Test PostBytes - invalid param (connectionId 0)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_POST_BYTES_016, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = g_brInterface->PostBytes(0, nullptr, 0, 1, 0, MODULE_CONNECTION, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_DISCONNECT_DEVICE_022
* @tc.desc: Test DisconnectDevice - connection not found
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_DISCONNECT_DEVICE_022, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = g_brInterface->DisconnectDevice(99999);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

/*
* @tc.name: INTERFACE_DISCONNECT_DEVICE_SUCCESS_023
* @tc.desc: Test DisconnectDevice - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_DISCONNECT_DEVICE_SUCCESS_023, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrConnection *conn = CreateConnectionAndSave("33:44:55:66:77:88", CONN_SIDE_CLIENT, 200);
    ASSERT_NE(conn, nullptr);
    
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, ActionOfConnBrUpdateConnectionRc(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnBrEnqueueNonBlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    
    int32_t ret = g_brInterface->DisconnectDevice(conn->connectionId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrRemoveConnection(conn);
    ConnBrReturnConnection(&conn);
}

/*
* @tc.name: INTERFACE_DISCONNECT_DEVICE_NOW_024
* @tc.desc: Test DisconnectDeviceNow - connection not found
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_DISCONNECT_DEVICE_NOW_024, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "AA:BB:CC:DD:EE:FF", strlen("AA:BB:CC:DD:EE:FF"));
    
    int32_t ret = g_brInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

/*
* @tc.name: INTERFACE_DISCONNECT_DEVICE_NOW_FAIL_025
* @tc.desc: Test DisconnectDeviceNow - invalid param (option null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_DISCONNECT_DEVICE_NOW_FAIL_025, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = g_brInterface->DisconnectDeviceNow(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_DISCONNECT_DEVICE_NOW_FAIL_026
* @tc.desc: Test DisconnectDeviceNow - invalid type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_DISCONNECT_DEVICE_NOW_FAIL_026, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BLE;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    
    int32_t ret = g_brInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_DISCONNECT_DEVICE_NOW_SUCCESS_027
* @tc.desc: Test DisconnectDeviceNow - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_DISCONNECT_DEVICE_NOW_SUCCESS_027, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrConnection *conn = CreateConnectionAndSave("44:55:66:77:88:99", CONN_SIDE_CLIENT, 300);
    ASSERT_NE(conn, nullptr);
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "44:55:66:77:88:99", strlen("44:55:66:77:88:99"));
    
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, ActionOfConnBrDisconnectNow(_)).WillRepeatedly(Return(SOFTBUS_OK));
    
    int32_t ret = g_brInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrRemoveConnection(conn);
    ConnBrReturnConnection(&conn);
}

/*
* @tc.name: INTERFACE_GET_CONNECTION_INFO_028
* @tc.desc: Test GetConnectionInfo - connection not found
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_GET_CONNECTION_INFO_028, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    
    int32_t ret = g_brInterface->GetConnectionInfo(99999, &info);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

/*
* @tc.name: INTERFACE_GET_CONNECTION_INFO_FAIL_029
* @tc.desc: Test GetConnectionInfo - invalid param (info null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_GET_CONNECTION_INFO_FAIL_029, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = g_brInterface->GetConnectionInfo(1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_GET_CONNECTION_INFO_SUCCESS_030
* @tc.desc: Test GetConnectionInfo - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_GET_CONNECTION_INFO_SUCCESS_030, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrConnection *conn = CreateConnectionAndSave("55:66:77:88:99:AA", CONN_SIDE_CLIENT, 400);
    ASSERT_NE(conn, nullptr);
    
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    
    int32_t ret = g_brInterface->GetConnectionInfo(conn->connectionId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(info.type, CONNECT_BR);
    
    ConnBrRemoveConnection(conn);
    ConnBrReturnConnection(&conn);
}

/*
* @tc.name: INTERFACE_START_LOCAL_LISTENING_031
* @tc.desc: Test StartLocalListening - invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_START_LOCAL_LISTENING_031, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = g_brInterface->StartLocalListening(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_START_LOCAL_LISTENING_032
* @tc.desc: Test StartLocalListening - thread create fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_START_LOCAL_LISTENING_032, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, SoftBusThreadCreate(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_CONN_BR_INTERNAL_ERR));
    
    LocalListenerInfo info;
    info.type = CONNECT_BR;
    int32_t ret = g_brInterface->StartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_BR_INTERNAL_ERR, ret);
}

/*
* @tc.name: INTERFACE_START_LOCAL_LISTENING_SUCCESS_033
* @tc.desc: Test StartLocalListening - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_START_LOCAL_LISTENING_SUCCESS_033, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, SoftBusThreadCreate(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ActionOfConnBrStartServer()).WillRepeatedly(Return(SOFTBUS_OK));
    
    LocalListenerInfo info;
    info.type = CONNECT_BR;
    int32_t ret = g_brInterface->StartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: INTERFACE_STOP_LOCAL_LISTENING_034
* @tc.desc: Test StopLocalListening - not listening
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_STOP_LOCAL_LISTENING_034, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, SoftBusThreadCreate(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ActionOfConnBrStartServer()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ActionOfConnBrStopServer()).WillRepeatedly(Return(SOFTBUS_CONN_BR_SPP_SERVER_ERR));
    
    LocalListenerInfo info;
    info.type = CONNECT_BR;
    g_brInterface->StartLocalListening(&info);
    int32_t ret = g_brInterface->StopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_BR_SPP_SERVER_ERR, ret);
}

/*
* @tc.name: INTERFACE_STOP_LOCAL_LISTENING_SUCCESS_035
* @tc.desc: Test StopLocalListening - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_STOP_LOCAL_LISTENING_SUCCESS_035, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    NiceMock<BrManagerTestMock> mock;
    EXPECT_CALL(mock, SoftBusThreadCreate(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ActionOfConnBrStartServer()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ActionOfConnBrStopServer()).WillRepeatedly(Return(SOFTBUS_OK));
    
    LocalListenerInfo info;
    info.type = CONNECT_BR;
    g_brInterface->StartLocalListening(&info);
    int32_t ret = g_brInterface->StopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: INTERFACE_CHECK_ACTIVE_CONNECTION_036
* @tc.desc: Test CheckActiveConnection - not found
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CHECK_ACTIVE_CONNECTION_036, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "AA:BB:CC:DD:EE:FF", strlen("AA:BB:CC:DD:EE:FF"));
    
    bool ret = g_brInterface->CheckActiveConnection(&option, false);
    EXPECT_FALSE(ret);
}

/*
* @tc.name: INTERFACE_CHECK_ACTIVE_CONNECTION_FAIL_037
* @tc.desc: Test CheckActiveConnection - invalid param (option null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CHECK_ACTIVE_CONNECTION_FAIL_037, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    bool ret = g_brInterface->CheckActiveConnection(nullptr, false);
    EXPECT_FALSE(ret);
}

/*
* @tc.name: INTERFACE_CHECK_ACTIVE_CONNECTION_FAIL_038
* @tc.desc: Test CheckActiveConnection - invalid type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CHECK_ACTIVE_CONNECTION_FAIL_038, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BLE;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    
    bool ret = g_brInterface->CheckActiveConnection(&option, false);
    EXPECT_FALSE(ret);
}

/*
* @tc.name: INTERFACE_CHECK_ACTIVE_CONNECTION_SUCCESS_039
* @tc.desc: Test CheckActiveConnection - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CHECK_ACTIVE_CONNECTION_SUCCESS_039, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrConnection *conn = CreateConnectionAndSave("66:77:88:99:AA:BB", CONN_SIDE_CLIENT, 500);
    ASSERT_NE(conn, nullptr);
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "66:77:88:99:AA:BB", strlen("66:77:88:99:AA:BB"));
    
    bool ret = g_brInterface->CheckActiveConnection(&option, false);
    EXPECT_TRUE(ret);
    
    ConnBrRemoveConnection(conn);
    ConnBrReturnConnection(&conn);
}

/*
* @tc.name: INTERFACE_UPDATE_CONNECTION_040
* @tc.desc: Test UpdateConnection - connection not found
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_UPDATE_CONNECTION_040, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    UpdateOption option;
    (void)memset_s(&option, sizeof(option), 0, sizeof(option));
    
    int32_t ret = g_brInterface->UpdateConnection(99999, &option);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

/*
* @tc.name: INTERFACE_UPDATE_CONNECTION_FAIL_041
* @tc.desc: Test UpdateConnection - invalid param (option null)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_UPDATE_CONNECTION_FAIL_041, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = g_brInterface->UpdateConnection(1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_UPDATE_CONNECTION_FAIL_042
* @tc.desc: Test UpdateConnection - invalid type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_UPDATE_CONNECTION_FAIL_042, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    UpdateOption option;
    (void)memset_s(&option, sizeof(option), 0, sizeof(option));
    option.type = CONNECT_BLE;
    
    int32_t ret = g_brInterface->UpdateConnection(1, &option);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: INTERFACE_UPDATE_CONNECTION_SUCCESS_043
* @tc.desc: Test UpdateConnection - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_UPDATE_CONNECTION_SUCCESS_043, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrConnection *conn = CreateConnectionAndSave("77:88:99:AA:BB:CC", CONN_SIDE_CLIENT, 600);
    ASSERT_NE(conn, nullptr);
    
    UpdateOption option;
    (void)memset_s(&option, sizeof(option), 0, sizeof(option));
    
    int32_t ret = g_brInterface->UpdateConnection(conn->connectionId, &option);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrRemoveConnection(conn);
    ConnBrReturnConnection(&conn);
}

/*
* @tc.name: INTERFACE_PREVENT_CONNECTION_044
* @tc.desc: Test PreventConnection - success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_PREVENT_CONNECTION_044, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnectOption option;
    option.type = CONNECT_BR;
    (void)memset_s(option.brOption.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    (void)memcpy_s(option.brOption.brMac, BT_MAC_LEN, "AA:BB:CC:DD:EE:FF", strlen("AA:BB:CC:DD:EE:FF"));
    
    int32_t ret = g_brInterface->PreventConnection(&option, 1000);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: CONN_BR_DUMPER_049
* @tc.desc: Test ConnBrDumper
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_BR_DUMPER_049, TestSize.Level1)
{
    if (!isInited_) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ListNode snapshots;
    ListInit(&snapshots);
    
    int32_t ret = ConnBrDumper(&snapshots);
    EXPECT_EQ(ret, SOFTBUS_OK);
    
    ConnBrConnectionSnapshot *it = nullptr;
    ConnBrConnectionSnapshot *next = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &snapshots, ConnBrConnectionSnapshot, node) {
        ListDelete(&it->node);
        SoftBusFree(it);
    }
}

/*
* @tc.name: CONN_BR_DUMPER_FAIL_050
* @tc.desc: Test ConnBrDumper - null param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_BR_DUMPER_FAIL_050, TestSize.Level1)
{
    if (!isInited_) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = ConnBrDumper(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: CONN_BR_SAVE_CONNECTION_051
* @tc.desc: Test ConnBrSaveConnection - null connection
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_BR_SAVE_CONNECTION_051, TestSize.Level1)
{
    if (!isInited_) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    int32_t ret = ConnBrSaveConnection(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: CONN_BR_REMOVE_CONNECTION_052
* @tc.desc: Test ConnBrRemoveConnection - null connection
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_BR_REMOVE_CONNECTION_052, TestSize.Level1)
{
    if (!isInited_) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrRemoveConnection(nullptr);
}

/*
* @tc.name: CONN_BR_GET_CONNECTION_BY_ADDR_053
* @tc.desc: Test ConnBrGetConnectionByAddr - null addr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_BR_GET_CONNECTION_BY_ADDR_053, TestSize.Level1)
{
    if (!isInited_) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrConnection *conn = ConnBrGetConnectionByAddr(nullptr, CONN_SIDE_CLIENT);
    EXPECT_EQ(conn, nullptr);
}

/*
* @tc.name: CONN_BR_GET_CONNECTION_BY_ID_054
* @tc.desc: Test ConnBrGetConnectionById - not found
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_BR_GET_CONNECTION_BY_ID_054, TestSize.Level1)
{
    if (!isInited_) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrConnection *conn = ConnBrGetConnectionById(99999);
    EXPECT_EQ(conn, nullptr);
}

/*
* @tc.name: CONN_BR_RETURN_CONNECTION_055
* @tc.desc: Test ConnBrReturnConnection - null ptr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_BR_RETURN_CONNECTION_055, TestSize.Level1)
{
    if (!isInited_) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrReturnConnection(nullptr);
}

/*
* @tc.name: CONN_BR_RETURN_CONNECTION_056
* @tc.desc: Test ConnBrReturnConnection - null connection
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, CONN_BR_RETURN_CONNECTION_056, TestSize.Level1)
{
    if (!isInited_) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    ConnBrConnection *conn = nullptr;
    ConnBrReturnConnection(&conn);
}

/*
* @tc.name: INTERFACE_CONFIG_POST_LIMIT_057
* @tc.desc: Test ConfigPostLimit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BrManagerTest, INTERFACE_CONFIG_POST_LIMIT_057, TestSize.Level1)
{
    if (g_brInterface == nullptr) {
        GTEST_SKIP() << "BR Manager not initialized";
    }
    
    LimitConfiguration config;
    config.maxBytesPerSec = 1024;
    config.maxMessagesPerSec = 100;
    
    int32_t ret = g_brInterface->ConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

} // namespace OHOS
