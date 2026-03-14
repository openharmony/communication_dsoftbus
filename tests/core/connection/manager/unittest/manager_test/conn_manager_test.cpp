/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under* Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with* License.
 * You may obtain a copy of* License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under* License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See* License for the specific language governing permissions and
 * limitations under* License.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "common_list.h"
#include "softbus_conn_manager_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"

#define DATASIZE 256
#define LARGE_DATASIZE 10240

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void OnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void OnReusedConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void OnDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void OnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    (void)connectionId;
    (void)moduleId;
    (void)seq;
    (void)data;
    (void)len;
}

void OnConnectSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)requestId;
    (void)connectionId;
    (void)info;
    return;
}

void OnConnectFailed(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
    return;
}

class ConnectionManagerTest : public testing::Test {
public:
    ConnectionManagerTest() { }
    ~ConnectionManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnectionManagerTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
}

void ConnectionManagerTest::TearDownTestCase(void)
{
}

void ConnectionManagerTest::SetUp(void) { }

void ConnectionManagerTest::TearDown(void) { }

/*
 * @tc.name: ConnGetHeadSize001
 * @tc.desc: Get connection header size
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetHeadSize001, TestSize.Level1)
{
    uint32_t ret = ConnGetHeadSize();
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: ConnGetHeadSize002
 * @tc.desc: Verify connection header size is within expected range
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetHeadSize002, TestSize.Level1)
{
    uint32_t ret = ConnGetHeadSize();
    EXPECT_LE(ret, 1024);
}

/*
 * @tc.name: ConnGetNewRequestId003
 * @tc.desc: Verify request ID is within expected range
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetNewRequestId003, TestSize.Level1)
{
    uint32_t reqId = ConnGetNewRequestId(MODULE_MESSAGE_SERVICE);
    EXPECT_GT(reqId, 0);
    EXPECT_LT(reqId, 1000001);
}

/*
 * @tc.name: ConnGetNewRequestId004
 * @tc.desc: Get request ID for proxy channel module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetNewRequestId004, TestSize.Level1)
{
    uint32_t reqId = ConnGetNewRequestId(MODULE_PROXY_CHANNEL);
    EXPECT_GT(reqId, 0);
}

/*
 * @tc.name: ConnTypeIsSupport001
 * @tc.desc: Check if connection types are supported
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnTypeIsSupport001, TestSize.Level1)
{
    int32_t ret = ConnTypeIsSupport(CONNECT_TCP);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);

    ret = ConnTypeIsSupport(CONNECT_BR);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);

    ret = ConnTypeIsSupport(CONNECT_BLE);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);

    ret = ConnTypeIsSupport(CONNECT_TYPE_MAX);
    EXPECT_EQ(SOFTBUS_CONN_INVALID_CONN_TYPE, ret);
}

/*
 * @tc.name: ConnTypeIsSupport002
 * @tc.desc: Check if P2P connection type is supported
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnTypeIsSupport002, TestSize.Level1)
{
    int32_t ret = ConnTypeIsSupport(CONNECT_P2P);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnTypeIsSupport003
 * @tc.desc: Check if BLE direct connection type is supported
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnTypeIsSupport003, TestSize.Level1)
{
    int32_t ret = ConnTypeIsSupport(CONNECT_BLE_DIRECT);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnTypeIsSupport004
 * @tc.desc: Check if HML connection type is supported
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnTypeIsSupport004, TestSize.Level1)
{
    int32_t ret = ConnTypeIsSupport(CONNECT_HML);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnSetConnectCallback001
 * @tc.desc: Set connection callback with null parameters
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback001, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    callback.OnConnected = nullptr;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = nullptr;
    callback.OnDataReceived = OnDataReceived;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = nullptr;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback002
 * @tc.desc: Set connection callback with invalid module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback002, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;
    ConnModule invalidModule = (ConnModule)999;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(invalidModule, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback003
 * @tc.desc: Set connection callback for HICHAIN module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback003, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;
    callback.OnReusedConnected = OnReusedConnected;

    ret = ConnSetConnectCallback(MODULE_HICHAIN, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback004
 * @tc.desc: Set connection callback for AUTH SDK module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback004, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback005
 * @tc.desc: Set connection callback for AUTH CONNECTION module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback005, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_AUTH_CONNECTION, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback006
 * @tc.desc: Set connection callback for MESSAGE SERVICE module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback006, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_MESSAGE_SERVICE, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback007
 * @tc.desc: Set connection callback for DIRECT CHANNEL module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback007, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_DIRECT_CHANNEL, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback008
 * @tc.desc: Set connection callback for PROXY CHANNEL module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback008, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_PROXY_CHANNEL, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback009
 * @tc.desc: Set connection callback for DEVICE AUTH module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback009, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_DEVICE_AUTH, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback010
 * @tc.desc: Set connection callback for P2P LINK module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback010, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_P2P_LINK, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback011
 * @tc.desc: Set connection callback for UDP INFO module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback011, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_UDP_INFO, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback012
 * @tc.desc: Set connection callback for PKG VERIFY module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback012, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_PKG_VERIFY, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback013
 * @tc.desc: Set connection callback for META AUTH module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback013, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_META_AUTH, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback014
 * @tc.desc: Set connection callback for P2P NEGO module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback014, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_P2P_NEGO, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback015
 * @tc.desc: Set connection callback for APPLY KEY CONNECTION module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback015, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_APPLY_KEY_CONNECTION, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback016
 * @tc.desc: Set connection callback for LANE SELECT module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback016, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_LANE_SELECT, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback017
 * @tc.desc: Set connection callback for BLE NET module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback017, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_BLE_NET, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback018
 * @tc.desc: Set connection callback for BLE CONN module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback018, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_BLE_CONN, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnSetConnectCallback019
 * @tc.desc: Set connection callback for BLE GENERAL module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetConnectCallback019, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback callback;

    callback.OnConnected = OnConnected;
    callback.OnDisconnected = OnDisconnected;
    callback.OnDataReceived = OnDataReceived;

    ret = ConnSetConnectCallback(MODULE_BLE_GENERAL, &callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnUnSetConnectCallback001
 * @tc:desc: Unset connection callback for multiple modules
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUnSetConnectCallback001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ConnUnSetConnectCallback(MODULE_TRUST_ENGINE));
    EXPECT_NO_FATAL_FAILURE(ConnUnSetConnectCallback(MODULE_HICHAIN));
}

/*
 * @tc.name: ConnUnSetConnectCallback002
 * @tc.desc: Unset connection callback for AUTH SDK module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUnSetConnectCallback002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ConnUnSetConnectCallback(MODULE_AUTH_SDK));
}

/*
 * @tc.name: ConnUnSetConnectCallback003
 * @tc.desc: Unset connection callback for MESSAGE SERVICE module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUnSetConnectCallback003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ConnUnSetConnectCallback(MODULE_MESSAGE_SERVICE));
}

/*
 * @tc.name: ConnUnSetConnectCallback004
 * @tc.desc: Unset connection callback for DIRECT CHANNEL module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUnSetConnectCallback004, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ConnUnSetConnectCallback(MODULE_DIRECT_CHANNEL));
}

/*
 * @tc.name: ConnUnSetConnectCallback005
 * @tc.desc: Unset connection callback for PROXY CHANNEL module
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUnSetConnectCallback005, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ConnUnSetConnectCallback(MODULE_PROXY_CHANNEL));
}

/*
 * @tc.name: ConnDeathCallback001
 * @tc.desc: Process death callback with valid parameters
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDeathCallback001, TestSize.Level1)
{
    const char *pkgName = "test.pkg";
    int32_t pid = 1234;
    EXPECT_NO_FATAL_FAILURE(ConnDeathCallback(pkgName, pid));
}

/*
 * @tc.name: ConnDeathCallback002
 * @tc.desc: Process death callback with zero PID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDeathCallback002, TestSize.Level1)
{
    const char *pkgName = "com.example.test";
    int32_t pid = 0;
    EXPECT_NO_FATAL_FAILURE(ConnDeathCallback(pkgName, pid));
}

/*
 * @tc.name: ConnDeathCallback003
 * @tc.desc: Process death callback with large PID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDeathCallback003, TestSize.Level1)
{
    const char *pkgName = "test.app";
    int32_t pid = 9999;
    EXPECT_NO_FATAL_FAILURE(ConnDeathCallback(pkgName, pid));
}

/*
 * @tc.name: ConnDeathCallback004
 * @tc.desc: Process death callback with empty package name
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDeathCallback004, TestSize.Level1)
{
    const char *pkgName = "";
    int32_t pid = 100;
    EXPECT_NO_FATAL_FAILURE(ConnDeathCallback(pkgName, pid));
}

/*
 * @tc.name: ConnConnectDevice001
 * @tc.desc: Connect device with null parameters
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnConnectDevice001, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    ConnectResult result;
    uint32_t requestId = 100;

    ret = ConnConnectDevice(nullptr, requestId, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    option.type = CONNECT_TCP;
    ret = ConnConnectDevice(&option, requestId, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnConnectDevice002
 * @tc.desc: Connect device with unsupported connection type
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnConnectDevice002, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    ConnectResult result;
    uint32_t requestId = 100;

    option.type = CONNECT_TYPE_MAX;
    ret = ConnConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnConnectDevice003
 * @tc.desc: Connect TCP device with zero request ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnConnectDevice003, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    ConnectResult result;
    uint32_t requestId = 0;

    option.type = CONNECT_TCP;
    ret = ConnConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnConnectDevice004
 * @tc.desc: Connect BR device with large request ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnConnectDevice004, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    ConnectResult result;
    uint32_t requestId = 9999;

    option.type = CONNECT_BR;
    ret = ConnConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnConnectDevice005
 * @tc.desc: Connect BLE device with valid request ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnConnectDevice005, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    ConnectResult result;
    uint32_t requestId = 1;

    option.type = CONNECT_BLE;
    ret = ConnConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnConnectDevice006
 * @tc.desc: Connect P2P device with large request ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnConnectDevice006, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    ConnectResult result;
    uint32_t requestId = 1000;

    option.type = CONNECT_P2P;
    ret = ConnConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnConnectDevice007
 * @tc.desc: Connect SLE device with valid request ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnConnectDevice007, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    ConnectResult result;
    uint32_t requestId = 500;

    option.type = CONNECT_SLE;
    ret = ConnConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnConnectDevice008
 * @tc.desc: Connect HML device with valid request ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnConnectDevice008, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    ConnectResult result;
    uint32_t requestId = 100;

    option.type = CONNECT_HML;
    ret = ConnConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc:desc: Get connection type by BR connection ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetTypeByConnectionId002, TestSize.Level1)
{
    int32_t ret;
    ConnectType type;
    uint32_t connectionId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetTypeByConnectionId(connectionId, &type);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetTypeByConnectionId003
 * @tc.desc: Get connection type by BLE connection ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetTypeByConnectionId003, TestSize.Level1)
{
    int32_t ret;
    ConnectType type;
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetTypeByConnectionId(connectionId, &type);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetTypeByConnectionId004
 * @tc.desc: Get connection type by P2P connection ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetTypeByConnectionId004, TestSize.Level1)
{
    int32_t ret;
    ConnectType type;
    uint32_t connectionId = (CONNECT_P2P << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetTypeByConnectionId(connectionId, &type);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetTypeByConnectionId005
 * @tc.desc: Get connection type by SLE connection ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetTypeByConnectionId005, TestSize.Level1)
{
    int32_t ret;
    ConnectType type;
    uint32_t connectionId = (CONNECT_SLE << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetTypeByConnectionId(connectionId, &type);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetTypeByConnectionId006
 * @tc.desc: Get connection type by HML connection ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetTypeByConnectionId006, TestSize.Level1)
{
    int32_t ret;
    ConnectType type;
    uint32_t connectionId = (CONNECT_HML << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetTypeByConnectionId(connectionId, &type);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetTypeByConnectionId007
 * @tc.desc: Get connection type by max connection ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetTypeByConnectionId007, TestSize.Level1)
{
    int32_t ret;
    ConnectType type;
    uint32_t connectionId = 0xFFFFFFFF;

    ret = ConnGetTypeByConnectionId(connectionId, &type);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnPostBytes001
 * @tc.desc: Post bytes with null parameters
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnPostBytes001, TestSize.Level1)
{
    int32_t ret;
    ConnPostData data;
    uint32_t connectionId = 0;

    ret = ConnPostBytes(connectionId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    data.buf = nullptr;
    data.len = 100;
    ret = ConnPostBytes(connectionId, &data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnDisconnectDevice001
 * @tc.desc: Disconnect device with invalid and valid connection IDs
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDevice001, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = 0;

    ret = ConnDisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);

    connectionId = (CONNECT_TCP << CONNECT_TYPE_SHIFT) + 1;
    ret = ConnDisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDevice002
 * @tc.desc: Disconnect BR device
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDevice002, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnDisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDevice003
 * @tc.desc: Disconnect BLE device
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDevice003, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnDisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDevice004
 * @tc.desc: Disconnect P2P device
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDevice004, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = (CONNECT_P2P << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnDisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDevice005
 * @tc.desc: Disconnect SLE device
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDevice005, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = (CONNECT_SLE << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnDisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDevice006
 * @tc.desc: Disconnect HML device
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDevice006, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = (CONNECT_HML << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnDisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDevice007
 * @tc.desc: Disconnect device with max connection ID
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDevice007, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = 0xFFFFFFFF;

    ret = ConnDisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDeviceAllConn001
 * @tc.desc: Disconnect all connections with null parameter
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDeviceAllConn001, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;

    ret = ConnDisconnectDeviceAllConn(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    option.type = CONNECT_TYPE_MAX;
    ret = ConnDisconnectDeviceAllConn(&option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDeviceAllConn002
 * @tc.desc: Disconnect all TCP connections
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDeviceAllConn002, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;

    option.type = CONNECT_TCP;
    ret = ConnDisconnectDeviceAllConn(&option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDeviceAllConn003
 * @tc.desc: Disconnect all BR connections
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDeviceAllConn003, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;

    option.type = CONNECT_BR;
    ret = ConnDisconnectDeviceAllConn(&option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDeviceAllConn004
 * @tc.desc: Disconnect all BLE connections
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDeviceAllConn004, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;

    option.type = CONNECT_BLE;
    ret = ConnDisconnectDeviceAllConn(&option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDeviceAllConn005
 * @tc.desc: Disconnect all P2P connections
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDeviceAllConn005, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;

    option.type = CONNECT_P2P;
    ret = ConnDisconnectDeviceAllConn(&option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnDisconnectDeviceAllConn006
 * @tc.desc: Disconnect all SLE connections
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnDisconnectDeviceAllConn006, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;

    option.type = CONNECT_SLE;
    ret = ConnDisconnectDeviceAllConn(&option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetConnectionInfo001
 * @tc.desc: Get connection info with null parameter
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetConnectionInfo001, TestSize.Level1)
{
    int32_t ret;
    ConnectionInfo info;
    uint32_t connectionId = 0;

    ret = ConnGetConnectionInfo(connectionId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    connectionId = (CONNECT_TCP << CONNECT_TYPE_SHIFT) + 1;
    ret = ConnGetConnectionInfo(connectionId, &info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetConnectionInfo002
 * @tc.desc: Get BR connection info
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetConnectionInfo002, TestSize.Level1)
{
    int32_t ret;
    ConnectionInfo info;
    uint32_t connectionId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetConnectionInfo(connectionId, &info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetConnectionInfo003
 * @tc.desc: Get BLE connection info
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetConnectionInfo003, TestSize.Level1)
{
    int32_t ret;
    ConnectionInfo info;
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetConnectionInfo(connectionId, &info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetConnectionInfo004
 * @tc.desc: Get P2P connection info
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetConnectionInfo004, TestSize.Level1)
{
    int32_t ret;
    ConnectionInfo info;
    uint32_t connectionId = (CONNECT_P2P << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetConnectionInfo(connectionId, &info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnGetConnectionInfo005
 * @tc.desc: Get SLE connection info
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnGetConnectionInfo005, TestSize.Level1)
{
    int32_t ret;
    ConnectionInfo info;
    uint32_t connectionId = (CONNECT_SLE << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnGetConnectionInfo(connectionId, &info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnSetKeepaliveByConnectionId001
 * @tc.desc: Set keepalive for TCP connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetKeepaliveByConnectionId001, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = 0;
    bool needKeepalive = true;

    ret = ConnSetKeepaliveByConnectionId(connectionId, needKeepalive);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);

    connectionId = (CONNECT_TCP << CONNECT_TYPE_SHIFT) + 1;
    ret = ConnSetKeepaliveByConnectionId(connectionId, needKeepalive);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnSetKeepaliveByConnectionId002
 * @tc.desc: Set keepalive for P2P connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetKeepaliveByConnectionId002, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = (CONNECT_P2P << CONNECT_TYPE_SHIFT) + 1;
    bool needKeepalive = true;

    ret = ConnSetKeepaliveByConnectionId(connectionId, needKeepalive);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnSetKeepaliveByConnectionId003
 * @tc.desc: Set keepalive false for HML connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetKeepaliveByConnectionId003, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = (CONNECT_HML << CONNECT_TYPE_SHIFT) + 1;
    bool needKeepalive = false;

    ret = ConnSetKeepaliveByConnectionId(connectionId, needKeepalive);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnSetKeepaliveByConnectionId004
 * @tc.desc: Set keepalive for TCP connection with offset
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnSetKeepaliveByConnectionId004, TestSize.Level1)
{
    int32_t ret;
    uint32_t connectionId = (CONNECT_TCP << CONNECT_TYPE_SHIFT) + 100;
    bool needKeepalive = true;

    ret = ConnSetKeepaliveByConnectionId(connectionId, needKeepalive);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStartLocalListening001
 * @tc.desc: Start local listening with null parameter
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStartLocalListening001, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    ret = ConnStartLocalListening(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info.type = CONNECT_TYPE_MAX;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStartLocalListening002
 * @tc.desc: Start TCP local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStartLocalListening002, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_TCP;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStartLocalListening003
 * @tc.desc: Start BR local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStartLocalListening003, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_BR;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStartLocalListening004
 * @tc.desc: Start BLE local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStartLocalListening004, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_BLE;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStartLocalListening005
 * @tc.desc: Start P2P local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStartLocalListening005, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_P2P;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStartLocalListening006
 * @tc.desc: Start SLE local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStartLocalListening006, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_SLE;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStopLocalListening001
 * @tc.desc: Stop local listening with null parameter
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStopLocalListening001, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    ret = ConnStopLocalListening(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info.type = CONNECT_TYPE_MAX;
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStopLocalListening002
 * @tc.desc: Stop TCP local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStopLocalListening002, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_TCP;
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStopLocalListening003
 * @tc.desc: Stop BR local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ressConnStopLocalListening003, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_BR;
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStopLocalListening004
 * @tc.desc: Stop BLE local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStopLocalListening004, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_BLE;
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnStopLocalListening005
 * @tc.desc: Stop P2P local listening
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnStopLocalListening005, TestSize.Level1)
{
    int32_t ret;
    LocalListenerInfo info;

    info.type = CONNECT_P2P;
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: CheckActiveConnection001
 * @tc.desc: Check active connection with null parameter
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, CheckActiveConnection001, TestSize.Level1)
{
    bool ret;
    ConnectOption option;
    bool needOccupy = true;

    ret = CheckActiveConnection(nullptr, needOccupy);
    EXPECT_EQ(false, ret);

    option.type = CONNECT_TYPE_MAX;
    ret = CheckActiveConnection(&option, needOccupy);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: CheckActiveConnection002
 * @tc.desc: Check TCP active connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, CheckActiveConnection002, TestSize.Level1)
{
    bool ret;
    ConnectOption option;
    bool needOccupy = true;

    option.type = CONNECT_TCP;
    ret = CheckActiveConnection(&option, needOccupy);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: CheckActiveConnection003
 * @tc.desc: Check BR active connection without occupy
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, CheckActiveConnection003, TestSize.Level1)
{
    bool ret;
    ConnectOption option;
    bool needOccupy = false;

    option.type = CONNECT_BR;
    ret = CheckActiveConnection(&option, needOccupy);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: CheckActiveConnection004
 * @tc.desc: Check BLE active connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, CheckActiveConnection004, TestSize.Level1)
{
    bool ret;
    ConnectOption option;
    bool needOccupy = true;

    option.type = CONNECT_BLE;
    ret = CheckActiveConnection(&option, needOccupy);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: CheckActiveConnection005
 * @tc.desc: Check P2P active connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, CheckActiveConnection005, TestSize.Level1)
{
    bool ret;
    ConnectOption option;
    bool needOccupy = true;

    option.type = CONNECT_P2P;
    ret = CheckActiveConnection(&option, needOccupy);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: CheckActiveConnection006
 * @tc.desc: Check SLE active connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, CheckActiveConnection006, TestSize.Level1)
{
    bool ret;
    ConnectOption option;
    bool needOccupy = true;

    option.type = CONNECT_SLE;
    ret = CheckActiveConnection(&option, needOccupy);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: CheckActiveConnection007
 * @tc.desc: Check HML active connection without occupy
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, CheckActiveConnection007, TestSize.Level1)
{
    bool ret;
    ConnectOption option;
    bool needOccupy = false;

    option.type = CONNECT_HML;
    ret = CheckActiveConnection(&option, needOccupy);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: ConnUpdateConnection001
 * @tc.desc: Update connection with null parameter
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUpdateConnection001, TestSize.Level1)
{
    int32_t ret;
    UpdateOption option;
    uint32_t connectionId = 0;

    ret = ConnUpdateConnection(connectionId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    connectionId = (CONNECT_TCP << CONNECT_TYPE_SHIFT) + 1;
    ret = ConnUpdateConnection(connectionId, &option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnUpdateConnection002
 * @tc.desc: Update BR connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUpdateConnection002, TestSize.Level1)
{
    int32_t ret;
    UpdateOption option;
    uint32_t connectionId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnUpdateConnection(connectionId, &option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnUpdateConnection003
 * @tc.desc: Update BLE connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUpdateConnection003, TestSize.Level1)
{
    int32_t ret;
    UpdateOption option;
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnUpdateConnection(connectionId, &option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/*
 * @tc.name: ConnUpdateConnection004
 * @tc.desc: Update P2P connection
 * @tc.type: FUNC
 * @tc.require: AR532D
 * @tc.level: Level1
 */
HWTEST_F(ConnectionManagerTest, ConnUpdateConnection004, TestSize.Level1)
{
    int32_t ret;
    UpdateOption option;
    uint32_t connectionId = (CONNECT_P2P << CONNECT_TYPE_SHIFT) + 1;

    ret = ConnUpdateConnection(connectionId, &option);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}
} // namespace OHOS
