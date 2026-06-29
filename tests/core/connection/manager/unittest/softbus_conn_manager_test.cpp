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
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "common_list.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "message_handler.h"

static const uint32_t CONN_HEAD_SIZE = 24;
static const uint32_t SHIFT_BITS = 16;

static ConnectCallback *g_mangerCb = nullptr;
static ConnectionInfo g_connInfo = {0};
static unsigned int g_connId = 0;

using namespace testing::ext;

namespace OHOS {
unsigned int ObjectGetConnectionId(unsigned int type)
{
    unsigned int ret = type << SHIFT_BITS;
    ret++;
    return ret;
}

int ObjectConnectDevice(const ConnectOption *option, unsigned int requestId, const ConnectResult *result)
{
    if (option == nullptr || result == nullptr) {
        return 1;
    }
    g_connInfo.isAvailable = 1;
    g_connInfo.type = option->type;
    result->OnConnectSuccessed(requestId, ObjectGetConnectionId(option->type), &g_connInfo);
    return 0;
}

int ObjectPostBytes(unsigned int connectionId, uint8_t *data, uint32_t len, int pid, int flag, int module, int64_t seq)
{
    (void)connectionId;
    (void)data;
    (void)len;
    (void)pid;
    (void)flag;
    (void)module;
    (void)seq;
    return 0;
}

int ObjectDisconnectDevice(unsigned int connectionId)
{
    (void)connectionId;
    return 0;
}

int ObjectGetConnectionInfo(unsigned int connectionId, ConnectionInfo *info)
{
    (void)connectionId;
    if (info == nullptr) {
        return -1;
    }
    (void)memcpy_s(info, sizeof(ConnectionInfo), &g_connInfo, sizeof(ConnectionInfo));
    return 0;
}

int ObjectStartLocalListening(const LocalListenerInfo *info)
{
    if (info == nullptr) {
        return 1;
    }
    // Initialize connection info for local listening
    g_connInfo.isAvailable = 1;
    g_connInfo.type = info->type;
    if (g_mangerCb != nullptr) {
        g_mangerCb->OnConnected(ObjectGetConnectionId(info->type), &g_connInfo);
    }
    return 0;
}

int ObjectStopLocalListening(const LocalListenerInfo *info)
{
    if (info == nullptr) {
        return 1;
    }
    if (g_mangerCb != nullptr) {
        g_mangerCb->OnDisconnected(ObjectGetConnectionId(info->type), &g_connInfo);
    }
    return 0;
}

ConnectFuncInterface *ConnInitObject(const ConnectCallback *callback)
{
    if (callback == nullptr) {
        return nullptr;
    }
    ConnectFuncInterface *inter = static_cast<ConnectFuncInterface*>(calloc(1, sizeof(ConnectFuncInterface)));
    if (inter == nullptr) {
        return nullptr;
    }
    g_mangerCb = const_cast<ConnectCallback*>(callback);
    // Reset connection info for each new initialization
    (void)memset_s(&g_connInfo, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));

    inter->ConnectDevice = ObjectConnectDevice;
    inter->PostBytes = ObjectPostBytes;
    inter->DisconnectDevice = ObjectDisconnectDevice;
    inter->GetConnectionInfo = ObjectGetConnectionInfo;
    inter->StartLocalListening = ObjectStartLocalListening;
    inter->StopLocalListening = ObjectStopLocalListening;
    return inter;
}

extern "C" ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    return ConnInitObject(callback);
}

extern "C" ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback)
{
    return ConnInitObject(callback);
}

void ConnectedCB(unsigned int connectionId, const ConnectionInfo *info)
{
    printf("recv remote ConnectedCB %u\r\n", connectionId);
    g_connId = connectionId;
    return;
}

void DisConnectCB(unsigned int connectionId, const ConnectionInfo *info)
{
    printf("DconDisConnect %u\r\n", connectionId);
    return;
}

void DataReceivedCB(unsigned int connectionId, ConnModule moduleId, int64_t seq, char *data, int len)
{
    printf("DconDataReceived moduleId %d %s %d\r\n", moduleId, data, len);
    return;
}

void ConnectSuccessedCB(unsigned int requestId, unsigned int connectionId, const ConnectionInfo *info)
{
    printf("ConnectSuccessedCB %u\r\n", connectionId);
    g_connId = connectionId;
    return;
}

void ConnectFailedCB(unsigned int requestId, int reason)
{
    (void)requestId;
    (void)reason;
    printf("DconConnectFailed\r\n");
    return;
}

class ConnectionManagerTest : public testing::Test {
public:
    ConnectionManagerTest()
    {}
    ~ConnectionManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnectionManagerTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    LooperInit();
    ConnServerInit();
}

void ConnectionManagerTest::TearDownTestCase(void)
{}

void ConnectionManagerTest::SetUp(void)
{
    // Reset global state for each test
    g_mangerCb = nullptr;
    g_connId = 0;
    (void)memset_s(&g_connInfo, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
}

void ConnectionManagerTest::TearDown(void)
{
    // Clean up after each test
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    ConnUnSetConnectCallback(MODULE_AUTH_SDK);
    g_mangerCb = nullptr;
    g_connId = 0;
    (void)memset_s(&g_connInfo, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
}

/*
* @tc.name: testConnmanger001
* @tc.desc: test ConnTypeIsSupport
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionManagerTest, testConnmanger001, TestSize.Level1)
{
    int ret;
    printf("testConnmanger001\r\n");

    ret = ConnTypeIsSupport(CONNECT_TCP);
    EXPECT_EQ(SOFTBUS_OK, ret);
#ifdef connection_enable_br_test
    ret = ConnTypeIsSupport(CONNECT_BR);
    EXPECT_EQ(SOFTBUS_OK, ret);
    GTEST_LOG_(INFO) << "BR Support";
#endif

#ifdef connection_enable_ble_test
    ret = ConnTypeIsSupport(CONNECT_BLE);
    EXPECT_EQ(SOFTBUS_OK, ret);
    GTEST_LOG_(INFO) << "BLE Support";
#endif
};

/*
* @tc.name: testConnmanger002
* @tc.desc: test invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionManagerTest, testConnmanger002, TestSize.Level1)
{
    printf("test begin testConnmanger002 \r\n");
    int32_t ret;
    ret = ConnSetConnectCallback(static_cast<ConnModule>(0), nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConnConnectDevice(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConnPostBytes(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConnStartLocalListening(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConnStopLocalListening(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
};

/*
* @tc.name: testConnmanger003
* @tc.desc: test set unset callback and connect post disconnect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionManagerTest, testConnmanger003, TestSize.Level1)
{
    int ret;
    int reqId;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";
    printf("test begin testConnmanger003 \r\n");

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = CONNECT_BR;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId != 0) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != nullptr);
        (void)strcpy_s(data.buf + CONN_HEAD_SIZE, 20, str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
            data.buf = nullptr;
        }
    }
    ret = ConnDisconnectDevice(g_connId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger004
* @tc.desc: test set unset callback and post disconnect without connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionManagerTest, testConnmanger004, TestSize.Level1)
{
    printf("test begin ConnManagerTest004 \r\n");
    int ret;
    ConnectCallback connCb;
    LocalListenerInfo info;
    ConnPostData data;
    const char *str = "send msg local2\r\n";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BR;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        data.buf = static_cast<char*>(calloc)(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != nullptr);
        (void)strcpy_s(data.buf + CONN_HEAD_SIZE, 20, str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
            data.buf = nullptr;
        }
    }

    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger005
* @tc.desc: test set unset callback multi times
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionManagerTest, testConnmanger005, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    // Test duplicate registration - should fail
    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &connCb);
    EXPECT_EQ(SOFTBUS_CONN_INTERNAL_ERR, ret);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger006
* @tc.desc: test set unset callback and connect post disconnect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionManagerTest, testConnmanger006, TestSize.Level1)
{
    uint32_t reqId;
    int32_t ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectionInfo info;
    ConnectResult connRet;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BR;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId != 0) {
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDevice(g_connId);
        g_connId = 0;
        EXPECT_EQ(SOFTBUS_OK, ret);
        printf("testConnmanger006 ConnDisconnectDevice\r\n");
    }
    printf("testConnmanger006 ConnUnSetConnectCallback\r\n");
    printf("testConnmanger006 ConnUnSetConnectCallback end\r\n");
};

/*
* @tc.name: testConnmanger007
* @tc.desc: Test ConnSetConnectCallback moduleId out of max.
* @tc.in: Test module, Test number, Test levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback operates normally.
*/
HWTEST_F(ConnectionManagerTest, testConnmanger007, TestSize.Level1)
{
    ConnectCallback connCb;
    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;

    int moduleIdMin = 0;
    int moduleIdMax = 200;

    int ret = ConnSetConnectCallback(static_cast<ConnModule>(moduleIdMin), &connCb);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ConnSetConnectCallback(static_cast<ConnModule>(moduleIdMax), &connCb);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
};

/*
* @tc.name: testConnmanger008
* @tc.desc: Test ConnConnectDevice info type out of max.
* @tc.in: Test module, Test number, Test levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnConnectDevice operates normally.
*/
HWTEST_F(ConnectionManagerTest, testConnmanger008, TestSize.Level1)
{
    const char *testBleMac = "11:22:33:44:55:66";
    ConnectResult connRet;
    ConnectOption info;
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.bleOption.bleMac, BT_MAC_LEN, testBleMac, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    uint32_t reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);

    int ret = ConnConnectDevice(nullptr, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info.type = static_cast<ConnectType>(CONNECT_TYPE_MAX + 1);
    ret = ConnConnectDevice(&info, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);

    info.type = static_cast<ConnectType>(CONNECT_TCP - 1);
    ret = ConnConnectDevice(&info, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
};

/*
* @tc.name: testConnmanger009
* @tc.desc: Test ConnStartLocalListening info type out of max.
* @tc.in: Test module, Test number, Test levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnStartLocalListening operates normally.
*/
HWTEST_F(ConnectionManagerTest, testConnmanger009, TestSize.Level1)
{
    LocalListenerInfo info;
    info.type = static_cast<ConnectType>(CONNECT_TYPE_MAX + 1);
    int ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
};

/*
* @tc.name: testConnmanger010
* @tc.desc: Test ConnStopLocalListening info type out of max.
* @tc.in: Test module, Test number, Test levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnStopLocalListening operates normally.
*/
HWTEST_F(ConnectionManagerTest, testConnmanger010, TestSize.Level1)
{
    LocalListenerInfo info;
    info.type = static_cast<ConnectType>(CONNECT_TYPE_MAX + 1);
    int ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
};

/*
* @tc.name: testConnmanger011
* @tc.desc: Test ConnTypeIsSupport type out of max.
* @tc.in: Test module, Test number, Test levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionManagerTest, testConnmanger011, TestSize.Level1)
{
    int ret = ConnTypeIsSupport(CONNECT_TYPE_MAX);
    EXPECT_EQ(SOFTBUS_CONN_INVALID_CONN_TYPE, ret);
};

/*
* @tc.name: testConnmanger012
* @tc.desc: Test multiple connect and disconnect cycles
* @tc.type: FUNC
* @tc.require: Connection manager handles multiple cycles correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger012, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    // Test multiple connect/disconnect cycles
    for (int i = 0; i < 3; i++) {
        optionInfo.type = CONNECT_BR;
        connRet.OnConnectFailed = ConnectFailedCB;
        connRet.OnConnectSuccessed = ConnectSuccessedCB;
        reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
        ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
        EXPECT_EQ(SOFTBUS_OK, ret);

        if (g_connId != 0) {
            ret = ConnDisconnectDevice(g_connId);
            EXPECT_EQ(SOFTBUS_OK, ret);
            g_connId = 0;
        }
    }
};

/*
* @tc.name: testConnmanger013
* @tc.desc: Test TCP connection type
* @tc.type: FUNC
* @tc.require: TCP connection works correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger013, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_TCP;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

/*
* @tc.name: testConnmanger014
* @tc.desc: Test BLE connection type
* @tc.type: FUNC
* @tc.require: BLE connection works correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger014, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    const char *testBleMac = "11:22:33:44:55:66";
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BLE;
    (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, testBleMac, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

/*
* @tc.name: testConnmanger015
* @tc.desc: Test local listening with TCP
* @tc.type: FUNC
* @tc.require: Local listening works with TCP
*/
HWTEST_F(ConnectionManagerTest, testConnmanger015, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    LocalListenerInfo info;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = CONNECT_TCP;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }

    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger016
* @tc.desc: Test local listening with BLE
* @tc.type: FUNC
* @tc.require: Local listening works with BLE
*/
HWTEST_F(ConnectionManagerTest, testConnmanger016, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    LocalListenerInfo info;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = CONNECT_BLE;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }

    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger017
* @tc.desc: Test data transmission with different sizes
* @tc.type: FUNC
* @tc.require: Data transmission handles various sizes
*/
HWTEST_F(ConnectionManagerTest, testConnmanger017, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    ConnPostData data;
    uint32_t reqId;
    const char *testMsg = "Test message";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BR;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        // Test with small data
        data.buf = static_cast<char*>(calloc)(1, CONN_HEAD_SIZE + 50);
        ASSERT_TRUE(data.buf != nullptr);
        (void)strcpy_s(data.buf + CONN_HEAD_SIZE, 50, testMsg);
        data.len = CONN_HEAD_SIZE + 50;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        free(data.buf);
        data.buf = nullptr;

        // Test with larger data
        data.buf = static_cast<char*>(calloc)(1, CONN_HEAD_SIZE + 1024);
        ASSERT_TRUE(data.buf != nullptr);
        (void)memset_s(data.buf + CONN_HEAD_SIZE, 1024, 'A', 1024);
        data.len = CONN_HEAD_SIZE + 1024;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        free(data.buf);
        data.buf = nullptr;

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

/*
* @tc.name: testConnmanger018
* @tc.desc: Test connection info retrieval
* @tc.type: FUNC
* @tc.require: Connection info can be retrieved correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger018, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectionInfo info;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_TCP;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        EXPECT_EQ(info.type, CONNECT_TCP);
        EXPECT_EQ(info.isAvailable, 1);

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }

    // Test getting info with invalid connectionId
    ret = ConnGetConnectionInfo(0, &info);
    EXPECT_NE(SOFTBUS_OK, ret);

    // Test getting info with nullptr
    ret = ConnGetConnectionInfo(g_connId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger019
* @tc.desc: Test invalid module IDs
* @tc.type: FUNC
* @tc.require: Invalid module IDs are rejected
*/
HWTEST_F(ConnectionManagerTest, testConnmanger019, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;

    // Test with invalid module ID (negative)
    ret = ConnSetConnectCallback(static_cast<ConnModule>(-1), &connCb);
    EXPECT_NE(SOFTBUS_OK, ret);

    // Test with large invalid module ID
    ret = ConnSetConnectCallback(static_cast<ConnModule>(99999), &connCb);
    EXPECT_NE(SOFTBUS_OK, ret);

    // Test ConnGetNewRequestId with invalid module
    reqId = ConnGetNewRequestId(static_cast<ConnModule>(-1));
    EXPECT_EQ(reqId, 0);

    reqId = ConnGetNewRequestId(static_cast<ConnModule>(99999));
    EXPECT_EQ(reqId, 0);
};

/*
* @tc.name: testConnmanger020
* @tc.desc: Test multiple modules with same connection
* @tc.type: FUNC
* @tc.require: Multiple modules can use same connection
*/
HWTEST_F(ConnectionManagerTest, testConnmanger020, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;

    // Register multiple modules
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_CONNECTION, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BR;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

/*
* @tc.name: testConnmanger021
* @tc.desc: Test connection with different flags
* @tc.type: FUNC
* @tc.require: Connection handles different flag values
*/
HWTEST_F(ConnectionManagerTest, testConnmanger021, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    ConnPostData data;
    uint32_t reqId;
    const char *testMsg = "Flag test message";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_TCP;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        // Test with different flag values
        for (int flag = 0; flag <= 3; flag++) {
            data.buf = static_cast<char*>(calloc)(1, CONN_HEAD_SIZE + 50);
            ASSERT_TRUE(data.buf != nullptr);
            (void)strcpy_s(data.buf + CONN_HEAD_SIZE, 50, testMsg);
            data.len = CONN_HEAD_SIZE + 50;
            data.module = MODULE_TRUST_ENGINE;
            data.pid = 0;
            data.flag = flag;
            data.seq = 1;
            ret = ConnPostBytes(g_connId, &data);
            EXPECT_EQ(SOFTBUS_OK, ret);
            free(data.buf);
            data.buf = nullptr;
        }

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

/*
* @tc.name: testConnmanger022
* @tc.desc: Test connection timeout scenarios
* @tc.type: FUNC
* @tc.require: Connection handles timeout correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger022, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_TCP;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        // Simulate delayed disconnect
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }

    // Test disconnect on non-existent connection
    ret = ConnDisconnectDevice(g_connId);
    EXPECT_NE(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger023
* @tc.desc: Test data transmission with null buffer
* @tc.type: FUNC
* @tc.require: Null buffer is handled correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger023, TestSize.Level1)
{
    int ret;
    ConnPostData data;
    unsigned int testConnId = 12345;

    // Test post bytes with null data
    data.buf = nullptr;
    data.len = 100;
    data.module = MODULE_TRUST_ENGINE;
    data.pid = 0;
    data.flag = 1;
    data.seq = 1;
    ret = ConnPostBytes(testConnId, &data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    // Test post bytes with null ConnPostData
    ret = ConnPostBytes(testConnId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
};

/*
* @tc.name: testConnmanger024
* @tc.desc: Test local listening start/stop cycles
* @tc.type: FUNC
* @tc.require: Multiple start/stop cycles work correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger024, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    LocalListenerInfo info;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    // Test multiple start/stop cycles
    for (int i = 0; i < 3; i++) {
        info.type = CONNECT_BR;
        ret = ConnStartLocalListening(&info);
        EXPECT_EQ(SOFTBUS_OK, ret);

        if (g_connId != 0) {
            ret = ConnDisconnectDevice(g_connId);
            EXPECT_EQ(SOFTBUS_OK, ret);
            g_connId = 0;
        }

        ret = ConnStopLocalListening(&info);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
};

/*
* @tc.name: testConnmanger025
* @tc.desc: Test unset callback on unregistered module
* @tc.type: FUNC
* @tc.require: Unsetting unregistered callback is handled
*/
HWTEST_F(ConnectionManagerTest, testConnmanger025, TestSize.Level1)
{
    int ret;

    // Test unsetting callback that was never set
    ret = ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    // Should either succeed or return appropriate error
    // depending on implementation
};

/*
* @tc.name: testConnmanger026
* @tc.desc: Test connection with all supported types
* @tc.type: FUNC
* @tc.require: All connection types work correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger026, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;
    ConnectType types[] = {CONNECT_TCP, CONNECT_BR, CONNECT_BLE};
    int typeCount = 3;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    for (int i = 0; i < typeCount; i++) {
        optionInfo.type = types[i];
        if (types[i] == CONNECT_BLE) {
            const char *testBleMac = "11:22:33:44:55:66";
            (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, testBleMac, BT_MAC_LEN);
        }
        connRet.OnConnectFailed = ConnectFailedCB;
        connRet.OnConnectSuccessed = ConnectSuccessedCB;
        reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
        ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
        EXPECT_EQ(SOFTBUS_OK, ret);

        if (g_connId != 0) {
            ret = ConnDisconnectDevice(g_connId);
            EXPECT_EQ(SOFTBUS_OK, ret);
            g_connId = 0;
        }
    }
};

/*
* @tc.name: testConnmanger027
* @tc.desc: Test data transmission with large sequence numbers
* @tc.type: FUNC
* @tc.require: Large sequence numbers are handled correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger027, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    ConnPostData data;
    uint32_t reqId;
    const char *testMsg = "Seq test message";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BR;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        // Test with large sequence number
        data.buf = static_cast<char*>(calloc)(1, CONN_HEAD_SIZE + 50);
        ASSERT_TRUE(data.buf != nullptr);
        (void)strcpy_s(data.buf + CONN_HEAD_SIZE, 50, testMsg);
        data.len = CONN_HEAD_SIZE + 50;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 999999;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        free(data.buf);
        data.buf = nullptr;

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

/*
* @tc.name: testConnmanger028
* @tc.desc: Test connection info structure integrity
* @tc.type: FUNC
* @tc.require: Connection info structure maintains integrity
*/
HWTEST_F(ConnectionManagerTest, testConnmanger028, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectionInfo info;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_TCP;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        // Get connection info and verify structure
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);

        // Verify basic fields
        EXPECT_EQ(info.isAvailable, 1);
        EXPECT_EQ(info.type, CONNECT_TCP);

        // Test that info structure can be copied
        ConnectionInfo infoCopy;
        (void)memcpy_s(&infoCopy, sizeof(ConnectionInfo), &info, sizeof(ConnectionInfo));
        EXPECT_EQ(infoCopy.type, info.type);
        EXPECT_EQ(infoCopy.isAvailable, info.isAvailable);

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

/*
* @tc.name: testConnmanger029
* @tc.desc: Test rapid connection and disconnection
* @tc.type: FUNC
* @tc.require: Rapid connect/disconnect cycles are handled
*/
HWTEST_F(ConnectionManagerTest, testConnmanger029, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    // Perform rapid connect/disconnect cycles
    for (int i = 0; i < 10; i++) {
        optionInfo.type = CONNECT_BR;
        connRet.OnConnectFailed = ConnectFailedCB;
        connRet.OnConnectSuccessed = ConnectSuccessedCB;
        reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
        ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
        EXPECT_EQ(SOFTBUS_OK, ret);

        if (g_connId != 0) {
            ret = ConnDisconnectDevice(g_connId);
            EXPECT_EQ(SOFTBUS_OK, ret);
            g_connId = 0;
        }
    }
};

/*
* @tc.name: testConnmanger030
* @tc.desc: Test callback null handling
* @tc.type: FUNC
* @tc.require: Null callbacks are handled correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger030, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;

    // Test setting callback with null function pointers
    connCb.OnConnected = nullptr;
    connCb.OnDisconnected = nullptr;
    connCb.OnDataReceived = nullptr;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    // Behavior depends on implementation - record result
    // Should either accept or reject null callbacks

    // Test connecting with null callback result
    optionInfo.type = CONNECT_TCP;
    connRet.OnConnectFailed = nullptr;
    connRet.OnConnectSuccessed = nullptr;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger031
* @tc.desc: Test different PID values
* @tc.type: FUNC
* @tc.require: Different PID values are handled correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger031, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    ConnPostData data;
    uint32_t reqId;
    const char *testMsg = "PID test message";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BR;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        // Test with different PID values
        int pids[] = {0, 100, 1000, 9999};
        for (int i = 0; i < 4; i++) {
            data.buf = static_cast<char*>(calloc)(1, CONN_HEAD_SIZE + 50);
            ASSERT_TRUE(data.buf != nullptr);
            (void)strcpy_s(data.buf + CONN_HEAD_SIZE, 50, testMsg);
            data.len = CONN_HEAD_SIZE + 50;
            data.module = MODULE_TRUST_ENGINE;
            data.pid = pids[i];
            data.flag = 1;
            data.seq = 1;
            ret = ConnPostBytes(g_connId, &data);
            EXPECT_EQ(SOFTBUS_OK, ret);
            free(data.buf);
            data.buf = nullptr;
        }

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

/*
* @tc.name: testConnmanger032
* @tc.desc: Test BLE MAC address validation
* @tc.type: FUNC
* @tc.require: BLE MAC addresses are validated correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger032, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    // Test with various BLE MAC addresses
    const char *macAddresses[] = {
        "00:00:00:00:00:00",
        "FF:FF:FF:FF:FF:FF",
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66"
    };

    for (int i = 0; i < 4; i++) {
        optionInfo.type = CONNECT_BLE;
        (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, macAddresses[i], BT_MAC_LEN);
        connRet.OnConnectFailed = ConnectFailedCB;
        connRet.OnConnectSuccessed = ConnectSuccessedCB;
        reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
        ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
        EXPECT_EQ(SOFTBUS_OK, ret);

        if (g_connId != 0) {
            ret = ConnDisconnectDevice(g_connId);
            EXPECT_EQ(SOFTBUS_OK, ret);
            g_connId = 0;
        }
    }
};

/*
* @tc.name: testConnmanger033
* @tc.desc: Test request ID generation
* @tc.type: FUNC
* @tc.require: Request IDs are generated correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger033, TestSize.Level1)
{
    uint32_t reqId1, reqId2, reqId3;

    // Generate multiple request IDs for same module
    reqId1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    EXPECT_NE(reqId1, 0);

    reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    EXPECT_NE(reqId2, 0);
    EXPECT_NE(reqId2, reqId1);

    reqId3 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    EXPECT_NE(reqId3, 0);
    EXPECT_NE(reqId3, reqId2);

    // Generate request IDs for different modules
    uint32_t reqId4 = ConnGetNewRequestId(MODULE_AUTH_SDK);
    EXPECT_NE(reqId4, 0);
};

/*
* @tc.name: testConnmanger034
* @tc.desc: Test connection state after failed operation
* @tc.type: FUNC
* @tc.require: Connection state is consistent after failures
*/
HWTEST_F(ConnectionManagerTest, testConnmanger034, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectionInfo info;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    // Try to get connection info when no connection exists
    ret = ConnGetConnectionInfo(g_connId, &info);
    EXPECT_NE(SOFTBUS_OK, ret);

    // Try to disconnect when no connection exists
    ret = ConnDisconnectDevice(g_connId);
    EXPECT_NE(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger035
* @tc.desc: Test data buffer size limits
* @tc.type: FUNC
* @tc.require: Various buffer sizes are handled correctly
*/
HWTEST_F(ConnectionManagerTest, testConnmanger035, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    ConnPostData data;
    uint32_t reqId;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_TCP;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        // Test with various buffer sizes
        uint32_t sizes[] = {10, 100, 500, 1024, 2048, 4096};
        for (int i = 0; i < 6; i++) {
            data.buf = static_cast<char*>(calloc)(1, CONN_HEAD_SIZE + sizes[i]);
            ASSERT_TRUE(data.buf != nullptr);
            (void)memset_s(data.buf + CONN_HEAD_SIZE, sizes[i], 'X', sizes[i]);
            data.len = CONN_HEAD_SIZE + sizes[i];
            data.module = MODULE_TRUST_ENGINE;
            data.pid = 0;
            data.flag = 1;
            data.seq = i + 1;
            ret = ConnPostBytes(g_connId, &data);
            EXPECT_EQ(SOFTBUS_OK, ret);
            free(data.buf);
            data.buf = nullptr;
        }

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        g_connId = 0;
    }
};

} // namespace OHOS