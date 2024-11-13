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

static ConnectCallback *g_mangerCb = 0;
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
    ConnectionInfo info = {0};
    if (option == 0 || result == 0) {
        return 1;
    }
    g_connInfo.isAvailable = 1;
    g_connInfo.type = option->type;
    result->OnConnectSuccessed(requestId, ObjectGetConnectionId(option->type), &info);
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
    if (g_mangerCb) {
        g_mangerCb->OnConnected(ObjectGetConnectionId(info->type), &g_connInfo);
    }
    return 0;
}

int ObjectStopLocalListening(const LocalListenerInfo *info)
{
    if (info == nullptr) {
        return 1;
    }
    if (g_mangerCb) {
        g_mangerCb->OnDisconnected(ObjectGetConnectionId(info->type), &g_connInfo);
    }
    return 0;
}

ConnectFuncInterface *ConnInitObject(const ConnectCallback *callback)
{
    if (callback == 0) {
        return nullptr;
    }
    ConnectFuncInterface *inter = (ConnectFuncInterface*)calloc(1, sizeof(ConnectFuncInterface));
    if (inter == nullptr) {
        return nullptr;
    }
    g_mangerCb = (ConnectCallback*)callback;

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
{}

void ConnectionManagerTest::TearDown(void)
{}

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
    if (g_connId) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != nullptr);
        (void)strcpy_s(data.buf + 1, strlen(str), str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
        }
    }
    ret = ConnDisconnectDevice(g_connId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    ConnUnSetConnectCallback(MODULE_AUTH_SDK);
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

    if (g_connId) {
        data.buf = (char*)calloc(1, CONN_HEAD_SIZE + 20);
        (void)strcpy_s(data.buf + CONN_HEAD_SIZE, strlen(str), str);
        ASSERT_TRUE(data.buf != NULL);
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
        }
    }

    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
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
    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &connCb);
    EXPECT_EQ(SOFTBUS_CONN_INTERNAL_ERR, ret);

    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    ConnUnSetConnectCallback(MODULE_AUTH_SDK);
};

/*
* @tc.name: testConnmanger006
* @tc.desc: test set unset callback and connect post disconnect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionManagerTest, testConnmanger006, TestSize.Level1)
{
    uint32_t reqId = 1;
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
    if (g_connId) {
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDevice(g_connId);
        g_connId = 0;
        EXPECT_EQ(SOFTBUS_OK, ret);
        printf("testConnmanger006 ConnDisconnectDevice\r\n");
    }
    printf("testConnmanger006 ConnUnSetConnectCallback\r\n");
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    printf("testConnmanger006 ConnUnSetConnectCallback end 11\r\n");
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

    int ret = ConnSetConnectCallback((ConnModule)moduleIdMin, &connCb);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ConnSetConnectCallback((ConnModule)moduleIdMax, &connCb);
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

    info.type = (ConnectType)(CONNECT_TYPE_MAX + 1);
    ret = ConnConnectDevice(&info, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);

    info.type = (ConnectType)(CONNECT_TCP -1);
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
    info.type = (ConnectType)(CONNECT_TYPE_MAX + 1);
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
    info.type = (ConnectType)(CONNECT_TYPE_MAX + 1);
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
} // namespace OHOS