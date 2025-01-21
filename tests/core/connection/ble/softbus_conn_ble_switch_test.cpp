/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "message_handler.h"
#include "conn_log.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"

static const uint32_t CONN_HEAD_SIZE = 24;
static const char *TEST_BLE_MAC = "11:22:33:44:55:66";

static unsigned int g_connId = 0;
static unsigned int g_secondConnId = 0;

#define WAIT_CONNECTION_COUNT 8
#define WAIT_CONNECTION_SLEEP_TIME 1

using namespace testing::ext;

namespace OHOS {
void ConnectedCB(unsigned int connectionId, const ConnectionInfo *info)
{
    if (info->type == CONNECT_BLE) {
        g_connId = connectionId;
    }
    return;
}

void DisConnectCB(unsigned int connectionId, const ConnectionInfo *info)
{
    return;
}

void DataReceivedCB(unsigned int connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    return;
}

void ConnectSuccessedCB(unsigned int requestId, unsigned int connectionId, const ConnectionInfo *info)
{
    g_connId = connectionId;
    return;
}

void SecondConnectSuccessedCB(unsigned int requestId, unsigned int connectionId, const ConnectionInfo *info)
{
    g_secondConnId = connectionId;
    return;
}

void ConnectFailedCB(unsigned int requestId, int32_t reason)
{
    return;
}

class ConnectionBleSwitchTest : public testing::Test {
public:
    ConnectionBleSwitchTest()
    {}
    ~ConnectionBleSwitchTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnectionBleSwitchTest::SetUpTestCase(void)
{
    LooperInit();
    SoftbusConfigInit();
    ConnServerInit();
}

void ConnectionBleSwitchTest::TearDownTestCase(void)
{
    LooperDeinit();
}

void ConnectionBleSwitchTest::SetUp(void)
{}

void ConnectionBleSwitchTest::TearDown(void)
{}

/*
* @tc.name: testConnmanger001
* @tc.desc: test set unset callback and connect post disconnect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger001, TestSize.Level1)
{
    int32_t ret;
    int32_t reqId;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";
    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId != 0) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != NULL);
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
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }

    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger002
* @tc.desc: Test set unset callback and connect post disconnectAll.
* @tc.in: Test module, Test number,Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnGetConnectionInfo and ConnDisconnectDeviceAllConn operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger002, TestSize.Level1)
{
    int32_t reqId = 1;
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

    optionInfo.type = CONNECT_BLE;
    (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId) {
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDeviceAllConn(&optionInfo);
        g_connId = 0;
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
};

/*
* @tc.name: testConnmanger003
* @tc.desc: Test set unset callback and connect post disconnect post.
* @tc.in: Test module, Test number,Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger003, TestSize.Level1)
{
    int32_t ret;
    int32_t reqId;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId, &connRet);

    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId != 0) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != NULL);
        (void)strcpy_s(data.buf + 1, strlen(str), str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);

        ret = ConnPostBytes(g_connId, &data);
        ASSERT_NE(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
        }
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger004
* @tc.desc: Test set unset callback and connect twice has same ConnectID.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:The ConnSetConnectCallback and ConnConnectDevice operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger004, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectionInfo info;
    ConnectResult connRet;
    ConnectResult connRet2;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BLE;
    (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int32_t reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);

    connRet2.OnConnectFailed = ConnectFailedCB;
    connRet2.OnConnectSuccessed = SecondConnectSuccessedCB;
    int32_t reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId2, &connRet2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    sleep(1);
    if ((g_connId) && (g_secondConnId)) {
        EXPECT_EQ(g_connId, g_secondConnId);
    }

    if (g_connId) {
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDeviceAllConn(&optionInfo);
        g_connId = 0;
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
};

/*
* @tc.name: testConnmanger005
* @tc.desc: Test set unset callback and connect twice post disconnect post.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger005, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int32_t reqId1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId1, &connRet);
    int32_t reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId2, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId != 0) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != NULL);
        (void)strcpy_s(data.buf + 1, strlen(str), str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);

        ret = ConnPostBytes(g_connId, &data);
        ASSERT_EQ(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
        }
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger006
* @tc.desc: Test set unset callback and connect twice post disconnectAll post.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes and ConnDisconnectDeviceAllConn operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger006, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;

    int32_t reqId1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId1, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId2, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId != 0) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != NULL);
        (void)strcpy_s(data.buf + 1, strlen(str), str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;

        ret = ConnPostBytes(g_connId, &data);
        ASSERT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDeviceAllConn(&info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnPostBytes(g_connId, &data);
        ASSERT_NE(SOFTBUS_OK, ret);

        g_connId = 0;
        if (data.buf != nullptr) {
            free(data.buf);
        }
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
};

/*
* @tc.name: testConnmanger007
* @tc.desc: Test whether the result of obtaining the request id multiple times is the same.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnGetNewRequestId operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger007, TestSize.Level1)
{
    int32_t req1 = 1, req2 = 1;
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

    optionInfo.type = CONNECT_BLE;
    (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    req1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    req2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ASSERT_LT(req1, req2);
    ret = ConnConnectDevice(&optionInfo, req1, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId) {
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDeviceAllConn(&optionInfo);
        g_connId = 0;
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
};

/*
* @tc.name: testConnmanger008
* @tc.desc: Test connect post disconnect post and multiple tests connsetconnectcallback and conndisconnectdevice.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger008, TestSize.Level1)
{
    int32_t ret;
    int32_t reqId;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_CONN_INTERNAL_ERR, ret);
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId, &connRet);

    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId != 0) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != NULL);
        (void)strcpy_s(data.buf + 1, strlen(str), str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);

        ret = ConnPostBytes(g_connId, &data);
        ASSERT_NE(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
        }
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger009
* @tc.desc: Test Set ConnSetConnectCallback and connect twice has same ConnectID multiple times.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnConnectDevice operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger009, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectionInfo info;
    ConnectResult connRet;
    ConnectResult connRet2;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_CONN_INTERNAL_ERR, ret);
    optionInfo.type = CONNECT_BLE;
    (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int32_t reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);

    connRet2.OnConnectFailed = ConnectFailedCB;
    connRet2.OnConnectSuccessed = ConnectSuccessedCB;
    int32_t reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId2, &connRet2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    sleep(1);
    if ((g_connId) && (g_secondConnId)) {
        EXPECT_EQ(g_connId, g_secondConnId);
    }

    if (g_connId) {
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDeviceAllConn(&optionInfo);
        g_connId = 0;
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
};

/*
* @tc.name: testConnmanger010
* @tc.desc: Test set unset callback and connect many times post disconnect post.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger010, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int32_t reqId1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId1, &connRet);
    int32_t reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId2, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId != 0) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != NULL);
        (void)strcpy_s(data.buf + 1, strlen(str), str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        data.flag = 1;
        data.seq = 1;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);

        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);

        ret = ConnPostBytes(g_connId, &data);
        ASSERT_EQ(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
        }
        ret = ConnPostBytes(g_connId, &data);
        ASSERT_EQ(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
        }
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger0011
* @tc.desc: Test set unset callback and connect twice has same ConnectID and update connection.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:The ConnUpdateConnection operates normally.
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0011, TestSize.Level1)
{
    int32_t ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectResult connRet;
    ConnectResult connRet2;
    UpdateOption option;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BLE;
    (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int32_t reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);

    connRet2.OnConnectFailed = ConnectFailedCB;
    connRet2.OnConnectSuccessed = SecondConnectSuccessedCB;
    int32_t reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId2, &connRet2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    sleep(1);
    if ((g_connId) && (g_secondConnId)) {
        EXPECT_EQ(g_connId, g_secondConnId);
    }

    if (g_connId) {
        option.type = CONNECT_BLE;
        option.bleOption.priority = CONN_BLE_PRIORITY_BALANCED;
        ret = ConnUpdateConnection(g_connId, &option);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDeviceAllConn(&optionInfo);
        g_connId = 0;
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
};

/*
* @tc.name: testConnmanger0012
* @tc.desc: check active  ble connection.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0012, TestSize.Level1)
{
    ConnectOption optionInfo;

    optionInfo.type = CONNECT_BLE;
    optionInfo.bleOption.protocol = BLE_GATT;
    (void)memcpy_s(optionInfo.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    bool isActive = CheckActiveConnection(&optionInfo, false);
    EXPECT_TRUE(isActive == false);
};

/*
* @tc.name: ManagerTest001
* @tc.desc: test ConnTypeIsSupport
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0013, TestSize.Level1)
{
    int32_t ret = ConnTypeIsSupport(CONNECT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: ManagerTest002
* @tc.desc: test invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0014, TestSize.Level1)
{
    int32_t ret = ConnSetConnectCallback(static_cast<ConnModule>(0), nullptr);
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
}

/*
* @tc.name: ManagerTest003
* @tc.desc: test set unset callback and post disconnect without connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0015, TestSize.Level1)
{
    ConnectCallback connCb;
    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    int32_t ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
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
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0016, TestSize.Level1)
{
    ConnectCallback connCb;
    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    int32_t ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LocalListenerInfo info;
    info.type = CONNECT_BLE;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0017, TestSize.Level1)
{
    int32_t ret = ConnTypeIsSupport(CONNECT_P2P);
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
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0018, TestSize.Level1)
{
    int32_t ret = ConnTypeIsSupport(CONNECT_BR);
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
HWTEST_F(ConnectionBleSwitchTest, testConnmanger0019, TestSize.Level1)
{
    int32_t ret = ConnTypeIsSupport(CONNECT_TCP);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}
