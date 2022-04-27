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
#include <cstdlib>
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

static const uint32_t CONN_HEAD_SIZE = 24;
#define TEST_BLE_MAC "11:22:33:44:55:66"

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

void DataReceivedCB(unsigned int connectionId, ConnModule moduleId, int64_t seq, char *data, int len)
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

void ConnectFailedCB(unsigned int requestId, int reason)
{
    return;
}

class ConnectionBleTest : public testing::Test {
public:
    ConnectionBleTest()
    {}
    ~ConnectionBleTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnectionBleTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
}

void ConnectionBleTest::TearDownTestCase(void)
{}

void ConnectionBleTest::SetUp(void)
{}

void ConnectionBleTest::TearDown(void)
{}

/*
* @tc.name: testConnmanger001
* @tc.desc: test ConnTypeIsSupport
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, testConnmanger001, TestSize.Level1)
{
    int ret;
    printf("testConnmanger001\r\n");

    ret = ConnTypeIsSupport(CONNECT_BLE);
    EXPECT_EQ(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger002
* @tc.desc: test invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, testConnmanger002, TestSize.Level1)
{
    printf("test begin testConnmanger002 \r\n");
    int ret;
    ret = ConnSetConnectCallback(static_cast<ConnModule>(0), nullptr);
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
};

/*
* @tc.name: testConnmanger003
* @tc.desc: test set unset callback and connect post disconnect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, testConnmanger003, TestSize.Level1)
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
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", info.info.bleOption.bleMac);
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
* @tc.name: testConnmanger004
* @tc.desc: test set unset callback and post disconnect without connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, testConnmanger004, TestSize.Level1)
{
    printf("test begin ConnManagerTest004 \r\n");
    int ret;
    ConnectCallback connCb;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger005
* @tc.desc: Test start stop listening.
* @tc.in: Test module, Test number,Test Levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnStartLocalListening and ConnStopLocalListening operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger005, TestSize.Level1)
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
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger006
* @tc.desc: Test set unset callback and connect post disconnectAll.
* @tc.in: Test module, Test number,Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnGetConnectionInfo and ConnDisconnectDeviceAllConn operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger006, TestSize.Level1)
{
    int reqId = 1;
    int ret;
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
    (void)memcpy_s(optionInfo.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    printf("bleMac: %s\n", optionInfo.info.bleOption.bleMac);
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
        printf("testConnmanger006 ConnDisconnectDeviceAllConn\r\n");
    }
    printf("testConnmanger006 ConnUnSetConnectCallback\r\n");
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    printf("testConnmanger006 ConnUnSetConnectCallback end 11\r\n");
};

/*
* @tc.name: testConnmanger007
* @tc.desc: Test set unset callback and connect post disconnect post.
* @tc.in: Test module, Test number,Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger007, TestSize.Level1)
{
    int ret;
    int reqId;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";
    printf("test begin testConnmanger007 \r\n");

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", info.info.bleOption.bleMac);
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
* @tc.name: testConnmanger008
* @tc.desc: Test set unset callback and connect twice has same ConnectID.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:The ConnSetConnectCallback and ConnConnectDevice operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger008, TestSize.Level1)
{
    int ret;
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
    (void)memcpy_s(optionInfo.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);

    connRet2.OnConnectFailed = ConnectFailedCB;
    connRet2.OnConnectSuccessed = SecondConnectSuccessedCB;
    int reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
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
* @tc.name: testConnmanger009
* @tc.desc: Test set unset callback and connect twice post disconnect post.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger009, TestSize.Level1)
{
    int ret;
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
    (void)memcpy_s(info.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int reqId1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId1, &connRet);
    int reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
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
* @tc.name: testConnmanger010
* @tc.desc: Test set unset callback and connect twice post disconnectAll post.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes and ConnDisconnectDeviceAllConn operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger010, TestSize.Level1)
{
    int ret;
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
    (void)memcpy_s(info.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;

    int reqId1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId1, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
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
* @tc.name: testConnmanger011
* @tc.desc: Test set unset callback and connect post disconnectAll.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnDisconnectDeviceAllConn and ConnGetConnectionInfo operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger011, TestSize.Level1)
{
    int reqId = 1;
    int ret;
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
    (void)memcpy_s(optionInfo.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    printf("bleMac: %s\n", optionInfo.info.bleOption.bleMac);
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
        printf("testConnmanger006 ConnDisconnectDeviceAllConn\r\n");
    }
    printf("testConnmanger006 ConnUnSetConnectCallback\r\n");
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    printf("testConnmanger006 ConnUnSetConnectCallback end 11\r\n");
};

/*
* @tc.name: testConnmanger012
* @tc.desc: Test set unset callback and connect post disconnect post.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger012, TestSize.Level1)
{
    int ret;
    int reqId;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";
    printf("test begin testConnmanger006 \r\n");

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BLE;
    (void)memcpy_s(info.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", info.info.bleOption.bleMac);
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
* @tc.name: testConnmanger013
* @tc.desc: Test set unset callback and connect twice has same ConnectID.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnConnectDevice operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger013, TestSize.Level1)
{
    int ret;
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
    (void)memcpy_s(optionInfo.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);

    connRet2.OnConnectFailed = ConnectFailedCB;
    connRet2.OnConnectSuccessed = ConnectSuccessedCB;
    int reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
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
* @tc.name: testConnmanger014
* @tc.desc: Test set unset callback and connect twice post disconnect post.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger014, TestSize.Level1)
{
    int ret;
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
    (void)memcpy_s(info.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    int reqId1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId1, &connRet);
    int reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
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
* @tc.name: testConnmanger015
* @tc.desc: Test set unset callback and connect twice post disconnectAll post.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnPostBytes operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger015, TestSize.Level1)
{
    int ret;
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
    (void)memcpy_s(info.info.bleOption.bleMac, BT_MAC_LEN, TEST_BLE_MAC, BT_MAC_LEN);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;

    int reqId1 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId1, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int reqId2 = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
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
* @tc.name: testConnmanger016
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger016, TestSize.Level1)
{
    int ret;
    printf("testConnmanger016\r\n");

    ret = ConnTypeIsSupport(CONNECT_P2P);
    EXPECT_EQ(SOFTBUS_ERR, ret);
};

/*
* @tc.name: testConnmanger017
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger017, TestSize.Level1)
{
    int ret;
    printf("testConnmanger017\r\n");

    ret = ConnTypeIsSupport(CONNECT_BR);
    EXPECT_EQ(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger018
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger018, TestSize.Level1)
{
    int ret;
    printf("testConnmanger018\r\n");

    ret = ConnTypeIsSupport(CONNECT_TCP);
    EXPECT_EQ(SOFTBUS_OK, ret);
};
}
