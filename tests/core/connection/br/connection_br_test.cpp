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

#include "connection_br_mock.h"
#include "softbus_conn_br_trans.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_conn_br_send_queue.h"

static const uint32_t CONN_HEAD_SIZE = 24;
#define TEST_BR_MAC "24:DA:33:6A:06:EC"

static unsigned int g_connId = 0;
static unsigned int g_secondConnId = 0;

#define WAIT_CONNECTION_COUNT 8
#define WAIT_CONNECTION_SLEEP_TIME 1

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void ConnectedCB(unsigned int connectionId, const ConnectionInfo *info)
{
    printf("recv remote ConnectedCB %u %d\r\n", connectionId, info->type);
    if (info->type == CONNECT_BR) {
        g_connId = connectionId;
    }
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

void SecondConnectSuccessedCB(unsigned int requestId, unsigned int connectionId, const ConnectionInfo *info)
{
    g_secondConnId = connectionId;
    return;
}

void ConnectFailedCB(unsigned int requestId, int reason)
{
    (void)requestId;
    (void)reason;
    printf("DconConnectFailed\r\n");
    return;
}

class ConnectionBrTest : public testing::Test {
public:
    ConnectionBrTest()
    {}
    ~ConnectionBrTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnectionBrTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
}

void ConnectionBrTest::TearDownTestCase(void)
{}

void ConnectionBrTest::SetUp(void)
{}

void ConnectionBrTest::TearDown(void)
{}

int32_t GetBrConnStateByConnectionId(uint32_t connectId)
{
    (void)connectId;
    return BR_CONNECTION_STATE_CLOSED;
}

/*
* @tc.name: testConnmanger001
* @tc.desc: test ConnTypeIsSupport
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBrTest, testConnmanger001, TestSize.Level1)
{
    int ret;
    printf("testConnmanger001\r\n");

    ret = ConnTypeIsSupport(CONNECT_BR);
    EXPECT_EQ(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger002
* @tc.desc: test invalid param
* @tc.in: test module, test number, Test Levels.
* @tc.out: zero
* @tc.type: FUNC
* @tc.require:AR000GIIE9
*/
HWTEST_F(ConnectionBrTest, testConnmanger002, TestSize.Level1)
{
    printf("test begin testConnmanger002 \r\n");
    int ret;
    ret = ConnSetConnectCallback(static_cast<ConnModule>(0), nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnConnectDevice(nullptr, 0, nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnPostBytes(0, nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnStartLocalListening(nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnStopLocalListening(nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
};

/*
* @tc.name: testConnmanger003
* @tc.desc: test set unset callback and connect post disconnect and multiple disconnects.
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(ConnectionBrTest, testConnmanger003, TestSize.Level1)
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
    info.type = CONNECT_BR;
    (void)memcpy_s(info.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", info.brOption.brMac);
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId) {
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
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
    }

    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger004
* @tc.desc: test set unset callback and post disconnect without connect
* @tc.type: FUNC
* @tc.require:AR000GIIE9
*/
HWTEST_F(ConnectionBrTest, testConnmanger004, TestSize.Level1)
{
    printf("test begin ConnManagerTest004 \r\n");
    int ret;
    ConnectCallback connCb;
    LocalListenerInfo info;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BR;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger005
* @tc.desc: The test set unsets the return value of callback and disconnection after connection.
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(ConnectionBrTest, testConnmanger005, TestSize.Level1)
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

    optionInfo.type = CONNECT_BR;
    (void)memcpy_s(optionInfo.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", optionInfo.brOption.brMac);
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
        printf("testConnmanger005 ConnDisconnectDevice\r\n");
    }
    printf("testConnmanger005 ConnUnSetConnectCallback\r\n");
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    printf("testConnmanger005 ConnUnSetConnectCallback end 11\r\n");
};

/*
* @tc.name: testConnmanger006
* @tc.desc: Test set unset callback.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: NA
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback operates normally.
*/
HWTEST_F(ConnectionBrTest, testConnmanger006, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;

    connCb.OnConnected = ConnectedCB;
    connCb.OnConnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_NE(SOFTBUS_OK, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger007
* @tc.desc: Test set unset callback and connect post disconnect.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnDisconnectDevice
* and ConnDisconnectDevice and ConnPostBytes and operates normally.
*/
HWTEST_F(ConnectionBrTest, testConnmanger007, TestSize.Level1)
{
    int ret;
    int reqId;
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
    info.type = CONNECT_BR;
    (void)memcpy_s(info.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
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
* @tc.name: testConnmanger008
* @tc.desc: Test set unset callback and connect twice has same ConnectID.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnSetConnectCallback and ConnConnectDevice operates normally.
*/
HWTEST_F(ConnectionBrTest, testConnmanger008, TestSize.Level1)
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

    optionInfo.type = CONNECT_BR;
    (void)memcpy_s(optionInfo.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
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
* @tc.require: The ConnSetConnectCallback and ConnConnectDevice operates normally.
*/
HWTEST_F(ConnectionBrTest, testConnmanger009, TestSize.Level1)
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
    info.type = CONNECT_BR;
    (void)memcpy_s(info.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", info.brOption.brMac);
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
* @tc.require: The ConnSetConnectCallback and ConnConnectDevice operates normally.
*/
HWTEST_F(ConnectionBrTest, testConnmanger010, TestSize.Level1)
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
    info.type = CONNECT_BR;
    (void)memcpy_s(info.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
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

HWTEST_F(ConnectionBrTest, testBrPendingPacket001, TestSize.Level1)
{
    int ret;
    ConnectOption info;
    uint32_t time = 1;

    ret = ConnPreventConnection(NULL, time);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    time = 0;
    ret = ConnPreventConnection(&info, time);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);

    time = 30000;
    ret = ConnPreventConnection(&info, time);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);

    time = 1;
    info.type = CONNECT_BLE;
    ret = ConnPreventConnection(&info, time);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);
}

HWTEST_F(ConnectionBrTest, testBrPendingPacket002, TestSize.Level1)
{
    int ret;
    ConnectOption info;
    uint32_t time = 1;

    info.type = CONNECT_BR;
    (void)memcpy_s(info.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", info.brOption.brMac);
    ret = ConnPreventConnection(&info, time);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrTest, testBrPendingPacket003, TestSize.Level1)
{
    int ret;
    ConnectOption info;

    info.type = CONNECT_BR;
    info.brOption.sideType = CONN_SIDE_ANY;
    (void)memcpy_s(info.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", info.brOption.brMac);
    ret = CheckActiveConnection(&info);
    EXPECT_EQ(false, ret);
}

HWTEST_F(ConnectionBrTest, testBrPendingPacket004, TestSize.Level1)
{
    int ret;
    uint32_t id = 1;
    ConnectionInfo info;

    ret = ConnGetConnectionInfo(id, NULL);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);

    id = 0;
    ret = ConnGetConnectionInfo(id, &info);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

HWTEST_F(ConnectionBrTest, testBrPendingPacket005, TestSize.Level1)
{
    int ret;
    uint32_t id = 0x20000;
    ConnectOption info;

    info.type = CONNECT_BR;
    (void)memcpy_s(info.brOption.brMac, BT_MAC_LEN, TEST_BR_MAC, BT_MAC_LEN);
    printf("brMac: %s\n", info.brOption.brMac);
    ret = ConnDisconnectDeviceAllConn(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    usleep(50);
    ret = ConnDisconnectDevice(id);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

HWTEST_F(ConnectionBrTest, testBrPendingPacket006, TestSize.Level1)
{
    int ret;
    uint32_t id = 1;
    int64_t seq = 1000;
    uint32_t waitMillis = 1000;
    void *data = NULL;

    ret = ConnBrInitBrPendingPacket();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);

    ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);

    ConnBrDelBrPendingPacket(id, seq);
    ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnBrSetBrPendingPacket(id, seq, data);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_ALREADY_TRIGGERED, ret);

    ConnBrDelBrPendingPacket(id, seq);
    ret = ConnBrSetBrPendingPacket(id, seq, data);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

HWTEST_F(ConnectionBrTest, testBrPendingPacket007, TestSize.Level1)
{
    int ret;
    ConnBrConnection connection;

    NiceMock<ConnectionBrInterfaceMock> brMock;
    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(false));
    connection.connectionId = 1;
    ret = ConnBrOnAckRequest(&connection, NULL);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);


    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    ret = ConnBrOnAckRequest(&connection, NULL);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    SoftBusMutexInit(&connection.lock, NULL);
    connection.connectionId = 0;
    ret = ConnBrOnAckRequest(&connection, NULL);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, AddNumber64ToJsonObject).WillRepeatedly(Return(true));
    SoftBusMutexInit(&connection.lock, NULL);
    connection.connectionId = 0;
    ret = ConnBrOnAckRequest(&connection, NULL);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

HWTEST_F(ConnectionBrTest, testBrPendingPacket008, TestSize.Level1)
{
    int ret;
    uint32_t id = 1;
    int64_t seq = 1000;
    void *data = NULL;
    ConnBrConnection connection;

    NiceMock<ConnectionBrInterfaceMock> brMock;
    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(false));
    connection.connectionId = 1;
    ret = ConnBrOnAckResponse(&connection, NULL);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    ConnBrDelBrPendingPacket(id, seq);
    ret = ConnBrSetBrPendingPacket(id, seq, data);
    ret = ConnBrOnAckResponse(&connection, NULL);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

HWTEST_F(ConnectionBrTest, testBrQueue001, TestSize.Level1)
{
    int ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrEnqueueNonBlock(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    queueNode.flag = CONN_HIGH;
    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_MIDDLE;
    queueNode.pid = 1;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

HWTEST_F(ConnectionBrTest, testBrQueue002, TestSize.Level1)
{
    int ret;
    void *msg = NULL;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ConnBrIsQueueEmpty();
    EXPECT_EQ(false, ret);
}

HWTEST_F(ConnectionBrTest, testBrBrans001, TestSize.Level1)
{
    int ret;
    uint32_t connectionId;
    int32_t socketHandle = 0;
    LimitedBuffer buffer;
    uint8_t *outData = NULL;
    ConnPktHead head;

    head.magic = MAGIC_NUMBER;
    head.len = 70;
    buffer.capacity = 140;
    buffer.length = 100;
    buffer.buffer = (uint8_t *)(&head);
    connectionId = 1;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_NE(SOFTBUS_OK, ret);

    head.magic = MAGIC_NUMBER + 1;
    head.len = 70;
    buffer.capacity = 140;
    buffer.length = 100;
    buffer.buffer = (uint8_t *)(&head);
    connectionId = 1;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_EQ(SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL, ret);
}

HWTEST_F(ConnectionBrTest, testBrBrans002, TestSize.Level1)
{
    int ret;
    uint32_t connectionId;
    int32_t socketHandle = 0;
    LimitedBuffer buffer;
    uint8_t *outData = NULL;
    ConnPktHead head;

    head.magic = MAGIC_NUMBER;
    head.len = 70;
    buffer.capacity = 70;
    buffer.length = 100;
    buffer.buffer = (uint8_t *)(&head);
    connectionId = 1;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_EQ(SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL, ret);
}

HWTEST_F(ConnectionBrTest, testBrBrans003, TestSize.Level1)
{
    int ret;
    uint32_t connectionId;
    int32_t socketHandle = 0;
    LimitedBuffer buffer;
    uint8_t *outData = NULL;
    ConnPktHead head;

    head.magic = MAGIC_NUMBER;
    head.len = 70;
    buffer.capacity = 140;
    buffer.length = 90;
    buffer.buffer = (uint8_t *)(&head);
    connectionId = 1;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_EQ(SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL, ret);
}

HWTEST_F(ConnectionBrTest, testBrBrans004, TestSize.Level1)
{
    int64_t ret;
    BrCtlMessageSerializationContext ctx;
    uint8_t *outData = NULL;
    uint32_t outDataLen;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, AddNumber64ToJsonObject).WillRepeatedly(Return(true));
    ctx.method = BR_METHOD_ACK_RESPONSE;
    ctx.connectionId = 1;
    ret = ConnBrPackCtlMessage(ctx, &outData, &outDataLen);
    EXPECT_NE(SOFTBUS_OK, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    ctx.method = BR_METHOD_NOTIFY_REQUEST;
    ctx.connectionId = 1;
    ret = ConnBrPackCtlMessage(ctx, &outData, &outDataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    ctx.method = BR_METHOD_NOTIFY_RESPONSE;
    ctx.connectionId = 1;
    ret = ConnBrPackCtlMessage(ctx, &outData, &outDataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.connectionId = 1;
    ret = ConnBrPackCtlMessage(ctx, &outData, &outDataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    ctx.method = BR_METHOD_ACK_RESPONSE;
    ctx.connectionId = 1;
    ret = ConnBrPackCtlMessage(ctx, &outData, &outDataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    ctx.method = (enum BrCtlMessageMethod)3;
    ctx.connectionId = 1;
    ret = ConnBrPackCtlMessage(ctx, &outData, &outDataLen);
    EXPECT_EQ(SOFTBUS_CONN_BR_INTERNAL_ERR, ret);
}

HWTEST_F(ConnectionBrTest, testBrBrans005, TestSize.Level1)
{
    int ret;
    uint32_t connectionId = 1;
    uint8_t *data = NULL;
    uint32_t len = 0;
    int32_t pid = 0;
    int32_t flag = 0;
    int32_t module = 0;
    int64_t seq = 0;

    ret = ConnBrPostBytes(connectionId, data, len, pid, flag, module, seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    len = MAX_DATA_LEN + 1;
    data = (uint8_t *)SoftBusCalloc(len);
    ret = ConnBrPostBytes(connectionId, data, len, pid, flag, module, seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    len = MAX_DATA_LEN;
    data = (uint8_t *)SoftBusCalloc(len);
    connectionId = 0x20001;
    ret = ConnBrPostBytes(connectionId, data, len, pid, flag, module, seq);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}
}
