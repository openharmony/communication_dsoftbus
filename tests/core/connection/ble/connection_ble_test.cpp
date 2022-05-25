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
* @tc.desc: test set unset callback and post disconnect without connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, testConnmanger003, TestSize.Level1)
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
* @tc.name: testConnmanger004
* @tc.desc: Test start stop listening.
* @tc.in: Test module, Test number,Test Levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnStartLocalListening and ConnStopLocalListening operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger004, TestSize.Level1)
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
* @tc.name: testConnmanger005
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger005, TestSize.Level1)
{
    int ret;
    printf("testConnmanger016\r\n");

    ret = ConnTypeIsSupport(CONNECT_P2P);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT, ret);
};

/*
* @tc.name: testConnmanger006
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger006, TestSize.Level1)
{
    int ret;
    printf("testConnmanger017\r\n");

    ret = ConnTypeIsSupport(CONNECT_BR);
    EXPECT_EQ(SOFTBUS_OK, ret);
};

/*
* @tc.name: testConnmanger007
* @tc.desc: Test ConnTypeIsSupport.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require: The ConnTypeIsSupport operates normally.
*/
HWTEST_F(ConnectionBleTest, testConnmanger007, TestSize.Level1)
{
    int ret;
    printf("testConnmanger018\r\n");

    ret = ConnTypeIsSupport(CONNECT_TCP);
    EXPECT_EQ(SOFTBUS_OK, ret);
};
}
