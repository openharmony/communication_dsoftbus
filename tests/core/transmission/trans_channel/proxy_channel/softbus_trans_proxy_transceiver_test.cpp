/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "message_handler.h"
#include "session.h"
#include "softbus_conn_manager.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.c"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "gtest/gtest.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class SoftbusProxyTransceiverTest : public testing::Test {
public:
    SoftbusProxyTransceiverTest()
    {}
    ~SoftbusProxyTransceiverTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftbusProxyTransceiverTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());

    IServerChannelCallBack callBack;
    ASSERT_NE(SOFTBUS_OK, TransProxyManagerInit(&callBack));
}

void SoftbusProxyTransceiverTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

/**
 * @tc.name: TransProxyOpenConnChannelTest001
 * @tc.desc: test proxy open new conn channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyOpenConnChannelTest001, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.appType = APP_TYPE_NORMAL;
    ConnectOption connInfo;
    int32_t channelId = -1;

    int32_t ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyOpenConnChannelTest002
 * @tc.desc: test proxy open exist channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyOpenConnChannelTest002, TestSize.Level1)
{
    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;
    ConnectionInfo brInfo;
    brInfo.type = CONNECT_BR;
    ConnectionInfo bleInfo;
    bleInfo.type = CONNECT_BLE;
    TransCreateConnByConnId(1);
    TransCreateConnByConnId(2);
    TransCreateConnByConnId(3);
    TransCreateConnByConnId(4);

    AppInfo appInfo;
    appInfo.appType = APP_TYPE_AUTH;
    int32_t channelId = -1;
    int32_t ret = SOFTBUS_ERR;
    ConnectOption connInfo;
    connInfo.type = CONNECT_TCP;
    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
    connInfo.type = CONNECT_BR;
    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
    connInfo.type = CONNECT_BLE;
    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
    sleep(1);
}

/**
 * @tc.name: TransProxyCloseConnChannelTest001
 * @tc.desc: test proxy close conn channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyCloseConnChannelTest001, TestSize.Level1)
{
    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;
    TransCreateConnByConnId(1);

    int32_t ret = TransProxyCloseConnChannel(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyCloseConnChannel(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyCloseConnChannel(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyCloseConnChannelResetTest001
 * @tc.desc: test proxy dec connInfo ref count.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyCloseConnChannelResetTest001, TestSize.Level1)
{
    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;

    TransCreateConnByConnId(2);

    int32_t ret = TransProxyCloseConnChannelReset(2, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyCloseConnChannelReset(2, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyCloseConnChannelReset(2, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetConnInfoByConnIdTest001
 * @tc.desc: test proxy get conn info by conn id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyGetConnInfoByConnIdTest001, TestSize.Level1)
{
    ConnectOption connOptInfo;

    int32_t ret = TransProxyGetConnInfoByConnId(3, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyGetConnInfoByConnId(100, &connOptInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyGetConnInfoByConnId(3, &connOptInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyTransSendMsgTest001
 * @tc.desc: test proxy send message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyTransSendMsgTest001, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *buf = NULL;
    uint32_t len = 1;
    int32_t priority = 0;
    int32_t pid = 0;
    int32_t ret = TransProxyTransSendMsg(connectionId, buf, len, priority, pid);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyTransSendMsg(connectionId, buf, len, priority, pid);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CompareConnectOption001
 * @tc.desc: test CompareConnectOption.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, CompareConnectOption001, TestSize.Level1)
{
    ConnectOption connInfo;
    connInfo.type = CONNECT_TCP;
    connInfo.socketOption.protocol = LNN_PROTOCOL_IP;
    ConnectOption itemConnInfo;
    bool ret = false;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(false, ret);

    itemConnInfo.socketOption.protocol = LNN_PROTOCOL_IP;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(true, ret);

    connInfo.socketOption.port = 1000;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(false, ret);

    itemConnInfo.socketOption.port = 1000;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(true, ret);

    connInfo.type = CONNECT_BR;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(true, ret);

    connInfo.type = CONNECT_BLE;
    connInfo.bleOption.protocol = BLE_GATT;
    itemConnInfo.bleOption.protocol = BLE_COC;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(false, ret);

    itemConnInfo.bleOption.protocol = BLE_GATT;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(true, ret);

    connInfo.bleOption.psm = 1;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(false, ret);

    itemConnInfo.bleOption.psm = 1;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(true, ret);

    connInfo.type = CONNECT_BLE_DIRECT;
    connInfo.bleDirectOption.protoType = BLE_COC;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(false, ret);

    itemConnInfo.bleDirectOption.protoType = BLE_COC;
    ret = CompareConnectOption(&itemConnInfo, &connInfo);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name: TransProxyConnExistProc001
 * @tc.desc: test TransProxyConnExistProc.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyConnExistProc001, TestSize.Level1)
{
    ProxyConnInfo conn;
    ProxyChannelInfo chan;
    int32_t chanNewId = 1;
    TransCreateConnByConnId(1);
    conn.connInfo.type = CONNECT_BR;
    conn.state = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    int32_t ret = SOFTBUS_ERR;
    ret = TransProxyConnExistProc(&conn, &chan, chanNewId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    conn.state = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    ret = TransProxyConnExistProc(&conn, &chan, chanNewId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyConnectDevice001
 * @tc.desc: test TransProxyConnectDevice.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyConnectDevice001, TestSize.Level1)
{
    ConnectOption connInfo;
    connInfo.type = CONNECT_BLE_DIRECT;
    uint32_t reqId = ConnGetNewRequestId(MODULE_PROXY_CHANNEL);
    int32_t ret = SOFTBUS_ERR;
    ret = TransProxyConnectDevice(&connInfo, reqId);
    EXPECT_NE(SOFTBUS_OK, ret);

    connInfo.type = CONNECT_TYPE_MAX;
    ret = TransProxyConnectDevice(&connInfo, reqId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyOpenNewConnChannel001
 * @tc.desc: test TransProxyOpenNewConnChannel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxyOpenNewConnChannel001, TestSize.Level1)
{
    int32_t channelId = -1;
    ConnectOption connInfo;
    ProxyChannelInfo chan;
    ListenerModule moduleId = PROXY;
    int32_t ret = SOFTBUS_ERR;
    connInfo.type = CONNECT_TCP;
    ret = TransProxyOpenNewConnChannel(moduleId, &chan, &connInfo, channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxySendBadKeyMessagel001
 * @tc.desc: test TransProxySendBadKeyMessage.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyTransceiverTest, TransProxySendBadKeyMessagel001, TestSize.Level1)
{
    int32_t channelId = -1;
    ConnectOption connInfo;
    ProxyChannelInfo chan;
    ListenerModule moduleId = PROXY;
    int32_t ret = SOFTBUS_ERR;
    connInfo.type = CONNECT_TCP;
    ret = TransProxyOpenNewConnChannel(moduleId, &chan, &connInfo, channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}
} // namespace OHOS
