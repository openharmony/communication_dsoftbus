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

#include "gtest/gtest.h"
#include "message_handler.h"
#include "session.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "trans_auth_mock.h"
#include "trans_common_mock.h"
#include "trans_conn_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class TransProxyTransceiverTest : public testing::Test {
public:
    TransProxyTransceiverTest()
    {}
    ~TransProxyTransceiverTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransProxyTransceiverTest::SetUpTestCase(void)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));

    SoftbusConfigInit();
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());

    IServerChannelCallBack callBack;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnSetConnectCallback).WillRepeatedly(Return(SOFTBUS_OK));
    ASSERT_EQ(SOFTBUS_OK, TransProxyManagerInit(&callBack));
}

void TransProxyTransceiverTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

/**
 * @tc.name: TransProxyOpenConnChannelTest001
 * @tc.desc: test proxy open new conn channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyTransceiverTest, TransProxyOpenConnChannelTest001, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.appType = APP_TYPE_NORMAL;
    ConnectOption connInfo;
    int32_t channelId = -1;

    TransAuthInterfaceMock authMock;
    TransConnInterfaceMock connMock;
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthGetLatestIdByUuid)
        .WillOnce(Return(AUTH_INVALID_ID))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(commMock, SoftBusGenerateRandomArray)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnConnectDevice)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetNewRequestId)
        .WillOnce(Return(1))
        .WillOnce(Return(2))
        .WillOnce(Return(3))
        .WillOnce(Return(4))
        .WillOnce(Return(5))
        .WillRepeatedly(Return(6));

    int32_t ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyOpenConnChannelTest002
 * @tc.desc: test proxy open exist channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyTransceiverTest, TransProxyOpenConnChannelTest002, TestSize.Level1)
{
    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;
    ConnectionInfo brInfo;
    brInfo.type = CONNECT_BR;
    ConnectionInfo bleInfo;
    bleInfo.type = CONNECT_BLE;
    TransCommInterfaceMock commMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(tcpInfo), Return(SOFTBUS_MEM_ERR)))
        .WillOnce(DoAll(SetArgPointee<1>(tcpInfo), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(brInfo), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(bleInfo), Return(SOFTBUS_OK)));
    TransCreateConnByConnId(1);
    TransCreateConnByConnId(2);
    TransCreateConnByConnId(3);
    TransCreateConnByConnId(4);

    EXPECT_CALL(connMock, ConnConnectDevice).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(24));
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    AppInfo appInfo;
    appInfo.appType = APP_TYPE_AUTH;
    int32_t channelId = -1;
    ConnectOption connInfo;
    connInfo.type = CONNECT_TCP;
    int32_t ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    connInfo.type = CONNECT_BR;
    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    connInfo.type = CONNECT_BLE;
    ret = TransProxyOpenConnChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    sleep(1);
}

/**
 * @tc.name: TransProxyCloseConnChannelTest001
 * @tc.desc: test proxy close conn channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyTransceiverTest, TransProxyCloseConnChannelTest001, TestSize.Level1)
{
    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;

    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(tcpInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(connMock, ConnDisconnectDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));
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
HWTEST_F(TransProxyTransceiverTest, TransProxyCloseConnChannelResetTest001, TestSize.Level1)
{
    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;

    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(tcpInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(connMock, ConnDisconnectDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
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
HWTEST_F(TransProxyTransceiverTest, TransProxyGetConnInfoByConnIdTest001, TestSize.Level1)
{
    ConnectOption connOptInfo;

    int32_t ret = TransProxyGetConnInfoByConnId(3, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyGetConnInfoByConnId(100, &connOptInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyGetConnInfoByConnId(3, &connOptInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyTransSendMsgTest001
 * @tc.desc: test proxy send message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyTransceiverTest, TransProxyTransSendMsgTest001, TestSize.Level1)
{
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));

    uint32_t connectionId = 1;
    uint8_t *buf = NULL;
    uint32_t len = 1;
    int32_t priority = 0;
    int32_t pid = 0;
    int32_t ret = TransProxyTransSendMsg(connectionId, buf, len, priority, pid);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyTransSendMsg(connectionId, buf, len, priority, pid);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

} // namespace OHOS
