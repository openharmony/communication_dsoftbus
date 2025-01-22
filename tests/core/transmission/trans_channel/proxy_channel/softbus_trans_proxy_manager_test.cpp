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

#include "gtest/gtest.h"
#include <securec.h>

#include "message_handler.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_transmission_interface.h"
#include "softbus_utils.h"
#include "trans_auth_mock.h"
#include "trans_channel_callback.h"
#include "trans_channel_manager.h"
#include "trans_common_mock.h"
#include "trans_conn_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_DEATH_CHANNEL_ID 14
#define TEST_PKG_NAME_LEN 65

static int32_t m_testProxyAuthChannelId = -4;
static int32_t m_testProxyNormalChannelId = -1;
static int32_t m_testProxyConningChannel = -3;

static bool g_testProxyChannelReceiveFlag = false;

class TransProxyManagerTest : public testing::Test {
public:
    TransProxyManagerTest()
    {}
    ~TransProxyManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransProxyManagerTest::SetUpTestCase(void) {}

void TransProxyManagerTest::TearDownTestCase(void) {}

void TestTransProxyAddAuthChannel(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));

    AppInfo appInfo;
    ProxyChannelInfo *chan = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, identity);
    chan->status = status;
    appInfo.appType = APP_TYPE_AUTH;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(chan);
}

void TestTransProxyAddNormalChannel(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    TransCommInterfaceMock commMock;
    OHOS::TransAuthInterfaceMock authMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthGetLatestIdByUuid).Times(0);

    AppInfo appInfo;
    ProxyChannelInfo *chan = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, identity);
    chan->status = status;
    appInfo.appType = APP_TYPE_NORMAL;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(chan);
}

/**@
 * @tc.name: TransProxyOpenProxyChannelTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyOpenProxyChannelTest001, TestSize.Level1)
{
    AppInfo appInfo;
    ConnectOption connInfo;
    int32_t channelId = -1;
    int32_t ret = TransProxyOpenProxyChannel(nullptr, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenProxyChannel(&appInfo, nullptr, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyCreateChanInfoTest001
 * @tc.desc: test proxy create channel info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyCreateChanInfoTest001, TestSize.Level1)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    OHOS::TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthGetLatestIdByUuid).Times(0);
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    AppInfo appInfo;
    ProxyChannelInfo *chan = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = 3069;
    chan->seq = 10;
    (void)strcpy_s(chan->identity, 33, "10");
    appInfo.appType = APP_TYPE_AUTH;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    chan->status = PROXY_CHANNEL_STATUS_COMPLETED;
    ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    m_testProxyAuthChannelId = chan->channelId;

    ProxyChannelInfo *chanNormal = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chanNormal);
    chanNormal->channelId = 11;
    (void)strcpy_s(chanNormal->identity, 33, "11");

    chanNormal->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    appInfo.appType = APP_TYPE_NORMAL;
    ret = TransProxyCreateChanInfo(chanNormal, chanNormal->channelId, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    m_testProxyNormalChannelId = chanNormal->channelId;
    SoftBusFree(chan);
    SoftBusFree(chanNormal);
}

/**
 * @tc.name: TransProxyGetNewChanSeqTest001
 * @tc.desc: test proxy get new chan seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyGetNewChanSeqTest001, TestSize.Level1)
{
    int32_t channelId = m_testProxyNormalChannelId;
    int32_t ret = TransProxyGetNewChanSeq(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransProxyGetNewChanSeq(-1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetAuthIdTest001
 * @tc.desc: test proxy get auth id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyGetAuthIdTest001, TestSize.Level1)
{
    AuthHandle authHandle = { 0 };
    int32_t channelId = -1;
    int32_t ret = TransProxyGetAuthId(channelId, &authHandle);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetAuthId(channelId, &authHandle);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: TransProxyGetNameByChanIdTest001
 * @tc.desc: test proxy get auth id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyGetNameByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    uint16_t pkgLen = PKG_NAME_SIZE_MAX;
    uint16_t sessionLen = SESSION_NAME_SIZE_MAX;
    int32_t ret = TransProxyGetNameByChanId(channelId, pkgName, sessionName, pkgLen, sessionLen);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyNormalChannelId;
    ret = TransProxyGetNameByChanId(channelId, pkgName, sessionName, pkgLen, sessionLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransProxyGetSessionKeyByChanIdTest001
 * @tc.desc: test proxy get session key by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyGetSessionKeyByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    char sessionKey[SESSION_KEY_LENGTH]= {0};
    uint32_t sessionKeySize = SESSION_KEY_LENGTH;
    int32_t ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: TransProxyGetAppInfoByChanIdTest001
 * @tc.desc: test proxy get app info by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyGetAppInfoByChanIdTest001, TestSize.Level1)
{
    AppInfo appInfo;
    int32_t channelId = -1;

    int32_t ret = TransProxyGetAppInfoByChanId(channelId, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetAppInfoByChanId(channelId, &appInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: TransProxyGetConnIdByChanIdTest001
 * @tc.desc: test proxy get conn id by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyGetConnIdByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t connId = -1;

    int32_t ret = TransProxyGetConnIdByChanId(channelId, &connId);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyNormalChannelId;
    ret = TransProxyGetConnIdByChanId(channelId, &connId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: TransProxyGetConnOptionByChanIdTest001
 * @tc.desc: test proxy get cpnn option by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyGetConnOptionByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    ConnectOption connOpt;
    AppInfo appInfo;

    int32_t ret = TransProxyGetConnOptionByChanId(channelId, &connOpt);
    EXPECT_NE(SOFTBUS_OK, ret);

    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo *chan = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = 20;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo(_, _))
        .WillRepeatedly(DoAll(SetArgPointee<1>(tcpInfo), Return(SOFTBUS_OK)));
    TransCreateConnByConnId(20, true);

    ret = TransProxyGetConnOptionByChanId(chan->channelId, &connOpt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(chan);
}

/**
 * @tc.name: TransProxyGetSendMsgChanInfoTest001
 * @tc.desc: test proxy get sendmsg chanInfo by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyGetSendMsgChanInfoTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    ProxyChannelInfo chanInfo;

    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: TransProxyChanProcessByReqIdTest001
 * @tc.desc: test proxy get sendmsg chanInfo by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyChanProcessByReqIdTest001, TestSize.Level1)
{
    int32_t channelId = 25;
    const char *identity = "25";
    int32_t errCode = SOFTBUS_OK;
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_PYH_CONNECTING);

    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusBase64Encode).WillRepeatedly(Return(SOFTBUS_OK));
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));

    TransProxyChanProcessByReqId(channelId, channelId, errCode);
    usleep(500000);
    ProxyChannelInfo chanInfo;
    int32_t ret = TransProxyGetSendMsgChanInfo(m_testProxyConningChannel, &chanInfo);
    ASSERT_EQ(SOFTBUS_NO_INIT, ret);
    EXPECT_TRUE(PROXY_CHANNEL_STATUS_HANDSHAKEING != (uint32_t)chanInfo.status);
}

/**@
 * @tc.name: TransProxyOnMessageReceivedTest005
 * @tc.desc: test proxy received normal message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyOnMessageReceivedTest005, TestSize.Level1)
{
    ProxyMessage msg;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_NORMAL;
    
    msg.msgHead.myId = -1;
    msg.msgHead.peerId = -1;
    g_testProxyChannelReceiveFlag = false;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);

    msg.msgHead.myId = 10;
    msg.msgHead.peerId = 10;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);

    g_testProxyChannelReceiveFlag = false;
    msg.msgHead.myId = 11;
    msg.msgHead.peerId = 11;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);
}

/**@
 * @tc.name: TransProxyCloseProxyChannelTest001
 * @tc.desc: test proxy close proxy channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyCloseProxyChannelTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    TestTransProxyAddAuthChannel(29, "29", PROXY_CHANNEL_STATUS_COMPLETED);

    TransCommInterfaceMock commMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnDisconnectDevice).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelChanByChanIdTest001
 * @tc.desc: test proxy del proxy channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyDelChanByChanIdTest001, TestSize.Level1)
{
    TransProxyDelChanByChanId(m_testProxyAuthChannelId);
    ProxyChannelInfo chanInfo;
    int32_t ret = TransProxyGetSendMsgChanInfo(m_testProxyAuthChannelId, &chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelChanByReqIdTest001
 * @tc.desc: test proxy del proxy channel by reqId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyDelChanByReqIdTest001, TestSize.Level1)
{
    int32_t channelId = 31;
    const char *identity = "31";
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_PYH_CONNECTING);
    TransProxyDelChanByReqId(channelId, 2);
    ProxyChannelInfo chanInfo;
    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelByConnIdTest001
 * @tc.desc: test proxy del proxy channel by connId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyDelByConnIdTest001, TestSize.Level1)
{
    TransCommInterfaceMock commMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnDisconnectDevice).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo chan;
    int32_t channelId = 32;
    const char *identity = "32";
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_PYH_CONNECTING);
    
    TransProxyDelByConnId(channelId);
    usleep(500000);
    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chan);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDeathCallbackTest001
 * @tc.desc: test proxy TransProxyDeathCallback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyDeathCallbackTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)strcpy_s(appInfo.myData.pkgName, TEST_PKG_NAME_LEN, "com.test.pkgname");
    appInfo.appType = APP_TYPE_AUTH;
    appInfo.myData.pid = TEST_DEATH_CHANNEL_ID;
    ProxyChannelInfo *chan = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_DEATH_CHANNEL_ID;
    chan->connId = -1;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;

    TransCommInterfaceMock commMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnDisconnectDevice).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    ASSERT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransProxyDeathCallback(nullptr, TEST_DEATH_CHANNEL_ID);
    TransProxyDeathCallback("com.test.pkgname", TEST_DEATH_CHANNEL_ID);

    ret = TransProxyGetSendMsgChanInfo(chan->channelId, chan);
    EXPECT_NE(SOFTBUS_OK, ret);
    SoftBusFree(chan);
}
} // namespace OHOS