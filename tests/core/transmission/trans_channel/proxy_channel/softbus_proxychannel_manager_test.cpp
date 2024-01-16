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
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_manager.c"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_transmission_interface.h"
#include "softbus_utils.h"
#include "trans_channel_callback.h"
#include "trans_channel_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {
#define TEST_AUTHSESSION "IShareAuthSession"
#define TEST_CHANNEL_INDENTITY "12345678"
#define TEST_PKG_NAME "com.trans.proxy.test.pkgname"
#define VALID_BUSNAME "testbusName"
#define VALID_PKGNAME "testPkgName"
#define VALID_SESSIONNAME "testSessionName"

#define TEST_ARRRY_SIZE 48
#define TEST_BUF_LEN 32
#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_DEATH_CHANNEL_ID 14
#define TEST_INVALID_LARGE_SIZE (100 * 1024)
#define TEST_MESSAGE_CHANNEL_ID 13
#define TEST_MESSAGE_CHANNEL_VALID_ID 46
#define TEST_NUMBER_ELEVEN 11
#define TEST_NUMBER_ONE 1
#define TEST_NUMBER_TEN 10
#define TEST_NUMBER_THREE 3
#define TEST_NUMBER_TWENTY 20
#define TEST_NUMBER_TWO 2
#define TEST_NUMBER_VALID (-1)
#define TEST_NUMBER_ZERO (-1)
#define TEST_NUMBER_25 25
#define TEST_NUMBER_26 26
#define TEST_NUMBER_5000 5000
#define TEST_PARSE_MESSAGE_CHANNEL 45
#define TEST_PAY_LOAD "testPayLoad"
#define TEST_PKGNAME "com.test.pkgname"
#define TEST_PKG_NAME_LEN 65
#define PROXY_CHANNEL_BT_IDLE_TIMEOUT 240
#define TEST_RESET_MESSAGE_CHANNEL_ID 30
#define TEST_STRING_TEN "10"
#define TEST_STRING_ELEVEN "11"
#define SESSIONKEYSIZE 256

static int32_t m_testProxyAuthChannelId = -1;
static bool g_testProxyChannelOpenSuccessFlag = false;
static bool g_testProxyChannelOpenFailFlag = false;
static bool g_testProxyChannelClosedFlag = false;
static bool g_testProxyChannelReceiveFlag = false;
static bool g_testNetworkChannelOpenFailFlag = false;

class SoftbusProxyChannelManagerTest : public testing::Test {
public:
    SoftbusProxyChannelManagerTest()
    {}
    ~SoftbusProxyChannelManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

int32_t TestOnDataReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)receiveData;
    g_testProxyChannelReceiveFlag = true;
    return SOFTBUS_OK;
}

int32_t TestOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)sessionName;
    (void)channel;
    (void)pid;
    g_testProxyChannelOpenSuccessFlag = true;
    return SOFTBUS_OK;
}

int32_t TestOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    g_testProxyChannelClosedFlag = true;
    return SOFTBUS_OK;
}

int32_t TestOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t channelType, int32_t errCode)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)errCode;
    g_testProxyChannelOpenFailFlag = true;
    return SOFTBUS_OK;
}

int32_t TestGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    return SOFTBUS_OK;
}

extern "C" {
int32_t TestGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    (void)sessionName;
    (void)pkgName;
    (void)len;
    return SOFTBUS_OK;
}
}

void TestOnNetworkingChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)channelId;
    (void)uuid;
    g_testNetworkChannelOpenFailFlag = true;
    return;
}

void SoftbusProxyChannelManagerTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());

    IServerChannelCallBack callBack;
    callBack.OnChannelOpened = TestOnChannelOpened;
    callBack.OnChannelClosed = TestOnChannelClosed;
    callBack.OnChannelOpenFailed = TestOnChannelOpenFailed;
    callBack.OnDataReceived = TestOnDataReceived;
    callBack.OnQosEvent = NULL;
    callBack.GetPkgNameBySessionName = TestGetPkgNameBySessionName;
    callBack.GetUidAndPidBySessionName = TestGetUidAndPidBySessionName;
    ASSERT_EQ(SOFTBUS_OK, TransProxyManagerInitInner(&callBack));
}

void SoftbusProxyChannelManagerTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

void TestTransProxyAddAuthChannel(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    AppInfo appInfo;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authId = channelId;
    chan->connId = channelId;
    chan->myId = channelId;
    chan->peerId = channelId;
    chan->reqId = channelId;
    chan->channelId = channelId;
    chan->seq = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, identity);
    chan->status = status;
    appInfo.appType = APP_TYPE_AUTH;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    ASSERT_TRUE(SOFTBUS_OK == ret);
}

void TestTransProxyAddNormalChannel(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    AppInfo appInfo;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authId = channelId;
    chan->connId = channelId;
    chan->myId = channelId;
    chan->peerId = channelId;
    chan->reqId = channelId;
    chan->channelId = channelId;
    chan->seq = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, identity);
    chan->status = status;
    appInfo.appType = APP_TYPE_NORMAL;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    ASSERT_TRUE(SOFTBUS_OK == ret);
}

/**@
 * @tc.name: TransProxyOpenProxyChannelTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyOpenProxyChannelTest001, TestSize.Level1)
{
    AppInfo appInfo;
    ConnectOption connInfo;
    int32_t channelId = TEST_NUMBER_VALID;
    int32_t ret = TransProxyOpenProxyChannel(NULL, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenProxyChannel(&appInfo, NULL, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetNewChanSeqTest001
 * @tc.desc: test proxy get new chan seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetNewChanSeqTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_TEN;
    int32_t ret = TransProxyGetNewChanSeq(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyGetNewChanSeq(TEST_NUMBER_VALID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyKeepAlvieChanTest001
  * @tc.desc: test trans proxy get new chanseq.
  * @tc.type: FUNC
  * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyKeepAlvieChanTest001, TestSize.Level1)
{
    uint32_t connId = TEST_NUMBER_VALID;
    ProxyChannelInfo *chanInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    chanInfo->channelId = TEST_NUMBER_TEN;
    chanInfo->peerId = TEST_PARSE_MESSAGE_CHANNEL;

    int32_t ret = TransProxyKeepAlvieChan(chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    chanInfo->peerId = TEST_MESSAGE_CHANNEL_VALID_ID;
    ret = TransProxyKeepAlvieChan(chanInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    TransProxyDelByConnId(connId);
    SoftBusFree(chanInfo);
}

/**
 * @tc.name: TransProxyGetAuthIdTest001
 * @tc.desc: test proxy get auth id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetAuthIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    int32_t ret = TransProxyGetAuthId(channelId);
    EXPECT_EQ(AUTH_INVALID_ID, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetAuthId(channelId);
    EXPECT_EQ(AUTH_INVALID_ID, ret);
}

/**
 * @tc.name: TransProxyGetNameByChanIdTest001
 * @tc.desc: test proxy get auth id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetNameByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    char pkgName[PKG_NAME_SIZE_MAX] = {TEST_NUMBER_ZERO};
    char sessionName[SESSION_NAME_SIZE_MAX] = {TEST_NUMBER_ZERO};
    uint16_t pkgLen = PKG_NAME_SIZE_MAX;
    uint16_t sessionLen = SESSION_NAME_SIZE_MAX;
    int32_t ret = TransProxyGetNameByChanId(channelId, pkgName, sessionName, pkgLen, sessionLen);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = TEST_NUMBER_TEN;
    ret = TransProxyGetNameByChanId(channelId, pkgName, sessionName, pkgLen, sessionLen);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetSessionKeyByChanIdTest001
 * @tc.desc: test proxy get session key by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetSessionKeyByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    char sessionKey[SESSION_KEY_LENGTH]= {TEST_NUMBER_ZERO};
    uint32_t sessionKeySize = SESSION_KEY_LENGTH;
    int32_t ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetSessionKeyByChanIdTest002
  * @tc.desc: test trans proxy check apptype and msghead.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetSessionKeyByChanIdTest002, TestSize.Level1)
{
    int32_t channelId;
    char *sessionKey = NULL;
    uint32_t sessionKeySize = SESSIONKEYSIZE;

    channelId = TEST_MESSAGE_CHANNEL_ID;
    int32_t ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = TEST_MESSAGE_CHANNEL_VALID_ID;
    ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransProxyGetAppInfoByChanIdTest001
 * @tc.desc: test proxy get app info by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetAppInfoByChanIdTest001, TestSize.Level1)
{
    AppInfo appInfo;
    int32_t channelId = TEST_NUMBER_VALID;

    int32_t ret = TransProxyGetAppInfoByChanId(channelId, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetAppInfoByChanId(channelId, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetAppInfoByChanIdTest002
  * @tc.desc: test proxy get appinfo by chanid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetAppInfoByChanIdTest002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_ERR;
    int32_t chanId = TEST_MESSAGE_CHANNEL_VALID_ID;
    AppInfo* appInfo = NULL;

    ret = TransProxyGetAppInfoByChanId(chanId, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    chanId = TEST_MESSAGE_CHANNEL_ID;
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetConnIdByChanIdTest001
 * @tc.desc: test proxy get conn id by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnIdByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    int32_t connId = TEST_NUMBER_VALID;

    int32_t ret = TransProxyGetConnIdByChanId(channelId, &connId);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = TEST_NUMBER_TEN;
    ret = TransProxyGetConnIdByChanId(channelId, &connId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetConnIdByChanIdTest002
  * @tc.desc: test proxy get connid by chanid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnIdByChanIdTest002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_ERR;
    int32_t channelId = TEST_MESSAGE_CHANNEL_ID;
    int32_t* connId = NULL;

    ret = TransProxyGetConnIdByChanId(channelId, connId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetConnOptionByChanIdTest001
 * @tc.desc: test proxy get cpnn option by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnOptionByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    ConnectOption connOpt;
    AppInfo appInfo;

    int32_t ret = TransProxyGetConnOptionByChanId(channelId, &connOpt);
    EXPECT_NE(SOFTBUS_OK, ret);

    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authId = TEST_NUMBER_TWENTY;
    chan->connId = TEST_NUMBER_TWENTY;
    chan->reqId = TEST_NUMBER_TWENTY;
    chan->channelId = TEST_NUMBER_TWENTY;
    chan->seq = TEST_NUMBER_TWENTY;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    ASSERT_TRUE(SOFTBUS_OK == ret);

    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;

    ret = TransProxyGetConnOptionByChanId(chan->channelId, &connOpt);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetConnOptionByChanIdTest002
  * @tc.desc: test proxy get connoption by chanid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnOptionByChanIdTest002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_ERR;
    int32_t channelId = TEST_MESSAGE_CHANNEL_VALID_ID;
    ConnectOption* connOpt = NULL;

    ret = TransProxyGetConnOptionByChanId(channelId, connOpt);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    connOpt = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ret = TransProxyGetConnOptionByChanId(channelId, connOpt);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channelId = TEST_MESSAGE_CHANNEL_ID;
    ret = TransProxyGetConnOptionByChanId(channelId, connOpt);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetSendMsgChanInfoTest001
 * @tc.desc: test proxy get sendmsg chanInfo by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetSendMsgChanInfoTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    ProxyChannelInfo chanInfo;

    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyChanProcessByReqIdTest001
 * @tc.desc: test proxy get sendmsg chanInfo by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyChanProcessByReqIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_25;
    uint32_t connId = TEST_NUMBER_TEN;
    char identity[TEST_ARRRY_SIZE] = {0};
    strcpy_s(identity, TEST_CHANNEL_IDENTITY_LEN, TEST_STRING_ELEVEN);
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_PYH_CONNECTING);
    TransProxyChanProcessByReqId(TEST_NUMBER_26, connId);
    usleep(TEST_NUMBER_5000);
    ProxyChannelInfo chanInfo;
    int32_t ret = TransProxyGetSendMsgChanInfo(TEST_NUMBER_25, &chanInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(PROXY_CHANNEL_STATUS_HANDSHAKEING != (uint32_t)chanInfo.status);
}

/**@
 * @tc.name: TransProxyonMessageReceivedTest001
 * @tc.desc: test proxy received handshake message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyonMessageReceivedTest001, TestSize.Level1)
{
    g_testProxyChannelOpenSuccessFlag = false;
    ProxyMessage msg;

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    (void)strcpy_s(info.appInfo.peerData.sessionName, SESSIONKEYSIZE, TEST_AUTHSESSION);
    msg.data = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;
    msg.connId = TEST_NUMBER_ELEVEN;
    msg.msgHead.myId = TEST_NUMBER_ELEVEN;
    msg.msgHead.peerId = TEST_NUMBER_ELEVEN;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    TransProxyonMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelOpenSuccessFlag);
}

/**@
 * @tc.name: TransProxyonMessageReceivedTest002
 * @tc.desc: test proxy received handshake ack message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyonMessageReceivedTest002, TestSize.Level1)
{
    ProxyMessage msg;

    g_testProxyChannelOpenSuccessFlag = false;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK;
    msg.data = TransProxyPackHandshakeErrMsg(SOFTBUS_ERR);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;

    /* test receive errcode msg */
    TransProxyonMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelOpenSuccessFlag);

    /* test receive normal msg */
    g_testProxyChannelOpenSuccessFlag = false;
    ProxyChannelInfo chan;
    chan.appInfo.appType = APP_TYPE_AUTH;
    string identity = TEST_STRING_TEN;
    (void)strcpy_s(chan.identity, TEST_CHANNEL_IDENTITY_LEN, identity.c_str());
    msg.data = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg.data);

    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;
    msg.msgHead.myId = TEST_NUMBER_TEN;
    TransProxyonMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelOpenSuccessFlag);
}


/**@
 * @tc.name: TransProxyonMessageReceivedTest003
 * @tc.desc: test proxy received reset message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyonMessageReceivedTest003, TestSize.Level1)
{
    ProxyMessage msg;
    const char *identity = TEST_STRING_ELEVEN;
    msg.data = TransProxyPackIdentity(identity);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;
    msg.connId = TEST_NUMBER_VALID;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_RESET;
    /* test no compare channel */
    msg.msgHead.myId = TEST_NUMBER_VALID;
    msg.msgHead.peerId = TEST_NUMBER_VALID;
    g_testProxyChannelClosedFlag = false;
    TransProxyonMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelClosedFlag);

    TestTransProxyAddAuthChannel(TEST_RESET_MESSAGE_CHANNEL_ID, identity, PROXY_CHANNEL_STATUS_COMPLETED);
    g_testProxyChannelClosedFlag = false;
    g_testProxyChannelOpenFailFlag = false;
    msg.msgHead.myId = TEST_RESET_MESSAGE_CHANNEL_ID;
    msg.msgHead.peerId = TEST_RESET_MESSAGE_CHANNEL_ID;
    TransProxyonMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelClosedFlag || g_testProxyChannelOpenFailFlag);
}

/**@
 * @tc.name: TransProxyonMessageReceivedTest004
 * @tc.desc: test proxy received  keepalive message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyonMessageReceivedTest004, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = 15;
    ProxyMessage msg;
    msg.msgHead.myId = channelId;
    msg.msgHead.peerId = channelId;
    const char *identity = TEST_STRING_ELEVEN;
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_KEEPLIVEING);
    msg.data = TransProxyPackIdentity(identity);
    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;

    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_KEEPALIVE;
    TransProxyonMessageReceived(&msg);

    ProxyChannelInfo chanInfo;
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(PROXY_CHANNEL_STATUS_COMPLETED, chanInfo.status);

    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_KEEPALIVE_ACK;
    TransProxyonMessageReceived(&msg);
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(PROXY_CHANNEL_STATUS_COMPLETED, chanInfo.status);
}

/**@
 * @tc.name: TransProxyonMessageReceivedTest005
 * @tc.desc: test proxy received normal message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyonMessageReceivedTest005, TestSize.Level1)
{
    ProxyMessage msg;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_NORMAL;

    msg.msgHead.myId = TEST_NUMBER_VALID;
    msg.msgHead.peerId = TEST_NUMBER_VALID;
    g_testProxyChannelReceiveFlag = false;
    TransProxyonMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);

    msg.msgHead.myId = TEST_NUMBER_TEN;
    msg.msgHead.peerId = TEST_NUMBER_TEN;
    TransProxyonMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);

    g_testProxyChannelReceiveFlag = false;
    msg.msgHead.myId = TEST_NUMBER_ELEVEN;
    msg.msgHead.peerId = TEST_NUMBER_ELEVEN;
    TransProxyonMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);
}

/**@
 * @tc.name: TransProxyCloseProxyChannelTest001
 * @tc.desc: test proxy close proxy channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyCloseProxyChannelTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    int32_t ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    TestTransProxyAddAuthChannel(29, TEST_STRING_ELEVEN, PROXY_CHANNEL_STATUS_COMPLETED);

    ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyCloseProxyChannelTest002
  * @tc.desc: test trans proxy close proxychannel.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyCloseProxyChannelTest002, TestSize.Level1)
{
    int32_t channelId = TEST_MESSAGE_CHANNEL_VALID_ID;
    int32_t ret = SOFTBUS_ERR;

    TransProxyOpenProxyChannelSuccess(channelId);

    ProxyMessage *msg = (ProxyMessage *)SoftBusCalloc(sizeof(ProxyMessage));
    msg->msgHead.cipher = TEST_NUMBER_ONE;
    msg->msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg->msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    TransProxyProcessDataRecv(msg);
    TransProxyProcessKeepAliveAck(msg);
    TransProxyProcessKeepAlive(msg);
    TransProxyProcessHandshakeAuthMsg(msg);

    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    TransProxyFastDataRecv(chan);

    TransProxyProcessResetMsg(msg);

    ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_DEL_CHANNELID_INVALID, ret);

    channelId = TEST_MESSAGE_CHANNEL_ID;
    ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelChanByChanIdTest001
 * @tc.desc: test proxy del proxy channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelChanByChanIdTest001, TestSize.Level1)
{
    TransProxyDelChanByChanId(TEST_NUMBER_VALID);

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
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelChanByReqIdTest001, TestSize.Level1)
{
    TransProxyDelChanByReqId(TEST_NUMBER_VALID, TEST_NUMBER_ONE);

    int32_t channelId = TEST_NUMBER_25;
    ProxyChannelInfo chanInfo;
    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelByConnIdTest001
 * @tc.desc: test proxy del proxy channel by connId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByConnIdTest001, TestSize.Level1)
{
    TransProxyDelByConnId(TEST_NUMBER_VALID);
    ProxyChannelInfo chan;
    int32_t channelId = TEST_BUF_LEN;
    usleep(TEST_NUMBER_5000);
    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chan);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyDelByConnIdTest002
  * @tc.desc: test trans proxy get new chanseq.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByConnIdTest002, TestSize.Level1)
{
    ProxyChannelInfo *chanInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    chanInfo->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chanInfo->peerId = TEST_PARSE_MESSAGE_CHANNEL;

    int32_t ret = TransProxyKeepAlvieChan(chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    chanInfo->peerId = TEST_MESSAGE_CHANNEL_VALID_ID;
    ret = TransProxyKeepAlvieChan(chanInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    SoftBusFree(chanInfo);
}

/**@
 * @tc.name: TransProxyDeathCallbackTest001
 * @tc.desc: test proxy TransProxyDeathCallback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDeathCallbackTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)strcpy_s(appInfo.myData.pkgName, TEST_PKG_NAME_LEN, TEST_PKGNAME);
    appInfo.appType = APP_TYPE_AUTH;
    appInfo.myData.pid = TEST_DEATH_CHANNEL_ID;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->channelId = TEST_DEATH_CHANNEL_ID;
    chan->connId = TEST_NUMBER_VALID;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;

    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);

    TransProxyDeathCallback(NULL, TEST_DEATH_CHANNEL_ID);
    TransProxyDeathCallback(TEST_PKGNAME, TEST_DEATH_CHANNEL_ID);

    ret = TransProxyGetSendMsgChanInfo(chan->channelId, chan);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: CheckAppTypeAndMsgHeadTest001
  * @tc.desc: test trans proxy check apptype and msghead.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, CheckAppTypeAndMsgHeadTest001, TestSize.Level1)
{
    ProxyMessageHead *msgHead = (ProxyMessageHead *)SoftBusCalloc(sizeof(ProxyMessageHead));
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));

    int32_t ret = CheckAppTypeAndMsgHead(msgHead, appInfo);

    msgHead->cipher = ENCRYPTED;
    appInfo->appType = APP_TYPE_AUTH;
    ret = CheckAppTypeAndMsgHead(msgHead, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ProxyMessage *msg = (ProxyMessage *)SoftBusCalloc(sizeof(ProxyMessage));
    msg->msgHead.cipher = TEST_NUMBER_ONE;
    msg->msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg->msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    TransProxyProcessHandshakeAckMsg(msg);
    SoftBusFree(msgHead);
    SoftBusFree(appInfo);
    SoftBusFree(msg);
}

/**
  * @tc.name: TransProxyGetChanByReqId001
  * @tc.desc: test trans proxy get chan by reqid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetChanByReqIdTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = NULL;
    int32_t reqId = TEST_PARSE_MESSAGE_CHANNEL;

    int32_t ret = TransProxyGetChanByReqId(reqId, chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    reqId = TEST_MESSAGE_CHANNEL_VALID_ID;
    chan = NULL;
    ret = TransProxyGetChanByReqId(reqId, chan);
    EXPECT_EQ(NULL, chan);
}


/**
 * @tc.name: TransChanIsEqualTest001
 * @tc.desc: TransChanIsEqualTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransChanIsEqualTest001, TestSize.Level1)
{
    ProxyChannelInfo info1;
    ProxyChannelInfo info2;

    info1.myId = TEST_NUMBER_ZERO;
    info1.peerId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info1.identity, sizeof(info1.identity), TEST_CHANNEL_INDENTITY);


    info2.myId = TEST_NUMBER_ZERO;
    info2.peerId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info2.identity, sizeof(info2.identity), TEST_CHANNEL_INDENTITY);

    int ret = ChanIsEqual(&info1, &info2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: TransResetChanIsEqualTest001
 * @tc.desc: TransResetChanIsEqualTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransResetChanIsEqualTest001, TestSize.Level1)
{
    int status = TEST_NUMBER_THREE;
    ProxyChannelInfo info1;
    ProxyChannelInfo info2;

    info1.myId = TEST_NUMBER_ZERO;
    info1.peerId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info1.identity, sizeof(info1.identity), TEST_CHANNEL_INDENTITY);

    info2.myId = TEST_NUMBER_ZERO;
    info2.peerId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info2.identity, sizeof(info2.identity), TEST_CHANNEL_INDENTITY);

    int32_t ret = ResetChanIsEqual(PROXY_CHANNEL_STATUS_HANDSHAKEING, &info1, &info2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = ResetChanIsEqual(status, &info1, &info2);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    info1.myId = TEST_NUMBER_TWO;
    ret = ResetChanIsEqual(status, &info1, &info2);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyUpdateAckInfoTest001
 * @tc.desc: TransProxyUpdateAckInfoTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyUpdateAckInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo testInfo;

    testInfo.myId = TEST_NUMBER_ZERO;
    testInfo.peerId = TEST_NUMBER_ZERO;
    testInfo.appInfo.encrypt = TEST_NUMBER_TWO;
    testInfo.appInfo.algorithm = TEST_NUMBER_TWO;
    testInfo.appInfo.crc = TEST_NUMBER_TWO;
    (void)strcpy_s(testInfo.identity, sizeof(testInfo.identity), TEST_CHANNEL_INDENTITY);

    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->appInfo.appType = APP_TYPE_AUTH;
    info->myId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info->identity, sizeof(info->identity), TEST_CHANNEL_INDENTITY);

    int32_t ret = TransProxyUpdateAckInfo(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyUpdateAckInfo(&testInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelByConnIdTest003
 * @tc.desc: test proxy del proxy channel by connId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByConnIdTest003, TestSize.Level1)
{
    int channelId = 1;

    int ret = TransRefreshProxyTimesNative(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->myId = 1;
    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransRefreshProxyTimesNative(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    LnnEventBasicInfo lnnInfo;
    TransWifiStateChange(NULL);
    TransWifiStateChange(&lnnInfo);
}

/**
 * @tc.name: TransChanIsEqualTest002
 * @tc.desc: TransChanIsEqualTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransChanIsEqualTest002, TestSize.Level1)
{
    ProxyChannelInfo info1;
    ProxyChannelInfo info2;

    info1.myId = 0;
    info1.peerId = 0;
    (void)strcpy_s(info1.identity, sizeof(info1.identity), TEST_CHANNEL_INDENTITY);

    info2.myId = 0;
    info2.peerId = 0;
    (void)strcpy_s(info2.identity, sizeof(info2.identity), TEST_CHANNEL_INDENTITY);

    int ret = ChanIsEqual(&info1, &info2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: TransResetChanIsEqualTest002
 * @tc.desc: TransResetChanIsEqualTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransResetChanIsEqualTest002, TestSize.Level1)
{
    int status = 3;
    ProxyChannelInfo info1;
    ProxyChannelInfo info2;

    info1.myId = 0;
    info1.peerId = 0;
    (void)strcpy_s(info1.identity, sizeof(info1.identity), TEST_CHANNEL_INDENTITY);

    info2.myId = 0;
    info2.peerId = 0;
    (void)strcpy_s(info2.identity, sizeof(info2.identity), TEST_CHANNEL_INDENTITY);

    int ret = ResetChanIsEqual(PROXY_CHANNEL_STATUS_HANDSHAKEING, &info1, &info2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = ResetChanIsEqual(status, &info1, &info2);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    info1.myId = 2;
    ret = ResetChanIsEqual(status, &info1, &info2);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyUpdateAckInfoTest002
 * @tc.desc: TransProxyUpdateAckInfoTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyUpdateAckInfoTest002, TestSize.Level1)
{
    ProxyChannelInfo testInfo;

    testInfo.myId = 0;
    testInfo.peerId = 0;
    testInfo.appInfo.encrypt = 2;
    testInfo.appInfo.algorithm = 2;
    testInfo.appInfo.crc = 2;
    (void)strcpy_s(testInfo.identity, sizeof(testInfo.identity), TEST_CHANNEL_INDENTITY);

    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->appInfo.appType = APP_TYPE_AUTH;
    info->myId = 0;
    (void)strcpy_s(info->identity, sizeof(info->identity), TEST_CHANNEL_INDENTITY);

    int32_t ret = TransProxyUpdateAckInfo(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyUpdateAckInfo(&testInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetLocalInfoTest001
 * @tc.desc: TransProxyGetLocalInfoTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetLocalInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    int ret = TransProxyGetLocalInfo(chan);
    EXPECT_NE(SOFTBUS_OK, ret);

    chan->appInfo.appType = APP_TYPE_INNER;
    ret = TransProxyGetLocalInfo(chan);
    EXPECT_NE(SOFTBUS_OK, ret);

    int16_t newChanId = 1;
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    ProxyMessage *msg = (ProxyMessage *)SoftBusCalloc(sizeof(ProxyMessage));
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));

    info.type = CONNECT_TCP;
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);
    info.type = CONNECT_BR;
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);
    info.type = CONNECT_BLE;
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);
    info.type = CONNECT_BLE_DIRECT;
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);

    TransWifiOnLineProc(NULL);

    char network[TEST_NUMBER_TWENTY]  = {0};
    strcpy_s(network, TEST_NUMBER_TWENTY, TEST_CHANNEL_INDENTITY);
    TransWifiOffLineProc(network);

    char networkId = 5;
    TransWifiOnLineProc(&networkId);
    TransWifiOffLineProc(&networkId);

    LnnEventBasicInfo lnnInfo;
    TransNotifyOffLine(NULL);
    TransNotifyOffLine(&lnnInfo);
}

} // namespace OHOS