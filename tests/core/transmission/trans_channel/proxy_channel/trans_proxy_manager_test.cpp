/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "trans_conn_mock.h"
#include "trans_common_mock.h"
#include "trans_channel_callback.h"
#include "trans_channel_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_PAY_LOAD "testPayLoad"
#define TEST_CHANNEL_INDENTITY "12345678"
#define TEST_PKG_NAME "com.trans.proxy.test.pkgname"
#define TEST_BUF_LEN 32
#define TEST_INVALID_LARGE_SIZE (100 * 1024)
#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_RESET_MESSAGE_CHANNEL_ID 30
#define TEST_DEATH_CHANNEL_ID 14
#define TEST_PKG_NAME_LEN 65

static int32_t m_testProxyAuthChannelId = -1;
static int32_t m_testProxyNormalChannelId = -1;
static int32_t m_testProxyConningChannel = -1;

static bool g_testProxyChannelOpenSuccessFlag = false;
static bool g_testProxyChannelOpenFailFlag = false;
static bool g_testProxyChannelClosedFlag = false;
static bool g_testProxyChannelReceiveFlag = false;
static bool g_testNetworkChannelOpenFailFlag = false;

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

int32_t TestOnDataReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)receiveData;
    g_testProxyChannelReceiveFlag = true;
    printf("TestOnDataReceived enter.\n");
    return SOFTBUS_OK;
}

int32_t TestOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)sessionName;
    (void)channel;
    (void)pid;
    printf("TestOnChannelOpened enter.\n");
    g_testProxyChannelOpenSuccessFlag = true;
    return SOFTBUS_OK;
}

int32_t TestOnChannelClosed(const char *pkgName, int32_t pid,
    int32_t channelId, int32_t channelType, int32_t messageType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)messageType;
    g_testProxyChannelClosedFlag = true;
    printf("TestOnChannelClosed enter.\n");
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
    printf("TestOnChannelOpenFailed enter.\n");
    return SOFTBUS_OK;
}

int32_t TestGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    printf("TestGetUidAndPidBySessionName enter.\n");
    return SOFTBUS_OK;
}

extern "C" {
int32_t TestGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    (void)sessionName;
    (void)pkgName;
    (void)len;
    printf("TestGetPkgNameBySessionName enter.\n");
    return SOFTBUS_OK;
}
}

void TestOnNetworkingChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)channelId;
    (void)uuid;
    g_testNetworkChannelOpenFailFlag = true;
    printf("TestOnNetworkingChannelOpenFailed enter.\n");
    return;
}

void TransProxyManagerTest::SetUpTestCase(void)
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
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnSetConnectCallback).WillRepeatedly(Return(SOFTBUS_OK));
    ASSERT_EQ(SOFTBUS_OK, TransProxyManagerInit(&callBack));
}

void TransProxyManagerTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

void TestTransProxyAddAuthChannel(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));

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
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void TestTransProxyAddNormalChannel(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    TransCommInterfaceMock commMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusGenerateRandomArray)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthGetLatestIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_OK));

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
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransProxyAuthSessionDataLenCheckTest001
 * @tc.desc: test proxy auth session data len check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyAuthSessionDataLenCheckTest001, TestSize.Level1)
{
    int32_t ret = TransProxyAuthSessionDataLenCheck(TEST_INVALID_LARGE_SIZE, PROXY_FLAG_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyAuthSessionDataLenCheck(1, PROXY_FLAG_MESSAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransProxyAuthSessionDataLenCheck(1, PROXY_FLAG_ASYNC_MESSAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransProxyAuthSessionDataLenCheck(TEST_INVALID_LARGE_SIZE, PROXY_FLAG_BYTES);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyAuthSessionDataLenCheck(1, PROXY_FLAG_ACK);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    int32_t ret = TransProxyOpenProxyChannel(NULL, &connInfo, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenProxyChannel(&appInfo, NULL, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyOpenProxyChannelTest002
 * @tc.desc: test proxy open proxy channel, use normal param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyOpenProxyChannelTest002, TestSize.Level1)
{
    AppInfo appInfo;
    int32_t channelId = -1;
    ConnectOption connInfo;

    TransConnInterfaceMock connMock;
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnConnectDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetNewRequestId)
        .WillOnce(Return(1));

    appInfo.appType = APP_TYPE_AUTH;
    int32_t ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, &channelId);
    ASSERT_EQ(SOFTBUS_OK, ret);
    m_testProxyConningChannel = channelId;
    printf("new channel1 id:%d.\n", channelId);
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
    EXPECT_CALL(commMock, SoftBusGenerateRandomArray)
        .WillRepeatedly(Return(SOFTBUS_OK));
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthGetLatestIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_OK));
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    AppInfo appInfo;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authId = 10;
    chan->connId = 10;
    chan->myId = 10;
    chan->peerId = 10;
    chan->reqId = 10;
    chan->channelId = 10;
    chan->seq = 10;
    (void)strcpy_s(chan->identity, 33, "10");
    appInfo.appType = APP_TYPE_AUTH;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    chan->status = PROXY_CHANNEL_STATUS_COMPLETED;
    ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    m_testProxyAuthChannelId = chan->channelId;

    ProxyChannelInfo *chanNormal = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chanNormal);
    chanNormal->authId = 11;
    chanNormal->connId = 11;
    chanNormal->myId = 11;
    chanNormal->peerId = 11;
    chanNormal->reqId = 11;
    chanNormal->channelId = 11;
    chanNormal->seq = 11;
    (void)strcpy_s(chanNormal->identity, 33, "11");

    chanNormal->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    appInfo.appType = APP_TYPE_NORMAL;
    ret = TransProxyCreateChanInfo(chanNormal, chanNormal->channelId, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    m_testProxyNormalChannelId = chanNormal->channelId;
}

/**@
 * @tc.name: TransProxySendMsgTest001
 * @tc.desc: test proxy send message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxySendMsgTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;

    const char *data = "test data";
    uint32_t dataLen = strlen(data);
    int32_t channelId = -1;
    int32_t priority = 0;
    TransAuthInterfaceMock authMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize)
        .WillRepeatedly(Return(35));
    EXPECT_CALL(authMock, AuthEncrypt)
        .WillRepeatedly(Return(SOFTBUS_OK));

    ret = TransProxySendMsg(channelId, data, dataLen, priority);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test proxy channel status not keepalive or complete */
    channelId = m_testProxyConningChannel;
    ret = TransProxySendMsg(channelId, data, dataLen, priority);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxySendMsg(channelId, data, dataLen, priority);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    printf("new chan seq :%d\n", channelId);
    int32_t ret = TransProxyGetNewChanSeq(channelId);
    EXPECT_NE(0, ret);

    ret = TransProxyGetNewChanSeq(-1);
    EXPECT_EQ(0, ret);
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
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetAuthId(channelId, &authHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authId = 20;
    chan->connId = 20;
    chan->reqId = 20;
    chan->channelId = 20;
    chan->seq = 20;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo(_, _))
        .WillRepeatedly(DoAll(SetArgPointee<1>(tcpInfo), Return(SOFTBUS_OK)));
    TransCreateConnByConnId(20);

    ret = TransProxyGetConnOptionByChanId(chan->channelId, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusBase64Encode)
        .WillRepeatedly(Return(SOFTBUS_OK));
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(sizeof(ConnPktHead)));

    TransProxyChanProcessByReqId(channelId, channelId, errCode);
    usleep(500000);
    ProxyChannelInfo chanInfo;
    int32_t ret = TransProxyGetSendMsgChanInfo(m_testProxyConningChannel, &chanInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(PROXY_CHANNEL_STATUS_HANDSHAKEING != (uint32_t)chanInfo.status);
}

/**
 * @tc.name: TransProxyOpenProxyChannelFailTest001
 * @tc.desc: test proxy open channel fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyOpenProxyChannelFailTest001, TestSize.Level1)
{
    AppInfo appInfo;
    int32_t errCode = SOFTBUS_MEM_ERR;

    appInfo.appType = APP_TYPE_AUTH;
    g_testProxyChannelOpenFailFlag = false;
    TransProxyOpenProxyChannelFail(-1, &appInfo, errCode);
    EXPECT_EQ(true, g_testProxyChannelOpenFailFlag);

    INetworkingListener listener;
    listener.onChannelOpenFailed = TestOnNetworkingChannelOpenFailed;
    int32_t ret = TransRegisterNetworkingChannelListener(&listener);
    ASSERT_EQ(SOFTBUS_OK, ret);
    g_testNetworkChannelOpenFailFlag = false;
    appInfo.appType = APP_TYPE_INNER;
    TransProxyOpenProxyChannelFail(-1, &appInfo, errCode);
    EXPECT_EQ(true, g_testNetworkChannelOpenFailFlag);
}

/**@
 * @tc.name: TransProxyOnMessageReceivedTest001
 * @tc.desc: test proxy received handshake message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyOnMessageReceivedTest001, TestSize.Level1)
{
    g_testProxyChannelOpenSuccessFlag = false;
    ProxyMessage msg;
    TransCommInterfaceMock commMock;
    TransConnInterfaceMock connMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetConnectionInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetNetworkIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    (void)strcpy_s(info.appInfo.peerData.sessionName, 256, "IShareAuthSession");
    msg.data = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + 1;
    msg.connId = 11;
    msg.msgHead.myId = 11;
    msg.msgHead.peerId = 11;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    TransProxyOnMessageReceived(&msg);
    EXPECT_TRUE(g_testProxyChannelOpenSuccessFlag);
}

/**@
 * @tc.name: TransProxyOnMessageReceivedTest002
 * @tc.desc: test proxy received handshake ack message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyOnMessageReceivedTest002, TestSize.Level1)
{
    ProxyMessage msg;

    g_testProxyChannelOpenSuccessFlag = false;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK;
    msg.data = TransProxyPackHandshakeErrMsg(SOFTBUS_MEM_ERR);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + 1;

    /* test receive errcode msg */
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelOpenSuccessFlag);

    /* test receive normal msg */
    g_testProxyChannelOpenSuccessFlag = false;
    ProxyChannelInfo chan;
    chan.appInfo.appType = APP_TYPE_AUTH;
    string identity = "10";
    (void)strcpy_s(chan.identity, 33, identity.c_str());
    msg.data = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg.data);

    msg.dateLen = strlen(msg.data) + 1;
    msg.msgHead.myId = 10;
    TransProxyOnMessageReceived(&msg);
    EXPECT_TRUE(g_testProxyChannelOpenSuccessFlag);
}


/**@
 * @tc.name: TransProxyOnMessageReceivedTest003
 * @tc.desc: test proxy received reset message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyOnMessageReceivedTest003, TestSize.Level1)
{
    ProxyMessage msg;
    const char *identity = "30";
    msg.data = TransProxyPackIdentity(identity);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + 1;
    msg.connId = -1;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_RESET;
    /* test no compare channel */
    msg.msgHead.myId = -1;
    msg.msgHead.peerId = -1;
    g_testProxyChannelClosedFlag = false;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelClosedFlag);

    /* test cpmpare exist channel */
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnDisconnectDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
    TestTransProxyAddAuthChannel(TEST_RESET_MESSAGE_CHANNEL_ID, identity, PROXY_CHANNEL_STATUS_COMPLETED);
    g_testProxyChannelClosedFlag = false;
    g_testProxyChannelOpenFailFlag = false;
    msg.msgHead.myId = TEST_RESET_MESSAGE_CHANNEL_ID;
    msg.msgHead.peerId = TEST_RESET_MESSAGE_CHANNEL_ID;
    TransProxyOnMessageReceived(&msg);
    EXPECT_TRUE(g_testProxyChannelClosedFlag || g_testProxyChannelOpenFailFlag);
}

/**@
 * @tc.name: TransProxyOnMessageReceivedTest004
 * @tc.desc: test proxy received  keepalive message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyManagerTest, TransProxyOnMessageReceivedTest004, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = 15;
    ProxyMessage msg;
    msg.msgHead.myId = channelId;
    msg.msgHead.peerId = channelId;
    const char *identity = "15";
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_KEEPLIVEING);
    msg.data = TransProxyPackIdentity(identity);
    msg.dateLen = strlen(msg.data) + 1;

    TransAuthInterfaceMock authMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(authMock, AuthGetEncryptSize)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthEncrypt)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(sizeof(ConnPktHead)));

    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_KEEPALIVE;
    TransProxyOnMessageReceived(&msg);

    ProxyChannelInfo chanInfo;
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(PROXY_CHANNEL_STATUS_COMPLETED, chanInfo.status);

    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_KEEPALIVE_ACK;
    TransProxyOnMessageReceived(&msg);
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(PROXY_CHANNEL_STATUS_COMPLETED, chanInfo.status);
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
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnDisconnectDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));

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
    TransProxyDelChanByChanId(-1);

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
    TransProxyDelChanByReqId(-1);

    int32_t channelId = 31;
    const char *identity = "31";
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_PYH_CONNECTING);
    TransProxyDelChanByReqId(channelId);
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
    TransProxyDelByConnId(-1);

    TransCommInterfaceMock commMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnDisconnectDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));

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
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->channelId = TEST_DEATH_CHANNEL_ID;
    chan->connId = -1;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;

    TransCommInterfaceMock commMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnDisconnectDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);

    TransProxyDeathCallback(NULL, TEST_DEATH_CHANNEL_ID);
    TransProxyDeathCallback("com.test.pkgname", TEST_DEATH_CHANNEL_ID);

    ret = TransProxyGetSendMsgChanInfo(chan->channelId, chan);
    EXPECT_NE(SOFTBUS_OK, ret);
}

} // namespace OHOS