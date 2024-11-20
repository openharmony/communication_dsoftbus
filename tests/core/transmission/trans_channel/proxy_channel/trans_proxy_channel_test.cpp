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
#include "session.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "auth_interface.h"
#include "softbus_proxychannel_control.c"
#include "softbus_proxychannel_manager.c"
#include "trans_channel_manager.h"
#include "trans_log.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_PAY_LOAD "testPayLoad"
#define TEST_CHANNEL_INDENTITY "12345678"
#define TEST_PKG_NAME "com.trans.proxy.test.pkgname"
#define TEST_BUF_LEN 32
#define TEST_AUTHID 1

static int32_t m_testProxyChannelId = -1;

class TransProxyChannelTest : public testing::Test {
public:
    TransProxyChannelTest()
    {}
    ~TransProxyChannelTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransProxyChannelTest::SetUpTestCase(void)
{
}

void TransProxyChannelTest::TearDownTestCase(void)
{
}


int32_t TestOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)sessionName;
    (void)channel;
    (void)pid;
    TRANS_LOGI(TRANS_TEST, "TestOnChannelOpened enter.");
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
    TRANS_LOGI(TRANS_TEST, "TestOnChannelClosed enter.");
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
    TRANS_LOGI(TRANS_TEST, "TestOnChannelOpenFailed enter.");
    return SOFTBUS_OK;
}

int32_t TestOnQosEvent(const char *pkgName, const QosParam *param)
{
    (void)pkgName;
    (void)param;
    TRANS_LOGI(TRANS_TEST, "TestOnQosEvent enter.");
    return SOFTBUS_OK;
}

int32_t TestGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    TRANS_LOGI(TRANS_TEST, "TestGetUidAndPidBySessionName enter.");
    return SOFTBUS_OK;
}

void TestAddTestProxyChannel(int32_t authId = AUTH_INVALID_ID)
{
    IServerChannelCallBack callBack;
    callBack.OnChannelOpened = TestOnChannelOpened;
    callBack.OnChannelClosed = TestOnChannelClosed;
    callBack.OnChannelOpenFailed = TestOnChannelOpenFailed;
    callBack.OnDataReceived = NULL;
    callBack.OnQosEvent = TestOnQosEvent;
    callBack.GetPkgNameBySessionName = NULL;
    callBack.GetUidAndPidBySessionName = TestGetUidAndPidBySessionName;
    TransProxyManagerInitInner(&callBack);

    m_testProxyChannelId = 1;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        TRANS_LOGE(TRANS_TEST, "test proxy calloc channel fail");
        return;
    }
    chan->myId = m_testProxyChannelId;
    chan->channelId = m_testProxyChannelId;
    chan->authHandle.authId = authId;
    chan->appInfo.appType = APP_TYPE_NORMAL;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTED;
    if (TransProxyAddChanItem(chan) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_TEST, "test proxy add channel fail");
        SoftBusFree(chan);
    }
}

void TestDelTestProxyChannel(void)
{
    TransProxyDelChanByChanId(m_testProxyChannelId);
    m_testProxyChannelId = -1;
    TransProxyManagerDeinitInner();
}

/**
 * @tc.name: SetCipherOfHandshakeMsgTest001
 * @tc.desc: SetCipherOfHandshakeMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, SetCipherOfHandshakeMsgTest001, TestSize.Level1)
{
    TestAddTestProxyChannel();
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    chan->myId = m_testProxyChannelId;
    chan->channelId = m_testProxyChannelId;
    chan->authHandle.authId = AUTH_INVALID_ID;
    chan->appInfo.appType = APP_TYPE_NORMAL;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTED;

    int32_t ret = SetCipherOfHandshakeMsg(chan, NULL);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_GET_AUTH_ID_FAILED);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: SetCipherOfHandshakeMsgTest002
 * @tc.desc: SetCipherOfHandshakeMsgTest002, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, SetCipherOfHandshakeMsgTest002, TestSize.Level1)
{
    TestAddTestProxyChannel(TEST_AUTHID);
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    chan->myId = m_testProxyChannelId;
    chan->channelId = m_testProxyChannelId;
    chan->authHandle.authId = TEST_AUTHID;
    chan->appInfo.appType = APP_TYPE_NORMAL;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTED;

    int32_t ret = SetCipherOfHandshakeMsg(chan, NULL);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_GET_AUTH_ID_FAILED);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyHandshakeTest001
 * @tc.desc: TransProxyHandshakeTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyHandshakeTest001, TestSize.Level1)
{
    int32_t ret = TransProxyHandshake(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.myId = 0;
    info.peerId = 0;

    TestAddTestProxyChannel();
    info.channelId = m_testProxyChannelId;
    
    ret = TransProxyHandshake(&info);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_SET_CIPHER_FAILED);

    info.authHandle.authId = AUTH_INVALID_ID;
    ret = TransProxyHandshake(&info);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_SET_CIPHER_FAILED);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyAckHandshakeTest001
 * @tc.desc: TransProxyAckHandshake, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyAckHandshakeTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;

    TestAddTestProxyChannel();
    info.channelId = m_testProxyChannelId;

    int32_t ret = TransProxyAckHandshake(0, NULL, SOFTBUS_NO_INIT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransProxyAckHandshake(0, &info, SOFTBUS_NO_INIT);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);

    ret = TransProxyAckHandshake(0, &info, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);

    info.appInfo.appType = APP_TYPE_NORMAL;
    ret = TransProxyAckHandshake(0, &info, SOFTBUS_NO_INIT);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_PACKMSG_ERR);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyKeepaliveTest001
 * @tc.desc: improve branch coverage, use the wrong or normal parameter..
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyKeepaliveTest001, TestSize.Level1)
{
    int32_t connId = 0;
    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;
    int32_t ret = strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TestAddTestProxyChannel();
    info.channelId = m_testProxyChannelId;

    TransProxyKeepalive(connId, NULL);
    TransProxyKeepalive(connId, &info);
    info.appInfo.appType = APP_TYPE_NORMAL;
    TransProxyKeepalive(connId, &info);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyKeepaliveTest002
 * @tc.desc: improve branch coverage, use the wrong or normal parameter..
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyKeepaliveTest002, TestSize.Level1)
{
    int32_t connId = 0;
    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;
    int32_t ret = strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TestAddTestProxyChannel(1);
    info.channelId = m_testProxyChannelId;
    TransProxyKeepalive(connId, &info);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyAckKeepaliveTest001
 * @tc.desc: improve branch coverage, use the wrong or normal parameter..
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyAckKeepaliveTest001, TestSize.Level1)
{
    ProxyChannelInfo info;

    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    TestAddTestProxyChannel();
    info.channelId = m_testProxyChannelId;

    int32_t ret = TransProxyAckKeepalive(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransProxyAckKeepalive(&info);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);

    info.appInfo.appType = APP_TYPE_NORMAL;
    ret = TransProxyAckKeepalive(&info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyAckKeepaliveTest002
 * @tc.desc: improve branch coverage, use the wrong or normal parameter..
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyAckKeepaliveTest002, TestSize.Level1)
{
    ProxyChannelInfo info;

    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    TestAddTestProxyChannel(1);
    info.channelId = m_testProxyChannelId;

    int32_t ret = TransProxyAckKeepalive(&info);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyResetPeerTest001
 * @tc.desc: TransProxyResetPeerTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyResetPeerTest001, TestSize.Level1)
{
    ProxyChannelInfo info;

    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);

    TestAddTestProxyChannel();
    int32_t ret = TransProxyResetPeer(&info);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);
    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyResetPeerTest002
 * @tc.desc: TransProxyResetPeerTest002, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyResetPeerTest002, TestSize.Level1)
{
    ProxyChannelInfo info;

    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);

    TestAddTestProxyChannel(1);
    int32_t ret = TransProxyResetPeer(&info);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);
    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyAddChanItemTest001
 * @tc.desc: TransProxyAddChanItemTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyAddChanItemTest001, TestSize.Level1)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->appInfo.appType = APP_TYPE_AUTH;
    info->myId = 0;
    info->peerId = 0;
    info->authHandle.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info->identity, sizeof(info->identity), TEST_CHANNEL_INDENTITY);
    IServerChannelCallBack callBack;
    TransProxyManagerInitInner(&callBack);

    int32_t ret = TransProxyAddChanItem(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransProxyManagerDeinitInner();
}

/**
 * @tc.name: TransProxyProcessErrMsgTest001
 * @tc.desc: TransProxyProcessErrMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyProcessErrMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;
    int32_t ret = strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TestAddTestProxyChannel();

    info.channelId = -1;
    TransProxyProcessErrMsg(&info, SOFTBUS_NO_INIT);

    info.channelId = m_testProxyChannelId;
    TransProxyProcessErrMsg(&info, SOFTBUS_NO_INIT);

    info.appInfo.appType = APP_TYPE_NORMAL;
    TransProxyProcessErrMsg(&info, SOFTBUS_NO_INIT);

    info.appInfo.appType = APP_TYPE_NOT_CARE;
    TransProxyProcessErrMsg(&info, SOFTBUS_NO_INIT);

    TransProxyManagerDeinitInner();
}

/**
 * @tc.name: TransProxyProcessHandshakeMsgTest001
 * @tc.desc: TransProxyProcessHandshakeMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyProcessHandshakeMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authHandle.authId = AUTH_INVALID_ID;
    int32_t ret = strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TestAddTestProxyChannel();

    ProxyMessage msg;
    msg.data = TransProxyPackHandshakeMsg(&info);
    msg.dateLen = strlen(msg.data) + 1;
    TransProxyProcessHandshakeMsg(&msg);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxyCreateChanInfoTest001
 * @tc.desc: TransProxyCreateChanInfoTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyCreateChanInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->appInfo.appType = APP_TYPE_AUTH;
    info->myId = 0;
    info->peerId = 0;
    info->authHandle.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info->identity, sizeof(info->identity), TEST_CHANNEL_INDENTITY);
    IServerChannelCallBack callBack;
    TransProxyManagerInitInner(&callBack);

    ProxyChannelInfo *normalInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    AppInfo appInfo;
    appInfo.appType = APP_TYPE_NORMAL;
    int32_t ret = TransProxyCreateChanInfo(info, 1, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ProxyChannelInfo *authInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyCreateChanInfo(info, 2, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(info);
    SoftBusFree(normalInfo);
    SoftBusFree(authInfo);
}

/**
 * @tc.name: TransProxyTimerProcTest001
 * @tc.desc: TransProxyTimerProcTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyTimerProcTest001, TestSize.Level1)
{
    IServerChannelCallBack callBack;
    int32_t ret = TransProxyManagerInitInner(&callBack);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransProxyTimerProc();
    TransProxyManagerDeinitInner();
}

/**
 * @tc.name: TransProxyDestroyChannelListTest001
 * @tc.desc: TransProxyDestroyChannelListTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyDestroyChannelListTest001, TestSize.Level1)
{
    TransProxyDestroyChannelList(NULL);
    IServerChannelCallBack callBack;
    int32_t ret = TransProxyManagerInitInner(&callBack);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListNode destroyList;
    ListInit(&destroyList);
    TransProxyDestroyChannelList(&destroyList);
    TransProxyManagerDeinitInner();
}

/**
 * @tc.name: TransProxyDeathCallbackTest001
 * @tc.desc: TransProxyDeathCallbackTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyDeathCallbackTest001, TestSize.Level1)
{
    int32_t pid = 1;
    const char *pkgName = "com.test.trans.proxy.channel.demo";

    IServerChannelCallBack callBack;
    int32_t ret = TransProxyManagerInitInner(&callBack);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransProxyDeathCallback(NULL, pid);
    TransProxyDeathCallback(pkgName, pid);

    TransProxyManagerDeinitInner();
}

/**
 * @tc.name: TransProxyPackMessageHeadTest001
 * @tc.desc: TransProxyPackMessageHeadTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyPackMessageHeadTest001, TestSize.Level1)
{
    IServerChannelCallBack callBack;
    int32_t ret = TransProxyManagerInitInner(&callBack);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransProxyManagerDeinitInner();
}

/**
 * @tc.name: TransProxyParseMessageTest001
 * @tc.desc: TransProxyParseMessageTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyParseMessageTest001, TestSize.Level1)
{
    ProxyDataInfo dataInfo;
    char *data = (char *)dataInfo.outData;
    int32_t len = dataInfo.outLen;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    
    ProxyMessage msg;
    int32_t ret = TransProxyParseMessage(data, len, &msg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK;
    ret = TransProxyParseMessage(data, len, &msg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyParseMessage(data, PROXY_CHANNEL_HEAD_LEN - 1, &msg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransGetConnIdByChanIdTest001
 * @tc.desc: TransGetConnIdByChanIdTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransGetConnIdByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t connId = -1;
    int32_t channelType = -1;
    TestAddTestProxyChannel();
    
    int32_t ret = TransGetConnByChanId(channelId, 0, &connId);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyChannelId;
    ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_NE(SOFTBUS_OK, ret);

    TestDelTestProxyChannel();
}

/**
 * @tc.name: TransProxySendInnerMessageTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null channelInfo.
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_PACKMSG_ERR when given invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxySendInnerMessageTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    memset_s(&info, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    uint32_t payLoadLen = 12;
    int32_t priority = 1;

    int32_t ret = TransProxySendInnerMessage(nullptr, TEST_PAY_LOAD, payLoadLen, priority);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    info.myId = 1;
    info.peerId = 1;
    info.authHandle.authId = 1;
    ret = TransProxySendInnerMessage(&info, TEST_PAY_LOAD, payLoadLen, priority);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/**
 * @tc.name: ConvertConnectType2AuthLinkTypeTest001
 * @tc.desc: Should return corresponding link type when given different connect types.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, ConvertConnectType2AuthLinkTypeTest001, TestSize.Level1)
{
    ConnectType type = CONNECT_TCP;
    AuthLinkType ret = ConvertConnectType2AuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_WIFI);
    type = CONNECT_BLE;
    ret = ConvertConnectType2AuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_BLE);
    type = CONNECT_BLE_DIRECT;
    ret = ConvertConnectType2AuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_BLE);
    type = CONNECT_BR;
    ret = ConvertConnectType2AuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_BR);
    type = CONNECT_P2P;
    ret = ConvertConnectType2AuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_P2P);
}
} // namespace OHOS