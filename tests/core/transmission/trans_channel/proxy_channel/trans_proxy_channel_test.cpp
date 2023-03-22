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
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"
#include "auth_interface.h"
#include "softbus_proxychannel_control.c"
#include "softbus_proxychannel_transceiver.c"
#include "softbus_proxychannel_message.c"
#include "softbus_proxychannel_manager.c"
#include "trans_channel_manager.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_PAY_LOAD "testPayLoad"
#define TEST_CHANNEL_INDENTITY "12345678"
#define TEST_PKG_NAME "com.trans.proxy.test.pkgname"
#define TEST_BUF_LEN 32

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


int32_t TestOnChannelOpened(const char *pkgName, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)sessionName;
    (void)channel;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TestOnChannelOpened enter.");
    return SOFTBUS_OK;
}

int32_t TestOnChannelClosed(const char *pkgName, int32_t channelId, int32_t channelType)
{
    (void)pkgName;
    (void)channelId;
    (void)channelType;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TestOnChannelClosed enter.");
    return SOFTBUS_OK;
}

int32_t TestOnChannelOpenFailed(const char *pkgName, int32_t channelId,
    int32_t channelType, int32_t errCode)
{
    (void)pkgName;
    (void)channelId;
    (void)channelType;
    (void)errCode;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TestOnChannelOpenFailed enter.");
    return SOFTBUS_OK;
}

int32_t TestOnQosEvent(const char *pkgName, const QosParam *param)
{
    (void)pkgName;
    (void)param;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TestOnQosEvent enter.");
    return SOFTBUS_OK;
}

int32_t TestGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TestGetUidAndPidBySessionName enter.");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "test proxy calloc channel fail");
        return;
    }
    chan->myId = m_testProxyChannelId;
    chan->channelId = m_testProxyChannelId;
    chan->authId = authId;
    chan->appInfo.appType = APP_TYPE_NORMAL;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTED;
    if (TransProxyAddChanItem(chan) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "test proxy add channel fail");
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
 * @tc.name: TransProxySendMessageTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxySendMessageTest001, TestSize.Level1)
{
    const char *payLoad = TEST_PAY_LOAD;
    uint32_t payLoadLen = strlen(payLoad);
    int32_t ret = TransProxySendMessage(NULL, payLoad, payLoadLen, 0);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authId = AUTH_INVALID_ID;
    
    ret = TransProxySendMessage(&info, NULL, 0, 0);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransProxySendMessage(&info, payLoad, payLoadLen, 0);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    info.authId = 0;
    ret = TransProxySendMessage(&info, payLoad, payLoadLen, 0);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransProxySendMessageTest002
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxySendMessageTest002, TestSize.Level1)
{
    const char *payLoad = TEST_PAY_LOAD;
    uint32_t payLoadLen = strlen(payLoad);

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.myId = 0;
    info.peerId = 0;
    info.authId = AUTH_INVALID_ID;
    info.connId = -1;

    int32_t ret = TransProxySendMessage(&info, payLoad, payLoadLen, 0);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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

    int32_t ret = SetCipherOfHandshakeMsg(m_testProxyChannelId, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

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
    TestAddTestProxyChannel(1);

    int32_t ret = SetCipherOfHandshakeMsg(m_testProxyChannelId, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

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
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.myId = 0;
    info.peerId = 0;

    TestAddTestProxyChannel();
    info.channelId = m_testProxyChannelId;
    
    ret = TransProxyHandshake(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    info.authId = AUTH_INVALID_ID;
    ret = TransProxyHandshake(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

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
    info.authId = AUTH_INVALID_ID;

    TestAddTestProxyChannel();
    info.channelId = m_testProxyChannelId;

    int32_t ret = TransProxyAckHandshake(0, NULL, SOFTBUS_ERR);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransProxyAckHandshake(0, &info, SOFTBUS_ERR);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransProxyAckHandshake(0, &info, SOFTBUS_OK);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    info.appInfo.appType = APP_TYPE_NORMAL;
    ret = TransProxyAckHandshake(0, &info, SOFTBUS_ERR);
    EXPECT_TRUE(ret != SOFTBUS_OK);

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
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);

    TestAddTestProxyChannel();
    info.channelId = m_testProxyChannelId;

    TransProxyKeepalive(connId, NULL);
    TransProxyKeepalive(connId, &info);
    info.appInfo.appType = APP_TYPE_NORMAL;
    TransProxyKeepalive(connId, &info);

    TestDelTestProxyChannel();
    EXPECT_TRUE(true);
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
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);

    TestAddTestProxyChannel(1);
    info.channelId = m_testProxyChannelId;
    TransProxyKeepalive(connId, &info);

    TestDelTestProxyChannel();
    EXPECT_TRUE(true);
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
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    TestAddTestProxyChannel();
    info.channelId = m_testProxyChannelId;

    int32_t ret = TransProxyAckKeepalive(NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransProxyAckKeepalive(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    info.appInfo.appType = APP_TYPE_NORMAL;
    ret = TransProxyAckKeepalive(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

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
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    TestAddTestProxyChannel(1);
    info.channelId = m_testProxyChannelId;

    int32_t ret = TransProxyAckKeepalive(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

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
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);

    TestAddTestProxyChannel();
    int ret = TransProxyResetPeer(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);

    TestAddTestProxyChannel(1);
    int ret = TransProxyResetPeer(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    info->authId = AUTH_INVALID_ID;
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
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    TestAddTestProxyChannel();

    info.channelId = -1;
    TransProxyProcessErrMsg(&info, SOFTBUS_ERR);

    info.channelId = m_testProxyChannelId;
    TransProxyProcessErrMsg(&info, SOFTBUS_ERR);

    info.appInfo.appType = APP_TYPE_NORMAL;
    TransProxyProcessErrMsg(&info, SOFTBUS_ERR);

    info.appInfo.appType = APP_TYPE_NOT_CARE;
    TransProxyProcessErrMsg(&info, SOFTBUS_ERR);

    TransProxyManagerDeinitInner();
    EXPECT_TRUE(true);
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
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), TEST_CHANNEL_INDENTITY);
    TestAddTestProxyChannel();

    ProxyMessage msg;
    msg.data = TransProxyPackHandshakeMsg(&info);
    msg.dateLen = strlen(msg.data) + 1;
    TransProxyProcessHandshakeMsg(&msg);

    TestDelTestProxyChannel();
    EXPECT_TRUE(true);
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
    info->authId = AUTH_INVALID_ID;
    (void)strcpy_s(info->identity, sizeof(info->identity), TEST_CHANNEL_INDENTITY);
    IServerChannelCallBack callBack;
    TransProxyManagerInitInner(&callBack);

    AppInfo appInfo;
    appInfo.appType = APP_TYPE_NORMAL;
    int32_t ret = TransProxyCreateChanInfo(info, 1, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyCreateChanInfo(info, 1, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransProxyManagerDeinitInner();
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
    TransProxyManagerInitInner(&callBack);

    TransProxyTimerProc();
    TransProxyManagerDeinitInner();
    EXPECT_TRUE(true);
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

    ListNode destroyList;
    ListInit(&destroyList);
    TransProxyDestroyChannelList(&destroyList);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: TransProxyDeathCallbackTest001
 * @tc.desc: TransProxyDeathCallbackTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyDeathCallbackTest001, TestSize.Level1)
{
    const char *pkgName = "com.test.trans.proxy.channel.demo";

    IServerChannelCallBack callBack;
    TransProxyManagerInitInner(&callBack);

    TransProxyDeathCallback(NULL);
    TransProxyDeathCallback(pkgName);

    TransProxyManagerDeinitInner();
    EXPECT_TRUE(true);
}

/**
 * @tc.name: TransProxyPackMessageHeadTest001
 * @tc.desc: TransProxyPackMessageHeadTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyPackMessageHeadTest001, TestSize.Level1)
{
    ProxyMessageHead msgHead;
    uint8_t buf[TEST_BUF_LEN] = {0};
    TransProxyPackMessageHead(&msgHead, (uint8_t *)buf, PROXY_CHANNEL_HEAD_LEN - 1);
    TransProxyPackMessageHead(&msgHead, (uint8_t *)buf, PROXY_CHANNEL_HEAD_LEN);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: GetRemoteUdidByBtMacTest001
 * @tc.desc: GetRemoteUdidByBtMacTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, GetRemoteUdidByBtMacTest001, TestSize.Level1)
{
    string peerMac = "";
    string udid = "";
    int32_t len = 1;
    int32_t ret = GetRemoteUdidByBtMac(peerMac.c_str(), (char *)udid.c_str(), len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetAuthConnInfoTest001
 * @tc.desc: TransProxyGetAuthConnInfoTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyGetAuthConnInfoTest001, TestSize.Level1)
{
    int32_t connId = 1;
    AuthConnInfo connInfo;
    int32_t ret = TransProxyGetAuthConnInfo(connId, &connInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: GetAuthIdByHandshakeMsgTest001
 * @tc.desc: GetAuthIdByHandshakeMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, GetAuthIdByHandshakeMsgTest001, TestSize.Level1)
{
    uint32_t connId = 1;
    uint8_t cipher = 1;
    int32_t ret = GetAuthIdByHandshakeMsg(connId, cipher);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyParseMessageTest001
 * @tc.desc: TransProxyParseMessageTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyParseMessageTest001, TestSize.Level1)
{
    ProxyMessageHead head;
    ProxyDataInfo dataInfo;
    head.cipher |= ENCRYPTED;
    head.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    PackPlaintextMessage(&head, &dataInfo);
    char *data = (char *)dataInfo.outData;
    int32_t len = dataInfo.outLen;
    
    ProxyMessage msg;
    int32_t ret = TransProxyParseMessage(data, len, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);

    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK;
    ret = TransProxyParseMessage(data, len, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyParseMessage(data, PROXY_CHANNEL_HEAD_LEN - 1, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: PackEncryptedMessageTest001
 * @tc.desc: PackEncryptedMessageTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, PackEncryptedMessageTest001, TestSize.Level1)
{
    ProxyMessageHead msg;
    int64_t authId = AUTH_INVALID_ID;
    ProxyDataInfo dataInfo;
    int32_t ret = PackEncryptedMessage(&msg, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = PackEncryptedMessage(&msg, 1, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyPackMessageTest001
 * @tc.desc: TransProxyPackMessageTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyPackMessageTest001, TestSize.Level1)
{
    ProxyMessageHead msg;
    int64_t authId = AUTH_INVALID_ID;
    ProxyDataInfo dataInfo;
    int32_t ret = TransProxyPackMessage(NULL, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyPackMessage(&msg, authId, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    dataInfo.inData = NULL;
    ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    dataInfo.inData = 0;
    ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    dataInfo.inData = (uint8_t *)"1";
    msg.cipher |= ENCRYPTED;
    msg.type = PROXYCHANNEL_MSG_TYPE_NORMAL;
    ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    msg.cipher = 0;
    msg.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyPackHandshakeErrMsgTest001
 * @tc.desc: TransProxyPackHandshakeErrMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyPackHandshakeErrMsgTest001, TestSize.Level1)
{
    (void)TransProxyPackHandshakeErrMsg(SOFTBUS_ERR);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: TransProxyUnPackHandshakeErrMsgTest001
 * @tc.desc: TransProxyUnPackHandshakeErrMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyUnPackHandshakeErrMsgTest001, TestSize.Level1)
{
    const char *msg = "";
    int32_t errCode = 1;
    int32_t ret = TransProxyUnPackHandshakeErrMsg(msg, &errCode, strlen(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *err = TransProxyPackHandshakeErrMsg(SOFTBUS_ERR);
    ASSERT_TRUE(NULL != err);

    ret = TransProxyUnPackHandshakeErrMsg(err, &errCode, strlen(err));
    EXPECT_TRUE(true);
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

} // namespace OHOS