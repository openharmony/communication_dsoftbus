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
#include "softbus_proxychannel_transceiver.c"
#include "softbus_proxychannel_manager.c"
#include "trans_channel_manager.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_PAY_LOAD "testPayLoad"
#define TEST_CHANNEL_INDENTITY "12345678"
#define TEST_PKG_NAME "com.trans.proxy.test.pkgname"

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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TestOnChannelOpened enter.");
    return SOFTBUS_OK;
}

int32_t TestOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TestOnChannelClosed enter.");
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

void TestAddTestProxyChannel(void)
{
    IServerChannelCallBack callBack;
    callBack.OnChannelOpened = TestOnChannelOpened;
    callBack.OnChannelClosed = TestOnChannelClosed;
    callBack.OnChannelOpenFailed = TestOnChannelOpenFailed;
    callBack.OnDataReceived = NULL;
    callBack.OnQosEvent = TestOnQosEvent;
    callBack.GetPkgNameBySessionName = NULL;
    callBack.GetUidAndPidBySessionName = NULL;
    TransProxyManagerInitInner(&callBack);

    m_testProxyChannelId = 1;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "test proxy calloc channel fail");
        return;
    }
    chan->myId = m_testProxyChannelId;
    chan->channelId = m_testProxyChannelId;
    chan->authId = AUTH_INVALID_ID;
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
    
    int32_t ret = TransProxyAckHandshake(0, NULL, SOFTBUS_ERR);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransProxyAckHandshake(0, &info, SOFTBUS_ERR);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    
    int32_t ret = TransProxyAckKeepalive(NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransProxyAckKeepalive(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    
    int ret = TransProxyResetPeer(&info);
    EXPECT_TRUE(ret != 0);
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