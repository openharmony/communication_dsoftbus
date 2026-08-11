/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "softbus_error_code.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_network.h"
#include "softbus_transmission_interface.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_SESSION_NAME       "SoftBusProxyChannelNetworkTest"
#define TEST_CHANNEL_ID         1
#define TEST_INVALID_CHANNEL_ID (-1)
#define TEST_MSG_DATA           "test data"

class TransProxyNetworkTest : public testing::Test {
public:
    TransProxyNetworkTest() { }
    ~TransProxyNetworkTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {
        m_channelOpenFailedFlag = false;
        m_channelClosedFlag = false;
        m_messageReceivedFlag = false;
    }
    void TearDown() override { }

    static int32_t TestOnNetworkChannelOpened(int32_t channelId, const char *uuid, unsigned char isServer);
    static void TestOnNetworkChannelOpenFailed(int32_t channelId, const char *uuid);
    static void TestOnNetworkChannelClosed(int32_t channelId);
    static void TestOnNetworkMessageReceived(int32_t channelId, const char *data, uint32_t len);
    static void TestRegisterNetworkingChannelListener(void);

    static bool m_channelOpenFailedFlag;
    static bool m_channelClosedFlag;
    static bool m_messageReceivedFlag;
};

bool TransProxyNetworkTest::m_channelClosedFlag = false;
bool TransProxyNetworkTest::m_channelOpenFailedFlag = false;
bool TransProxyNetworkTest::m_messageReceivedFlag = false;

int32_t TestNormalChannelOpened(const char *pkgName, int32_t pid, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)pid;
    (void)sessionName;
    (void)channel;
    return SOFTBUS_OK;
}

int32_t TestChannelDataReceived(
    const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType, TransReceiveData *receiveData)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)receiveData;
    return SOFTBUS_OK;
}

void TransProxyNetworkTest::SetUpTestCase(void)
{
    IServerChannelCallBack cb = { };
    cb.OnChannelOpened = TestNormalChannelOpened;
    cb.OnDataReceived = TestChannelDataReceived;
    ASSERT_EQ(SOFTBUS_OK, TransProxySetCallBack(&cb));
}

void TransProxyNetworkTest::TearDownTestCase(void) { }

int32_t TransProxyNetworkTest::TestOnNetworkChannelOpened(int32_t channelId, const char *uuid, unsigned char isServer)
{
    (void)channelId;
    (void)uuid;
    (void)isServer;
    printf("test on networking channel opened.\n");
    return SOFTBUS_OK;
}

void TransProxyNetworkTest::TestOnNetworkChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)channelId;
    (void)uuid;
    printf("test on network channel open failed.\n");
    TransProxyNetworkTest::m_channelOpenFailedFlag = true;
}

void TransProxyNetworkTest::TestOnNetworkChannelClosed(int32_t channelId)
{
    (void)channelId;
    printf("test on networking channel closed.\n");
    TransProxyNetworkTest::m_channelClosedFlag = true;
}

void TransProxyNetworkTest::TestOnNetworkMessageReceived(int32_t channelId, const char *data, uint32_t len)
{
    (void)channelId;
    (void)data;
    (void)len;
    printf("test on networking message received.\n");
    TransProxyNetworkTest::m_messageReceivedFlag = true;
}

void TransProxyNetworkTest::TestRegisterNetworkingChannelListener(void)
{
    INetworkingListener listener = { };
    listener.onChannelClosed = TransProxyNetworkTest::TestOnNetworkChannelClosed;
    listener.onChannelOpened = TransProxyNetworkTest::TestOnNetworkChannelOpened;
    listener.onChannelOpenFailed = TransProxyNetworkTest::TestOnNetworkChannelOpenFailed;
    listener.onMessageReceived = TransProxyNetworkTest::TestOnNetworkMessageReceived;
    int32_t ret = TransRegisterNetworkingChannelListener(TEST_SESSION_NAME, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: NotifyNetworkingNoListenerTest001
 * @tc.desc: verify Notify functions return error or do not invoke callbacks when no listener is registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, NotifyNetworkingNoListenerTest001, TestSize.Level1)
{
    int32_t ret = NotifyNetworkingChannelOpened(TEST_SESSION_NAME, TEST_CHANNEL_ID, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);
    NotifyNetworkingChannelOpenFailed(TEST_SESSION_NAME, TEST_CHANNEL_ID, nullptr);
    EXPECT_FALSE(m_channelOpenFailedFlag);
    NotifyNetworkingChannelClosed(TEST_SESSION_NAME, TEST_CHANNEL_ID);
    EXPECT_FALSE(m_channelClosedFlag);
    NotifyNetworkingMsgReceived(TEST_SESSION_NAME, TEST_CHANNEL_ID, nullptr, 0);
    EXPECT_FALSE(m_messageReceivedFlag);
}

/*
 * @tc.name: NotifyNetworkingWithListenerTest001
 * @tc.desc: verify Notify functions invoke callbacks after registering networking channel listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, NotifyNetworkingWithListenerTest001, TestSize.Level1)
{
    TestRegisterNetworkingChannelListener();
    int32_t ret = NotifyNetworkingChannelOpened(TEST_SESSION_NAME, TEST_CHANNEL_ID, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NotifyNetworkingChannelOpenFailed(TEST_SESSION_NAME, TEST_CHANNEL_ID, nullptr);
    EXPECT_TRUE(m_channelOpenFailedFlag);
    NotifyNetworkingChannelClosed(TEST_SESSION_NAME, TEST_CHANNEL_ID);
    EXPECT_TRUE(m_channelClosedFlag);
    NotifyNetworkingMsgReceived(TEST_SESSION_NAME, TEST_CHANNEL_ID, nullptr, 0);
    EXPECT_FALSE(m_messageReceivedFlag);
}

/*
 * @tc.name: OnProxyChannelOpenFailedNullParamTest001
 * @tc.desc: OnProxyChannelOpenFailed with null appInfo returns SOFTBUS_INVALID_PARAM,
 *           and APP_TYPE_NOT_CARE returns SOFTBUS_INVALID_APPTYPE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, OnProxyChannelOpenFailedNullParamTest001, TestSize.Level1)
{
    int32_t channelId = TEST_INVALID_CHANNEL_ID;
    int32_t ret = OnProxyChannelOpenFailed(channelId, nullptr, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    AppInfo appInfo = { };
    appInfo.appType = APP_TYPE_NOT_CARE;
    ret = OnProxyChannelOpenFailed(channelId, &appInfo, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_INVALID_APPTYPE, ret);
}

/*
 * @tc.name: OnProxyChannelClosedNullParamTest001
 * @tc.desc: OnProxyChannelClosed with null appInfo returns SOFTBUS_INVALID_PARAM,
 *           and APP_TYPE_NOT_CARE returns SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, OnProxyChannelClosedNullParamTest001, TestSize.Level1)
{
    int32_t channelId = TEST_INVALID_CHANNEL_ID;
    int32_t ret = OnProxyChannelClosed(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    AppInfo appInfo = { };
    appInfo.appType = APP_TYPE_NOT_CARE;
    ret = OnProxyChannelClosed(channelId, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
}

/*
 * @tc.name: OnProxyChannelClosedInnerAppTypeTest001
 * @tc.desc: OnProxyChannelClosed with APP_TYPE_INNER returns SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, OnProxyChannelClosedInnerAppTypeTest001, TestSize.Level1)
{
    AppInfo appInfo = { };
    appInfo.appType = APP_TYPE_INNER;
    int32_t channelId = TEST_INVALID_CHANNEL_ID;
    int32_t ret = OnProxyChannelClosed(channelId, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
}

/*
 * @tc.name: OnProxyChannelMsgReceivedNullParamTest001
 * @tc.desc: OnProxyChannelMsgReceived with null appInfo, null data, or zero len returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, OnProxyChannelMsgReceivedNullParamTest001, TestSize.Level1)
{
    const char *data = TEST_MSG_DATA;
    uint32_t len = strlen(data) + 1;
    int32_t channelId = TEST_INVALID_CHANNEL_ID;
    int32_t ret = OnProxyChannelMsgReceived(channelId, nullptr, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    AppInfo appInfo = { };
    ret = OnProxyChannelMsgReceived(channelId, &appInfo, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: OnProxyChannelMsgReceivedInvalidAppTypeTest001
 * @tc.desc: OnProxyChannelMsgReceived with APP_TYPE_NOT_CARE returns SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, OnProxyChannelMsgReceivedInvalidAppTypeTest001, TestSize.Level1)
{
    const char *data = TEST_MSG_DATA;
    uint32_t len = strlen(data) + 1;
    AppInfo appInfo = { };
    appInfo.appType = APP_TYPE_NOT_CARE;
    int32_t channelId = TEST_INVALID_CHANNEL_ID;
    int32_t ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
}

/*
 * @tc.name: OnProxyChannelMsgReceivedInnerAppTypeTest001
 * @tc.desc: OnProxyChannelMsgReceived with APP_TYPE_INNER returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, OnProxyChannelMsgReceivedInnerAppTypeTest001, TestSize.Level1)
{
    const char *data = TEST_MSG_DATA;
    uint32_t len = strlen(data) + 1;
    AppInfo appInfo = { };
    appInfo.appType = APP_TYPE_INNER;
    int32_t channelId = TEST_INVALID_CHANNEL_ID;
    int32_t ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: OnProxyChannelMsgReceivedAuthAppTypeTest001
 * @tc.desc: OnProxyChannelMsgReceived with APP_TYPE_AUTH returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, OnProxyChannelMsgReceivedAuthAppTypeTest001, TestSize.Level1)
{
    const char *data = TEST_MSG_DATA;
    uint32_t len = strlen(data) + 1;
    AppInfo appInfo = { };
    appInfo.appType = APP_TYPE_AUTH;
    int32_t channelId = TEST_INVALID_CHANNEL_ID;
    int32_t ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: OnProxyChannelMsgReceivedNormalAppTypeTest001
 * @tc.desc: OnProxyChannelMsgReceived with APP_TYPE_NORMAL returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, OnProxyChannelMsgReceivedNormalAppTypeTest001, TestSize.Level1)
{
    const char *data = TEST_MSG_DATA;
    uint32_t len = strlen(data) + 1;
    AppInfo appInfo = { };
    appInfo.appType = APP_TYPE_NORMAL;
    int32_t channelId = TEST_INVALID_CHANNEL_ID;
    int32_t ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxySetCallBackTest001
 * @tc.desc: TransProxySetCallBack with valid callback returns SOFTBUS_OK,
 *           and null callback returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, TransProxySetCallBackTest001, TestSize.Level1)
{
    IServerChannelCallBack cb = { };
    cb.OnChannelOpened = TestNormalChannelOpened;
    cb.OnDataReceived = TestChannelDataReceived;
    int32_t ret = TransProxySetCallBack(&cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxySetCallBack(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
} // namespace OHOS
