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
#include "softbus_error_code.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_network.h"
#include "softbus_transmission_interface.h"
#include "trans_auth_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_VALID_SESSIONNAME "com.test.sessionname"
#define TEST_VALID_PEER_NETWORKID "12345678"

class TransProxyNetworkTest : public testing::Test {
public:
    TransProxyNetworkTest()
    {}
    ~TransProxyNetworkTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}

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

int32_t TestChannelDataReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
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
    IServerChannelCallBack cb;
    cb.OnChannelOpened = TestNormalChannelOpened;
    cb.OnDataReceived = TestChannelDataReceived;
    ASSERT_EQ(SOFTBUS_OK, TransProxySetCallBack(&cb));
}

void TransProxyNetworkTest::TearDownTestCase(void)
{
}

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
    INetworkingListener listener;
    listener.onChannelClosed = TransProxyNetworkTest::TestOnNetworkChannelClosed;
    listener.onChannelOpened = TransProxyNetworkTest::TestOnNetworkChannelOpened;
    listener.onChannelOpenFailed = TransProxyNetworkTest::TestOnNetworkChannelOpenFailed;
    listener.onMessageReceived = TransProxyNetworkTest::TestOnNetworkMessageReceived;
    int32_t ret = TransRegisterNetworkingChannelListener(&listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransNoRegisterListenerTest001
 * @tc.desc: test callback after no register networking channel listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, TransNoRegisterListenerTest001, TestSize.Level1)
{
    int32_t ret = NotifyNetworkingChannelOpened(1, NULL, 0);
    EXPECT_NE(SOFTBUS_OK, ret);
    
    NotifyNetworkingChannelOpenFailed(1, NULL);
    EXPECT_NE(true, TransProxyNetworkTest::m_channelOpenFailedFlag);
    NotifyNetworkingChannelClosed(1);
    EXPECT_NE(true, TransProxyNetworkTest::m_channelClosedFlag);
    NotifyNetworkingMsgReceived(1, NULL, 0);
    EXPECT_NE(true, TransProxyNetworkTest::m_messageReceivedFlag);
}

/**
 * @tc.name: TransRegisterListenerTest001
 * @tc.desc: test callback after register networking channel listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, TransRegisterListenerTest001, TestSize.Level1)
{
    TransProxyNetworkTest::TestRegisterNetworkingChannelListener();

    int32_t ret = NotifyNetworkingChannelOpened(1, NULL, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    NotifyNetworkingChannelOpenFailed(1, NULL);
    EXPECT_EQ(true, TransProxyNetworkTest::m_channelOpenFailedFlag);
    NotifyNetworkingChannelClosed(1);
    EXPECT_EQ(true, TransProxyNetworkTest::m_channelClosedFlag);
    NotifyNetworkingMsgReceived(1, NULL, 0);
    EXPECT_EQ(true, TransProxyNetworkTest::m_messageReceivedFlag);
}

/**
  * @tc.name: TransNotifyNetworkingChannelOpenedTest001
  * @tc.desc: test proxy channel opened with wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyNetworkTest, TransNotifyNetworkingChannelOpenedTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    AppInfo appInfo;
    unsigned char isServer = '0';
    /* test app info is null */
    int32_t ret = OnProxyChannelOpened(channelId, NULL, isServer);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test app type is other */
    appInfo.appType = APP_TYPE_NOT_CARE;
    ret = OnProxyChannelOpened(channelId, &appInfo, isServer);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test app type is normal and get network id fail */
    appInfo.appType = APP_TYPE_NORMAL;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = OnProxyChannelOpened(channelId, &appInfo, isServer);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = OnProxyChannelOpened(channelId, &appInfo, isServer);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* test app type is inner */
    appInfo.appType = APP_TYPE_INNER;
    ret = OnProxyChannelOpened(channelId, &appInfo, isServer);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransOnProxyChannelOpenFailedTest001
  * @tc.desc: test proxy channel open failed with wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyNetworkTest, TransOnProxyChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    AppInfo appInfo;
    int32_t errCode = SOFTBUS_MEM_ERR;
    /* test app info is null */
    int32_t ret = OnProxyChannelOpenFailed(channelId, NULL, errCode);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test app type is other */
    appInfo.appType = APP_TYPE_NOT_CARE;
    ret = OnProxyChannelOpenFailed(channelId, &appInfo, errCode);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransOnProxyChannelClosedTest001
  * @tc.desc: test proxy channel closed with wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyNetworkTest, TransOnProxyChannelClosedTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = -1;
    AppInfo appInfo;
    /* test app info is null */
    ret = OnProxyChannelClosed(channelId, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test app type is other */
    appInfo.appType = APP_TYPE_NOT_CARE;
    ret = OnProxyChannelClosed(channelId, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test app type is inner */
    appInfo.appType = APP_TYPE_INNER;
    ret = OnProxyChannelClosed(channelId, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
}

/**
  * @tc.name: TransOnProxyChannelMsgReceivedTest001
  * @tc.desc: test proxy channel msg received.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyNetworkTest, TransOnProxyChannelMsgReceivedTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    AppInfo appInfo;
    const char *data = "test data";
    uint32_t len = strlen(data) + 1;

    /* test invalid param */
    int32_t ret = OnProxyChannelMsgReceived(channelId, NULL, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = OnProxyChannelMsgReceived(channelId, &appInfo, NULL, len);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, 0);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test app type is other */
    appInfo.appType = APP_TYPE_NOT_CARE;
    ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test app type is inner */
    appInfo.appType = APP_TYPE_INNER;
    ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* test app type is auth */
    appInfo.appType = APP_TYPE_AUTH;
    ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* test app type is normal and return err */
    appInfo.appType = APP_TYPE_NORMAL;
    ret = OnProxyChannelMsgReceived(channelId, &appInfo, data, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransOpenNetWorkingChannelTest001
  * @tc.desc: test proxy open networking channel with wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyNetworkTest, TransOpenNetWorkingChannelTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = TransOpenNetWorkingChannel(NULL, TEST_VALID_PEER_NETWORKID);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    ret = TransOpenNetWorkingChannel(TEST_VALID_SESSIONNAME, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
}
} // namespace OHOS
