/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "lnn_lane_interface.h"
#include "gtest/gtest.h"
#include "softbus_error_code.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_network.h"
#include "softbus_transmission_interface.h"

using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {

#define TEST_VALID_SESSIONNAME "com.test.sessionname"
#define TEST_VALID_PEER_NETWORKID "12345678"
#define TEST_NUMBER_256 256

class SoftbusProxyNetworkTest : public testing::Test {
public:
    SoftbusProxyNetworkTest()
    {}
    ~SoftbusProxyNetworkTest()
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

bool SoftbusProxyNetworkTest::m_channelClosedFlag = false;
bool SoftbusProxyNetworkTest::m_channelOpenFailedFlag = false;
bool SoftbusProxyNetworkTest::m_messageReceivedFlag = false;

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

void SoftbusProxyNetworkTest::SetUpTestCase(void)
{
    IServerChannelCallBack cb;
    cb.OnChannelOpened = TestNormalChannelOpened;
    cb.OnDataReceived = TestChannelDataReceived;
    ASSERT_EQ(SOFTBUS_OK, TransProxySetCallBack(&cb));
}

void SoftbusProxyNetworkTest::TearDownTestCase(void)
{
}

int32_t SoftbusProxyNetworkTest::TestOnNetworkChannelOpened(int32_t channelId, const char *uuid, unsigned char isServer)
{
    (void)channelId;
    (void)uuid;
    (void)isServer;
    return SOFTBUS_OK;
}

void SoftbusProxyNetworkTest::TestOnNetworkChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)channelId;
    (void)uuid;
    SoftbusProxyNetworkTest::m_channelOpenFailedFlag = true;
}

void SoftbusProxyNetworkTest::TestOnNetworkChannelClosed(int32_t channelId)
{
    (void)channelId;
    SoftbusProxyNetworkTest::m_channelClosedFlag = true;
}

void SoftbusProxyNetworkTest::TestOnNetworkMessageReceived(int32_t channelId, const char *data, uint32_t len)
{
    (void)channelId;
    (void)data;
    (void)len;
    SoftbusProxyNetworkTest::m_messageReceivedFlag = true;
}

void SoftbusProxyNetworkTest::TestRegisterNetworkingChannelListener(void)
{
    INetworkingListener listener;
    char sessionName[TEST_NUMBER_256] = {0};
    strcpy_s(sessionName, TEST_NUMBER_256, TEST_VALID_SESSIONNAME);
    listener.onChannelClosed = SoftbusProxyNetworkTest::TestOnNetworkChannelClosed;
    listener.onChannelOpened = SoftbusProxyNetworkTest::TestOnNetworkChannelOpened;
    listener.onChannelOpenFailed = SoftbusProxyNetworkTest::TestOnNetworkChannelOpenFailed;
    listener.onMessageReceived = SoftbusProxyNetworkTest::TestOnNetworkMessageReceived;
    int32_t ret = TransRegisterNetworkingChannelListener(sessionName, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransNoRegisterListenerTest001
 * @tc.desc: test callback after no register networking channel listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyNetworkTest, TransNoRegisterListenerTest001, TestSize.Level1)
{
    SoftbusProxyNetworkTest::TestRegisterNetworkingChannelListener();
    char sessionName[TEST_NUMBER_256] = {0};
    strcpy_s(sessionName, TEST_NUMBER_256, TEST_VALID_SESSIONNAME);
    int32_t ret = NotifyNetworkingChannelOpened(sessionName, 1, NULL, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);

    NotifyNetworkingChannelOpenFailed(sessionName, 1, NULL);
    EXPECT_EQ(true, SoftbusProxyNetworkTest::m_channelOpenFailedFlag);
    NotifyNetworkingChannelClosed(sessionName, 1);
    EXPECT_EQ(true, SoftbusProxyNetworkTest::m_channelClosedFlag);
    NotifyNetworkingMsgReceived(sessionName, 1, NULL, 0);
    EXPECT_EQ(true, SoftbusProxyNetworkTest::m_messageReceivedFlag);
}

/**
 * @tc.name: TransRegisterListenerTest001
 * @tc.desc: test callback after register networking channel listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyNetworkTest, TransRegisterListenerTest001, TestSize.Level1)
{
    char sessionName[TEST_NUMBER_256] = {0};
    strcpy_s(sessionName, TEST_NUMBER_256, TEST_VALID_SESSIONNAME);
    SoftbusProxyNetworkTest::TestRegisterNetworkingChannelListener();

    int32_t ret = NotifyNetworkingChannelOpened(sessionName, 1, NULL, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);

    NotifyNetworkingChannelOpenFailed(sessionName, 1, NULL);
    EXPECT_EQ(true, SoftbusProxyNetworkTest::m_channelOpenFailedFlag);
    NotifyNetworkingChannelClosed(sessionName, 1);
    EXPECT_EQ(true, SoftbusProxyNetworkTest::m_channelClosedFlag);
    NotifyNetworkingMsgReceived(sessionName, 1, NULL, 0);
    EXPECT_EQ(true, SoftbusProxyNetworkTest::m_messageReceivedFlag);
}

/**
  * @tc.name: TransNotifyNetworkingChannelOpenedTest001
  * @tc.desc: test proxy channel opened with wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyNetworkTest, TransNotifyNetworkingChannelOpenedTest001, TestSize.Level1)
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
    ret = OnProxyChannelOpened(channelId, &appInfo, isServer);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = OnProxyChannelOpened(channelId, &appInfo, isServer);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test app type is inner */
    appInfo.appType = APP_TYPE_INNER;
    ret = OnProxyChannelOpened(channelId, &appInfo, isServer);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransOnProxyChannelOpenFailedTest001
  * @tc.desc: test proxy channel open failed with wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyNetworkTest, TransOnProxyChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    AppInfo appInfo;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
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
HWTEST_F(SoftbusProxyNetworkTest, TransOnProxyChannelClosedTest001, TestSize.Level1)
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
HWTEST_F(SoftbusProxyNetworkTest, TransOnProxyChannelMsgReceivedTest001, TestSize.Level1)
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
HWTEST_F(SoftbusProxyNetworkTest, TransOpenNetWorkingChannelTest001, TestSize.Level1)
{
    LanePreferredLinkList preferred = {
        .linkTypeNum = 1,
        .linkType[0] = LANE_COC_DIRECT,
     };
    char sessionName[TEST_NUMBER_256] = {0};
    strcpy_s(sessionName, TEST_NUMBER_256, TEST_VALID_SESSIONNAME);
    int32_t ret = SOFTBUS_OK;
    ret = TransOpenNetWorkingChannel(sessionName, NULL, &preferred);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    ret = TransOpenNetWorkingChannel(sessionName, NULL, &preferred);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
}
} // namespace OHOS
