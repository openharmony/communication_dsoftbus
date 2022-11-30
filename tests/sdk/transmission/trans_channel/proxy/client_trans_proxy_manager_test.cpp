/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "securec.h"

#include "client_trans_proxy_manager.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_access_token_test.h"
#include "client_trans_proxy_file_manager.h"

#define TEST_CHANNEL_ID (-10)
#define TEST_ERR_CODE (-1)
#define TEST_DATA "testdata"
#define TEST_DATA_LENGTH 9
#define TEST_FILE_CNT 4

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_proxyPkgName = "dms";
const char *g_proxySessionName = "ohos.distributedschedule.dms.test";
const char *g_testProxyFileName[] = {
    "/data/test.txt",
    "/data/ss.txt",
    "/data/test.tar",
    "/data/test.mp3",
};
const char *g_proxyFileSet[] = {
    "/data/data/test.txt",
    "/path/max/length/512/"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "111111111111111111111111111111111111111111111111111",
    "ss",
    "/data/ss",
};

class ClientTransProxyManagerTest : public testing::Test {
public:
    ClientTransProxyManagerTest() {}
    ~ClientTransProxyManagerTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransProxyManagerTest::SetUpTestCase(void)
{
    SetAceessTokenPermission("dsoftbusTransTest");
}
void ClientTransProxyManagerTest::TearDownTestCase(void) {}

int32_t TransOnSessionOpened(const char *sessionName, const ChannelInfo *channel, SessionType flag)
{
    return SOFTBUS_OK;
}

int32_t TransOnSessionClosed(int32_t channelId, int32_t channelType)
{
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    return SOFTBUS_OK;
}

int32_t TransOnBytesReceived(int32_t channelId, int32_t channelType,
    const void *data, uint32_t len, SessionPktType type)
{
    return SOFTBUS_OK;
}

int32_t TransOnOnStreamRecevied(int32_t channelId, int32_t channelType,
    const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    return SOFTBUS_OK;
}

int32_t TransOnGetSessionId(int32_t channelId, int32_t channelType, int32_t *sessionId)
{
    return SOFTBUS_OK;
}
int32_t TransOnQosEvent(int32_t channelId, int32_t channelType, int32_t eventId,
    int32_t tvCount, const QosTv *tvList)
{
    return SOFTBUS_OK;
}

static int OnSessionOpened(int sessionId, int result)
{
    return SOFTBUS_OK;
}

static void OnSessionClosed(int sessionId)
{
}

static void OnBytesReceived(int sessionId, const void *data, unsigned int len)
{
}

static void OnMessageReceived(int sessionId, const void *data, unsigned int len)
{
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

/**
 * @tc.name: ClinetTransProxyInitTest
 * @tc.desc: client trans proxy init test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClinetTransProxyInitTest, TestSize.Level0)
{
    IClientSessionCallBack cb;
    cb.OnSessionOpened = TransOnSessionOpened;
    cb.OnSessionClosed = TransOnSessionClosed;
    cb.OnSessionOpenFailed = TransOnSessionOpenFailed;
    cb.OnDataReceived = TransOnBytesReceived;
    cb.OnStreamReceived = TransOnOnStreamRecevied;
    cb.OnGetSessionId = TransOnGetSessionId;
    cb.OnQosEvent = TransOnQosEvent;

    int ret = ClinetTransProxyInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClinetTransProxyInit(&cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyOnChannelOpenedTest
 * @tc.desc: client trans proxy on channel opened test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnChannelOpenedTest, TestSize.Level0)
{
    int ret = ClientTransProxyOnChannelOpened(g_proxySessionName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ChannelInfo channelInfo = {0};
    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo);
    EXPECT_NE(SOFTBUS_ERR, ret);

    ret = CreateSessionServer(g_proxyPkgName, g_proxySessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_proxyPkgName, g_proxySessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyOnChannelClosedTest
 * @tc.desc: client trans proxy on channel closed test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnChannelClosedTest, TestSize.Level0)
{
    int32_t channelId = 1;
    int ret = ClientTransProxyOnChannelClosed(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreateSessionServer(g_proxyPkgName, g_proxySessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyOnChannelClosed(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_proxyPkgName, g_proxySessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyOnChannelOpenFailedTest
 * @tc.desc: client trans proxy on channel open failed test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnChannelOpenFailedTest, TestSize.Level0)
{
    int32_t channelId = 1;
    int ret = ClientTransProxyOnChannelOpenFailed(channelId, TEST_ERR_CODE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreateSessionServer(g_proxyPkgName, g_proxySessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ClientTransProxyOnChannelOpenFailed(channelId, TEST_ERR_CODE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_proxyPkgName, g_proxySessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyOnDataReceivedTest
 * @tc.desc: client trans proxy on data received test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest, TestSize.Level0)
{
    int32_t channelId = 1;
    int ret = ClientTransProxyOnDataReceived(channelId, nullptr, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    ret = ClientTransProxyOnDataReceived(channelId, TEST_DATA, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreateSessionServer(g_proxyPkgName, g_proxySessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyOnDataReceived(channelId, TEST_DATA, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_proxyPkgName, g_proxySessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyCloseChannelTest
 * @tc.desc: client trans proxy close channel test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyCloseChannelTest, TestSize.Level0)
{
    int32_t channelId = 1;
    ClientTransProxyCloseChannel(TEST_CHANNEL_ID);

    int ret = CreateSessionServer(g_proxyPkgName, g_proxySessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ClientTransProxyCloseChannel(channelId);

    ret = RemoveSessionServer(g_proxyPkgName, g_proxySessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyChannelSendFileTest
 * @tc.desc: trans proxy channel send file test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyChannelSendFileTest, TestSize.Level0)
{
    int32_t channelId = 1;
    int ret = TransProxyChannelSendFile(channelId, nullptr, g_proxyFileSet, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyChannelSendFile(channelId, g_testProxyFileName, g_proxyFileSet, MAX_SEND_FILE_NUM + TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyChannelSendFile(channelId, g_testProxyFileName, nullptr, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransProxyChannelSendFile(channelId, g_testProxyFileName, g_proxyFileSet, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
} // namespace OHOS