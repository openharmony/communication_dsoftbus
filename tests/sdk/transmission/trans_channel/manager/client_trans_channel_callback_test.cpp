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

#include "client_trans_channel_callback.h"
#include "client_trans_session_callback.h"
#include "client_trans_tcp_direct_callback.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_auth_manager.h"
#include "client_trans_udp_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

#define TEST_DATA_LENGTH 1024

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";

int32_t OnSessionOpened(const char *sessionName, const ChannelInfo *channel, SessionType flag)
{
    return SOFTBUS_OK;
}
int32_t OnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    return SOFTBUS_OK;
}

int32_t OnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    return SOFTBUS_OK;
}

static int32_t OnDataReceived(int32_t channelId, int32_t channelType,
    const void *data, uint32_t len, SessionPktType type)
{
    return SOFTBUS_OK;
}

static int32_t OnStreamReceived(int32_t channelId, int32_t channelType, const StreamData *data,
    const StreamData *ext, const StreamFrameInfo *param)
{
    return SOFTBUS_OK;
}

static int32_t OnQosEvent(int32_t channelId, int32_t channelType, int32_t eventId,
    int32_t tvCount, const QosTv *tvList)
{
    return SOFTBUS_OK;
}

static IClientSessionCallBack g_clientSessionCb = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
    .OnStreamReceived = OnStreamReceived,
    .OnQosEvent = OnQosEvent,
};

class ClientTransChannelCallbackTest : public testing::Test {
public:
    ClientTransChannelCallbackTest() {}
    ~ClientTransChannelCallbackTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransChannelCallbackTest::SetUpTestCase(void)
{
    int ret = ClientTransAuthInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransTdcSetCallBack(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransUdpMgrInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void ClientTransChannelCallbackTest::TearDownTestCase(void) {}

/**
 * @tc.name: TransOnChannelOpenTest001
 * @tc.desc: trans on channel open test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenTest001, TestSize.Level0)
{
    ChannelInfo info = {0};
    int ret = TransOnChannelOpened(nullptr, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info.channelType = CHANNEL_TYPE_AUTH;
    ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_NE(SOFTBUS_OK, ret);

    info.channelType = CHANNEL_TYPE_PROXY;
    ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);

    info.channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_NE(SOFTBUS_ERR, ret);

    info.channelType = CHANNEL_TYPE_UDP;
    info.isServer = 0;
    ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_NE(SOFTBUS_MEM_ERR, ret);

    info.channelType = CHANNEL_TYPE_UDP;
    info.isServer = 1;
    ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_NE(SOFTBUS_OK, ret);

    info.channelType = CHANNEL_TYPE_BUTT;
    ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_NE(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelOpenFailedTest001
 * @tc.desc: trans on channel open failed test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenFailedTest001, TestSize.Level0)
{
    int channelId = 1;
    int ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_AUTH, SOFTBUS_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_PROXY, SOFTBUS_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_TCP_DIRECT, SOFTBUS_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_UDP, SOFTBUS_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_BUTT, SOFTBUS_ERR);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelLinkDownTest001
 * @tc.desc: trans on channel link down test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelLinkDownTest001, TestSize.Level0)
{
    int ret = TransOnChannelLinkDown(nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransOnChannelLinkDown(g_networkid, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelClosedTest001
 * @tc.desc: trans on channel closed test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelClosedTest001, TestSize.Level0)
{
    int channelId = 1;
    int ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_AUTH, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_PROXY, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_UDP, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_TCP_DIRECT, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelMsgReceivedTest001
 * @tc.desc: trans on channel msg received test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelMsgReceivedTest001, TestSize.Level0)
{
    int channelId = 1;
    const void *data = (const void *)"test";
    int ret = TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_AUTH, data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_PROXY, data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_BUTT, data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelQosEventTest001
 * @tc.desc: trans on channel qos event test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelQosEventTest001, TestSize.Level0)
{
    int channelId = 1;
    int32_t eventId = 0;
    int32_t tvCount = 1;
    const QosTv tvList = {
        .type = WIFI_CHANNEL_QUALITY,
    };
    int ret = TransOnChannelQosEvent(channelId, CHANNEL_TYPE_UDP, eventId, tvCount, &tvList);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransOnChannelQosEvent(channelId, CHANNEL_TYPE_BUTT, eventId, tvCount, &tvList);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}
} // namespace OHOS
