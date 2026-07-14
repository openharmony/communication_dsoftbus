/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "securec.h"
#include <gtest/gtest.h>

#include "client_trans_auth_manager.h"
#include "client_trans_channel_callback.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_tcp_direct_callback.h"
#include "client_trans_udp_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_DATA_LENGTH 1024

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const int32_t PRIVILEGE_CLOSE_CHANNEL = 11;

int32_t OnSessionOpened(
    const char *sessionName, const ChannelInfo *channel, SessionType flag, SocketAccessInfo *accessInfo)
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

static int32_t OnDataReceived(
    int32_t channelId, int32_t channelType, const void *data, uint32_t len, SessionPktType type)
{
    return SOFTBUS_OK;
}

static int32_t OnStreamReceived(
    int32_t channelId, int32_t channelType, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    return SOFTBUS_OK;
}

static int32_t OnQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    return SOFTBUS_OK;
}

static int32_t OnChannelBind(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

static IClientSessionCallBack g_clientSessionCb = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
    .OnStreamReceived = OnStreamReceived,
    .OnQosEvent = OnQosEvent,
    .OnChannelBind = OnChannelBind,
};

class ClientTransChannelCallbackTest : public testing::Test {
public:
    ClientTransChannelCallbackTest() { }
    ~ClientTransChannelCallbackTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void ClientTransChannelCallbackTest::SetUpTestCase(void)
{
    int32_t ret = ClientTransAuthInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransTdcSetCallBack(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransUdpMgrInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void ClientTransChannelCallbackTest::TearDownTestCase(void) { }

/**
 * @tc.name: TransOnChannelOpenedTest001
 * @tc.desc: TransOnChannelOpened with null sessionName and null channelInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenedTest001, TestSize.Level1)
{
    ChannelInfo info = { 0 };
    int32_t ret = TransOnChannelOpened(nullptr, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOnChannelOpened(g_sessionName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransOnChannelOpenedTest002
 * @tc.desc: TransOnChannelOpened with AUTH and PROXY channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenedTest002, TestSize.Level1)
{
    ChannelInfo info = { 0 };
    info.channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.channelType = CHANNEL_TYPE_PROXY;
    ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
}

/**
 * @tc.name: TransOnChannelOpenedTest003
 * @tc.desc: TransOnChannelOpened with TCP_DIRECT channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenedTest003, TestSize.Level1)
{
    ChannelInfo info = { 0 };
    info.channelType = CHANNEL_TYPE_TCP_DIRECT;
    info.channelId = 1;
    int32_t ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransOnChannelOpenedTest004
 * @tc.desc: TransOnChannelOpened with UDP channel type and isServer=0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenedTest004, TestSize.Level1)
{
    ChannelInfo info = { 0 };
    info.channelType = CHANNEL_TYPE_UDP;
    info.isServer = 0;
    int32_t ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
}

/**
 * @tc.name: TransOnChannelOpenedTest005
 * @tc.desc: TransOnChannelOpened with UDP channel type and isServer=1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenedTest005, TestSize.Level1)
{
    ChannelInfo info = { 0 };
    info.channelType = CHANNEL_TYPE_UDP;
    info.isServer = 1;
    int32_t ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelOpenedTest006
 * @tc.desc: TransOnChannelOpened with invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenedTest006, TestSize.Level1)
{
    ChannelInfo info = { 0 };
    info.channelType = CHANNEL_TYPE_BUTT;
    info.channelId = 1;
    int32_t ret = TransOnChannelOpened(g_sessionName, &info);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransOnChannelOpenFailedTest001
 * @tc.desc: TransOnChannelOpenFailed with AUTH and PROXY channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_AUTH, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_PROXY, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelOpenFailedTest002
 * @tc.desc: TransOnChannelOpenFailed with TCP_DIRECT and UDP channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenFailedTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_TCP_DIRECT, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_UDP, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelOpenFailedTest003
 * @tc.desc: TransOnChannelOpenFailed with UNDEFINED and invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelOpenFailedTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_UNDEFINED, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelOpenFailed(channelId, CHANNEL_TYPE_BUTT, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelLinkDownTest001
 * @tc.desc: TransOnChannelLinkDown with null networkId, valid networkId and privilege flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelLinkDownTest001, TestSize.Level1)
{
    int32_t ret = TransOnChannelLinkDown(nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOnChannelLinkDown(g_networkid, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelLinkDown(g_networkid, 0 | 1 << PRIVILEGE_CLOSE_CHANNEL);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelClosedTest001
 * @tc.desc: TransOnChannelClosed with AUTH channel and normal/close ack message type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelClosedTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_AUTH, MESSAGE_TYPE_NOMAL, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_AUTH, MESSAGE_TYPE_CLOSE_ACK, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelClosedTest002
 * @tc.desc: TransOnChannelClosed with PROXY channel and normal/close ack message type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelClosedTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_PROXY, MESSAGE_TYPE_NOMAL, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_PROXY, MESSAGE_TYPE_CLOSE_ACK, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelClosedTest003
 * @tc.desc: TransOnChannelClosed with UDP channel and close ack/normal message type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelClosedTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_UDP, MESSAGE_TYPE_CLOSE_ACK, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_UDP, MESSAGE_TYPE_NOMAL, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: TransOnChannelClosedTest004
 * @tc.desc: TransOnChannelClosed with TCP_DIRECT channel and normal/close ack message type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelClosedTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_TCP_DIRECT, MESSAGE_TYPE_NOMAL, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_TCP_DIRECT, MESSAGE_TYPE_CLOSE_ACK, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelClosedTest005
 * @tc.desc: TransOnChannelClosed with invalid channel type and invalid message type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelClosedTest005, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_BUTT, MESSAGE_TYPE_NOMAL, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
    ret = TransOnChannelClosed(channelId, CHANNEL_TYPE_TCP_DIRECT, MESSAGE_TYPE_BUTT, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelMsgReceivedTest001
 * @tc.desc: TransOnChannelMsgReceived with null data and valid data on AUTH channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelMsgReceivedTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret =
        TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_AUTH, nullptr, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    const void *data = static_cast<const void *>("test");
    ret = TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_AUTH, data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelMsgReceivedTest002
 * @tc.desc: TransOnChannelMsgReceived with valid data on PROXY and TCP_DIRECT channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelMsgReceivedTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const void *data = static_cast<const void *>("test");
    int32_t ret = TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_PROXY, data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
    ret = TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_TCP_DIRECT, data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelMsgReceivedTest003
 * @tc.desc: TransOnChannelMsgReceived with invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelMsgReceivedTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    const void *data = static_cast<const void *>("test");
    int32_t ret = TransOnChannelMsgReceived(channelId, CHANNEL_TYPE_BUTT, data, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransOnChannelQosEventTest001
 * @tc.desc: TransOnChannelQosEvent with null tvList and UDP channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelQosEventTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t eventId = 0;
    int32_t tvCount = 1;

    int32_t ret = TransOnChannelQosEvent(channelId, CHANNEL_TYPE_UDP, eventId, tvCount, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransOnChannelQosEventTest002
 * @tc.desc: TransOnChannelQosEvent with valid tvList and UDP channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelQosEventTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t eventId = 0;
    int32_t tvCount = 1;
    const QosTv tvList = {
        .type = WIFI_CHANNEL_QUALITY,
    };

    int32_t ret = TransOnChannelQosEvent(channelId, CHANNEL_TYPE_UDP, eventId, tvCount, &tvList);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: TransOnChannelQosEventTest003
 * @tc.desc: TransOnChannelQosEvent with invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelQosEventTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t eventId = 0;
    int32_t tvCount = 1;
    const QosTv tvList = {
        .type = WIFI_CHANNEL_QUALITY,
    };

    int32_t ret = TransOnChannelQosEvent(channelId, CHANNEL_TYPE_BUTT, eventId, tvCount, &tvList);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnChannelBindTest001
 * @tc.desc: TransOnChannelBind with UDP and TCP_DIRECT channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelBindTest001, TestSize.Level1)
{
    const int32_t channelId = 1;
    int32_t ret = TransOnChannelBind(channelId, CHANNEL_TYPE_UDP);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelBind(channelId, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/**
 * @tc.name: TransOnChannelBindTest002
 * @tc.desc: TransOnChannelBind with PROXY and AUTH channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelBindTest002, TestSize.Level1)
{
    const int32_t channelId = 1;
    int32_t ret = TransOnChannelBind(channelId, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelBind(channelId, CHANNEL_TYPE_AUTH);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnChannelBindTest003
 * @tc.desc: TransOnChannelBind with UNDEFINED and invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnChannelBindTest003, TestSize.Level1)
{
    const int32_t channelId = 1;
    int32_t ret = TransOnChannelBind(channelId, CHANNEL_TYPE_UNDEFINED);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnChannelBind(channelId, CHANNEL_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransOnCheckCollabRelationTest001
 * @tc.desc: TransOnCheckCollabRelation with isSinkSide=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnCheckCollabRelationTest001, TestSize.Level1)
{
    CollabInfo sourceInfo;
    (void)memset_s(&sourceInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    CollabInfo sinkInfo;
    (void)memset_s(&sinkInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    const int32_t channelId = 1;
    const int32_t channelType = 1;
    bool isSinkSide = true;
    int32_t ret = TransOnCheckCollabRelation(&sourceInfo, isSinkSide, &sinkInfo, channelId, channelType);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnCheckCollabRelationTest002
 * @tc.desc: TransOnCheckCollabRelation with isSinkSide=false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelCallbackTest, TransOnCheckCollabRelationTest002, TestSize.Level1)
{
    CollabInfo sourceInfo;
    (void)memset_s(&sourceInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    CollabInfo sinkInfo;
    (void)memset_s(&sinkInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    const int32_t channelId = 1;
    const int32_t channelType = 1;
    bool isSinkSide = false;
    int32_t ret = TransOnCheckCollabRelation(&sourceInfo, isSinkSide, &sinkInfo, channelId, channelType);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}
} // namespace OHOS
