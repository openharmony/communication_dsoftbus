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
#include "client_trans_channel_manager.h"
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
class ClientTransChannelManagerTest : public testing::Test {
public:
    ClientTransChannelManagerTest() { }
    ~ClientTransChannelManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

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

static IClientSessionCallBack g_clientSessionCb = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
    .OnStreamReceived = OnStreamReceived,
    .OnQosEvent = OnQosEvent,
};

void ClientTransChannelManagerTest::SetUpTestCase(void)
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
void ClientTransChannelManagerTest::TearDownTestCase(void) { }

/**
 * @tc.name: ClientTransCloseChannelTest001
 * @tc.desc: ClientTransCloseChannel with proxy and tcp direct channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransCloseChannelTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_PROXY, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_TCP_DIRECT, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransCloseChannelTest002
 * @tc.desc: ClientTransCloseChannel with auth and invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransCloseChannelTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_AUTH, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_BUTT, 1);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: ClientTransCloseReserveChannelTest001
 * @tc.desc: ClientTransCloseChannel with invalid channel id and invalid channel types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransCloseReserveChannelTest001, TestSize.Level1)
{
    int32_t ret = ClientTransCloseChannel(INVALID_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    int32_t channelId = 1;
    ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_BUTT, 1);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
    ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_UNDEFINED, 1);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: ClientTransChannelSendBytesTest001
 * @tc.desc: ClientTransChannelSendBytes with null data and zero len
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendBytesTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_AUTH, nullptr, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_AUTH, data, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransChannelSendBytesTest002
 * @tc.desc: ClientTransChannelSendBytes with auth channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendBytesTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_AUTH, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: ClientTransChannelSendBytesTest003
 * @tc.desc: ClientTransChannelSendBytes with proxy channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendBytesTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_PROXY, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: ClientTransChannelSendBytesTest004
 * @tc.desc: ClientTransChannelSendBytes with tcp direct channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendBytesTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_TCP_DIRECT, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: ClientTransChannelSendBytesTest005
 * @tc.desc: ClientTransChannelSendBytes with invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendBytesTest005, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_BUTT, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: ClientTransChannelAsyncSendBytesTest001
 * @tc.desc: ClientTransChannelAsyncSendBytes with null data and zero len
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelAsyncSendBytesTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t dataSeq = 1;

    int32_t ret = ClientTransChannelAsyncSendBytes(channelId, CHANNEL_TYPE_AUTH, nullptr, TEST_DATA_LENGTH, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelAsyncSendBytes(channelId, CHANNEL_TYPE_AUTH, data, 0, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransChannelAsyncSendBytesTest002
 * @tc.desc: ClientTransChannelAsyncSendBytes with auth channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelAsyncSendBytesTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t dataSeq = 1;

    int32_t ret = ClientTransChannelAsyncSendBytes(channelId, CHANNEL_TYPE_AUTH, data, TEST_DATA_LENGTH, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: ClientTransChannelAsyncSendBytesTest003
 * @tc.desc: ClientTransChannelAsyncSendBytes with proxy channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelAsyncSendBytesTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t dataSeq = 1;

    int32_t ret = ClientTransChannelAsyncSendBytes(channelId, CHANNEL_TYPE_PROXY, data, TEST_DATA_LENGTH, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: ClientTransChannelAsyncSendBytesTest004
 * @tc.desc: ClientTransChannelAsyncSendBytes with tcp direct channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelAsyncSendBytesTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t dataSeq = 1;

    int32_t ret = ClientTransChannelAsyncSendBytes(channelId, CHANNEL_TYPE_TCP_DIRECT, data, TEST_DATA_LENGTH, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: ClientTransChannelSendMessageTest001
 * @tc.desc: ClientTransChannelSendMessage with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendMessageTest001, TestSize.Level1)
{
    int32_t channelId = 1;

    int32_t ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_AUTH, nullptr, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_AUTH, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransChannelSendMessageTest002
 * @tc.desc: ClientTransChannelSendMessage with auth channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendMessageTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_AUTH, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: ClientTransChannelSendMessageTest003
 * @tc.desc: ClientTransChannelSendMessage with proxy channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendMessageTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_PROXY, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: ClientTransChannelSendMessageTest004
 * @tc.desc: ClientTransChannelSendMessage with tcp direct channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendMessageTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_TCP_DIRECT, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: ClientTransChannelSendMessageTest005
 * @tc.desc: ClientTransChannelSendMessage with invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendMessageTest005, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";

    int32_t ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_BUTT, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNEL_TYPE_INVALID, ret);
}

/**
 * @tc.name: ClientTransChannelSendStreamTest001
 * @tc.desc: ClientTransChannelSendStream with null data, ext or param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendStreamTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const StreamData data = { 0 };
    const StreamData ext = { 0 };
    const StreamFrameInfo param = { 0 };

    int32_t ret = ClientTransChannelSendStream(channelId, CHANNEL_TYPE_UDP, nullptr, &ext, &param);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelSendStream(channelId, CHANNEL_TYPE_UDP, &data, nullptr, &param);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelSendStream(channelId, CHANNEL_TYPE_UDP, &data, &ext, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransChannelSendStreamTest002
 * @tc.desc: ClientTransChannelSendStream with UDP channel type and valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendStreamTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const StreamData data = { 0 };
    const StreamData ext = { 0 };
    const StreamFrameInfo param = { 0 };

    int32_t ret = ClientTransChannelSendStream(channelId, CHANNEL_TYPE_UDP, &data, &ext, &param);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: ClientTransChannelSendStreamTest003
 * @tc.desc: ClientTransChannelSendStream with invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendStreamTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    const StreamData data = { 0 };
    const StreamData ext = { 0 };
    const StreamFrameInfo param = { 0 };

    int32_t ret = ClientTransChannelSendStream(channelId, CHANNEL_TYPE_BUTT, &data, &ext, &param);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNEL_TYPE_INVALID, ret);
}

/**
 * @tc.name: ClientTransChannelSendFileTest001
 * @tc.desc: ClientTransChannelSendFile with UDP channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendFileTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fileCnt = 1;
    const char *sFileList[] = { "/data/test.txt" };
    const char *dFileList[] = { "/data/test.txt" };

    int32_t ret = ClientTransChannelSendFile(channelId, CHANNEL_TYPE_UDP, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: ClientTransChannelSendFileTest002
 * @tc.desc: ClientTransChannelSendFile with proxy channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendFileTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fileCnt = 1;
    const char *sFileList[] = { "/data/test.txt" };
    const char *dFileList[] = { "/data/test.txt" };

    int32_t ret = ClientTransChannelSendFile(channelId, CHANNEL_TYPE_PROXY, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: ClientTransChannelSendFileTest003
 * @tc.desc: ClientTransChannelSendFile with invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendFileTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fileCnt = 1;
    const char *sFileList[] = { "/data/test.txt" };
    const char *dFileList[] = { "/data/test.txt" };

    int32_t ret = ClientTransChannelSendFile(channelId, CHANNEL_TYPE_BUTT, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNEL_TYPE_INVALID, ret);
}

/**
 * @tc.name: ClientTransChannelAsyncSendMessageTest001
 * @tc.desc: ClientTransChannelAsyncSendMessage with null data, zero len and zero seq
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelAsyncSendMessageTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint16_t dataSeq = 1;

    int32_t ret = ClientTransChannelAsyncSendMessage(channelId, CHANNEL_TYPE_AUTH, nullptr, TEST_DATA_LENGTH, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelAsyncSendMessage(channelId, CHANNEL_TYPE_AUTH, data, 0, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelAsyncSendMessage(channelId, CHANNEL_TYPE_AUTH, data, TEST_DATA_LENGTH, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransChannelAsyncSendMessageTest002
 * @tc.desc: ClientTransChannelAsyncSendMessage with proxy channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelAsyncSendMessageTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint16_t dataSeq = 1;

    int32_t ret = ClientTransChannelAsyncSendMessage(channelId, CHANNEL_TYPE_PROXY, data, TEST_DATA_LENGTH, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: ClientTransChannelAsyncSendMessageTest003
 * @tc.desc: ClientTransChannelAsyncSendMessage with tcp direct channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelAsyncSendMessageTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint16_t dataSeq = 1;

    int32_t ret =
        ClientTransChannelAsyncSendMessage(channelId, CHANNEL_TYPE_TCP_DIRECT, data, TEST_DATA_LENGTH, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}
} // namespace OHOS
