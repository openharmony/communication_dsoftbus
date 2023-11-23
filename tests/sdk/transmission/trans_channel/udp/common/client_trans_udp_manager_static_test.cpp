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
#include "client_trans_channel_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_udp_manager.c"
#include "securec.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "trans_udp_channel_manager.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
#define TEST_CHANNELID 5
#define ERR_CHANNELID (-1)
#define TEST_COUNT 2
#define STREAM_DATA_LENGTH 10
#define TEST_EVENT_ID 2
class ClientTransUdpManagerStaticTest : public testing::Test {
public:
    ClientTransUdpManagerStaticTest() {}
    ~ClientTransUdpManagerStaticTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransUdpManagerStaticTest::SetUpTestCase(void) {}

void ClientTransUdpManagerStaticTest::TearDownTestCase(void) {}

/**
 * @tc.name: ClientTransUdpManagerStaticTest001
 * @tc.desc: client trans udp manager static test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransUdpManagerStaticTest001, TestSize.Level0)
{
    char sendStringData[STREAM_DATA_LENGTH] = "diudiudiu";
    StreamData tmpData = {
        sendStringData,
        STREAM_DATA_LENGTH,
    };
    char str[STREAM_DATA_LENGTH] = "oohoohooh";
    StreamData tmpData2 = {
        str,
        STREAM_DATA_LENGTH,
    };

    StreamFrameInfo tmpf = {};
    int32_t sessionId = 0;
    QosTv tvList;
    OnStreamReceived(TEST_CHANNELID, &tmpData, &tmpData2, &tmpf);

    int32_t ret = OnFileGetSessionId(TEST_CHANNELID, &sessionId);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    OnUdpChannelOpened(TEST_CHANNELID);
    OnUdpChannelClosed(TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);
    OnQosEvent(TEST_CHANNELID, TEST_EVENT_ID, TEST_COUNT, &tvList);

    ret = TransDeleteUdpChannel(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    UdpChannel channel;
    ret = TransGetUdpChannel(TEST_CHANNELID, &channel);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = ClosePeerUdpChannel(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: ClientTransUdpManagerStaticTest002
 * @tc.desc: client trans udp manager static test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransUdpManagerStaticTest002, TestSize.Level0)
{
    int32_t sessionId = 0;
    char sendStringData[STREAM_DATA_LENGTH] = "diudiudiu";
    QosTv tvList;
    StreamData tmpData = {
        sendStringData,
        STREAM_DATA_LENGTH,
    };
    char str[STREAM_DATA_LENGTH] = "oohoohooh";
    StreamData tmpData2 = {
        str,
        STREAM_DATA_LENGTH,
    };

    StreamFrameInfo tmpf = {};

    int32_t ret = ClientTransUdpMgrInit(NULL);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    IClientSessionCallBack *cb = GetClientSessionCb();
    ret = ClientTransUdpMgrInit(cb);
    ASSERT_EQ(SOFTBUS_OK, ret);

    OnUdpChannelClosed(TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_OK, ret);

    OnStreamReceived(TEST_CHANNELID, &tmpData, &tmpData2, &tmpf);

    ret = OnFileGetSessionId(TEST_CHANNELID, &sessionId);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);

    OnQosEvent(TEST_CHANNELID, TEST_EVENT_ID, TEST_COUNT, &tvList);
}

/**
 * @tc.name: ClientTransAddUdpChannelTest001
 * @tc.desc: client trans add udp channel test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransAddUdpChannelTest001, TestSize.Level0)
{
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransAddUdpChannel(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    udpChannel.channelId = TEST_CHANNELID;
    ret = ClientTransAddUdpChannel(&udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransAddUdpChannel(&udpChannel);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    OnUdpChannelOpened(TEST_CHANNELID);

    ret = TransSetUdpChannelEnable(TEST_CHANNELID, false);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSetUdpChannelEnable(ERR_CHANNELID, false);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransDeleteBusinnessChannelTest001
 * @tc.desc: trans delete businness channel test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransDeleteBusinnessChannelTest001, TestSize.Level0)
{
    UdpChannel channel;
    channel.businessType = BUSINESS_TYPE_STREAM;
    channel.channelId = ERR_CHANNELID;
    channel.dfileId = TEST_CHANNELID;

    int32_t ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channel.channelId = TEST_CHANNELID;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channel.businessType = BUSINESS_TYPE_FILE;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_OK, ret);

    channel.businessType = TEST_CHANNELID;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
} // namespace OHOS
