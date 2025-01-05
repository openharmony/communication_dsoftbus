/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_udp_channel_manager.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
#define TEST_CHANNELID 1030
#define ERR_CHANNELID (-1)
#define TEST_COUNT 2
#define STREAM_DATA_LENGTH 10
#define TEST_EVENT_ID 2
#define TEST_ERRCODE 426442703
#define TEST_CHANNELTYPE 2
#define TEST_CLOSEID 1088
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
 * @tc.name: TransOnUdpChannelBind
 * @tc.desc: udp channel on bind test, use the invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransOnUdpChannelBindTest001, TestSize.Level0)
{
    int32_t ret = ClientTransUdpMgrInit(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOnUdpChannelBind(TEST_CHANNELID, TEST_CHANNELTYPE);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransSetdFileIdByChannelId(TEST_CHANNELID, TEST_COUNT);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = OnIdleTimeoutReset(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OnRawStreamEncryptOptGetTest001
 * @tc.desc: on raw stream encrypt test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest001, TestSize.Level0)
{
    int32_t channelId = TEST_CHANNELID;
    bool encrypt = true;
    int32_t ret = OnRawStreamEncryptOptGet(channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: TransSetUdpChannelEnableTest001
 * @tc.desc: trans delete businness channel test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSetUdpChannelEnableTest001, TestSize.Level0)
{
    int32_t ret = TransSetUdpChannelEnable(TEST_CHANNELID, false);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

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
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    OnUdpChannelOpened(TEST_CHANNELID);
    OnUdpChannelClosed(TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);
    OnQosEvent(TEST_CHANNELID, TEST_EVENT_ID, TEST_COUNT, &tvList);

    ret = TransDeleteUdpChannel(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    UdpChannel channel;
    ret = TransGetUdpChannel(TEST_CHANNELID, &channel);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    
    IClientSessionCallBack *cb = GetClientSessionCb();
    ret = ClientTransUdpMgrInit(cb);
    ret = TransGetUdpChannel(TEST_CHANNELID, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClosePeerUdpChannel(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_ACCESS_TOKEN_DENIED, ret);
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

    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
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
    udpChannel.businessType = BUSINESS_TYPE_FILE;
    ret = ClientTransAddUdpChannel(&udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransAddUdpChannel(&udpChannel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST, ret);

    ret = TransGetUdpChannel(TEST_CHANNELID, &udpChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);

    OnUdpChannelOpened(TEST_CHANNELID);

    ret = TransSetUdpChannelEnable(TEST_CHANNELID, false);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSetUdpChannelEnable(ERR_CHANNELID, false);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
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
    EXPECT_EQ(SOFTBUS_TRANS_CLOSE_UDP_CHANNEL_FAILED, ret);

    channel.channelId = TEST_CHANNELID;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_TRANS_CLOSE_UDP_CHANNEL_FAILED, ret);

    channel.businessType = BUSINESS_TYPE_FILE;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_OK, ret);

    channel.businessType = TEST_CHANNELID;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH, ret);
}

/**
 * @tc.name: TransSetdFileIdByChannelIdTest001
 * @tc.desc: trans delete businness channel test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSetdFileIdByChannelIdTest001, TestSize.Level0)
{
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransSetdFileIdByChannelId(TEST_CHANNELID, TEST_COUNT);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);

    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    udpChannel.channelId = TEST_CHANNELID;
    ret = ClientTransAddUdpChannel(&udpChannel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST, ret);
    ret = TransSetdFileIdByChannelId(TEST_CHANNELID, TEST_COUNT);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnUdpChannelOpenFailedTest002
 * @tc.desc: trans on udp channel opened test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransOnUdpChannelOpenFailedTest001, TestSize.Level0)
{
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));

    udpChannel.isEnable = false;
    ret = TransOnUdpChannelOpenFailed(TEST_CHANNELID, TEST_ERRCODE);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);

    udpChannel.isEnable = true;
    ret = TransOnUdpChannelOpenFailed(TEST_CHANNELID, TEST_ERRCODE);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: NotifyCallbackTest001
 * @tc.desc: trans NotifyCallback test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, NotifyCallbackTest001, TestSize.Level0)
{
    UdpChannel *testChannel = NULL;
    NotifyCallback(testChannel, TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);

    UdpChannel channel;
    (void)memset_s(&channel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    channel.channelId = TEST_CHANNELID;
    channel.isEnable = false;
    int32_t ret = ClientTransAddUdpChannel(&channel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST, ret);
    NotifyCallback(&channel, TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);

    channel.isEnable = true;
    ret = ClientTransAddUdpChannel(&channel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST, ret);
    NotifyCallback(&channel, TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);
}

/**
 * @tc.name: CloseUdpChannelProcTest001
 * @tc.desc: trans CloseUdpChannelProc test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(ClientTransUdpManagerStaticTest, CloseUdpChannelProc001, TestSize.Level0)
{
    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    udpChannel.businessType = BUSINESS_TYPE_FILE;
    int32_t ret = CloseUdpChannelProc(&udpChannel, TEST_CLOSEID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CloseUdpChannelProc(&udpChannel, TEST_CLOSEID, SHUTDOWN_REASON_SEND_FILE_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CloseUdpChannelProc(&udpChannel, TEST_CLOSEID, SHUTDOWN_REASON_RECV_FILE_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CloseUdpChannelProc(&udpChannel, TEST_CLOSEID, SHUTDOWN_REASON_LOCAL);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CloseUdpChannelProc(NULL, TEST_CLOSEID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CloseUdpChannelTest001
 * @tc.desc: close udp channel test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, CloseUdpChannelTest001, TestSize.Level0)
{
    int32_t ret = ClientTransChannelInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CloseUdpChannel(TEST_CLOSEID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = CloseUdpChannel(TEST_CLOSEID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: OnIdleTimeoutResetTest001
 * @tc.desc: client On idle timeout reset test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnIdleTimeoutResetTest001, TestSize.Level0)
{
    int32_t ret = OnIdleTimeoutReset(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: OnRawStreamEncryptOptGetTest002
 * @tc.desc: on raw stream encrypt test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest002, TestSize.Level0)
{
    int32_t channelId = TEST_CHANNELID;
    bool encrypt = true;
    int32_t ret = OnRawStreamEncryptOptGet(channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: OnRawStreamEncryptOptGetTest003
 * @tc.desc: on raw stream encrypt test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest003, TestSize.Level0)
{
    int32_t channelId = TEST_CHANNELID;
    bool encrypt = true;
    int32_t ret = OnRawStreamEncryptOptGet(channelId, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = ERR_CHANNELID;
    ret = OnRawStreamEncryptOptGet(channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OnRawStreamEncryptOptGetTest004
 * @tc.desc: on raw stream encrypt test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest004, TestSize.Level0)
{
    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    udpChannel.channelId = TEST_CHANNELID;
    udpChannel.info.isServer = true;

    int32_t ret = ClientTransAddUdpChannel(&udpChannel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST, ret);
    int32_t channelId = TEST_CHANNELID;
    bool encrypt = true;
    ret = OnRawStreamEncryptOptGet(channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);

    udpChannel.channelId = TEST_CLOSEID;
    udpChannel.info.isServer = false;
    ret = ClientTransAddUdpChannel(&udpChannel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST, ret);
    ret = OnRawStreamEncryptOptGet(channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: TransUdpChannelSetStreamMultiLayer
 * @tc.desc: TransUdpChannelSetStreamMultiLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransUdpChannelSetStreamMultiLayer, TestSize.Level0)
{
    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    udpChannel.channelId = TEST_CHANNELID;
    udpChannel.isEnable = false;

    ClientTransAddUdpChannel(&udpChannel);
    int32_t ret = TransUdpChannelSetStreamMultiLayer(TEST_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_DISABLE, ret);

    udpChannel.isEnable = true;
    ret = TransUdpChannelSetStreamMultiLayer(TEST_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransSendLimitChangeDataToCoreTest001
 * @tc.desc: TransSendLimitChangeDataToCore
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSendLimitChangeDataToCoreTest001, TestSize.Level0)
{
    int32_t ret = TransSendLimitChangeDataToCore(TEST_CHANNELID, FILE_PRIORITY_BK, NSTACKX_EOK);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
