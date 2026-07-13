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

#include <gtest/gtest.h>
#include <iostream>
#include <securec.h>

#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_stream.c"
#include "client_trans_stream.h"
#include "client_trans_udp_manager.h"
#include "softbus_adapter_mem.h"
#include "trans_server_proxy.h"

#define TEST_CHANNELID       1025
#define TEST_NORMALCHANNELID 12

using namespace testing::ext;

namespace OHOS {
class ClientTransStreamTest : public testing::Test {
public:
    ClientTransStreamTest(void) { }
    ~ClientTransStreamTest(void) { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
};

void ClientTransStreamTest::SetUpTestCase(void) { }

void ClientTransStreamTest::TearDownTestCase(void) { }

static void TestOnStreamReceived(
    int32_t channelId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    (void)channelId;
    (void)data;
    (void)ext;
    (void)param;
}

static int32_t TestOnFileGetSessionId(int32_t channelId, int32_t *sessionId)
{
    (void)channelId;
    (void)sessionId;
    return SOFTBUS_OK;
}

static int32_t TestOnUdpChannelOpened(int32_t channelId, SocketAccessInfo *accessInfo)
{
    (void)channelId;
    (void)accessInfo;
    return SOFTBUS_OK;
}

static void TestOnUdpChannelClosed(int32_t channelId, ShutdownReason reason)
{
    (void)channelId;
    (void)reason;
}

static void TestOnQosEvent(int channelId, int eventId, int tvCount, const QosTv *tvList)
{
    (void)channelId;
    (void)eventId;
    (void)tvCount;
    (void)tvList;
}

static int32_t TestOnIdleTimeoutReset(int32_t sessionId)
{
    (void)sessionId;
    return SOFTBUS_OK;
}

static int32_t TestOnRawStreamEncryptOptGet(int32_t sessionId, int32_t channelId, bool *isEncrypt)
{
    (void)sessionId;
    (void)channelId;
    (void)isEncrypt;
    return SOFTBUS_OK;
}

static UdpChannelMgrCb g_testUdpChannelCb = {
    .OnStreamReceived = TestOnStreamReceived,
    .OnFileGetSessionId = TestOnFileGetSessionId,
    .OnMessageReceived = nullptr,
    .OnUdpChannelOpened = TestOnUdpChannelOpened,
    .OnUdpChannelClosed = TestOnUdpChannelClosed,
    .OnQosEvent = TestOnQosEvent,
    .OnIdleTimeoutReset = TestOnIdleTimeoutReset,
    .OnRawStreamEncryptOptGet = TestOnRawStreamEncryptOptGet,
};

/**
 * @tc.name: RegisterStreamCbTest001
 * @tc.desc: register stream callback with nullptr and zeroed struct, callback not registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, RegisterStreamCbTest001, TestSize.Level1)
{
    RegisterStreamCb(nullptr);
    UdpChannelMgrCb zeroedCb = { };
    RegisterStreamCb(&zeroedCb);
    int32_t ret = OnStreamUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: RegisterStreamCbTest002
 * @tc.desc: register stream callback with valid callback struct, callback registered successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, RegisterStreamCbTest002, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    ret = OnStreamUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: UnregisterStreamCbTest001
 * @tc.desc: unregister stream callback after registration, callback removed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, UnregisterStreamCbTest001, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    UnregisterStreamCb();
    ret = OnStreamUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: SetStreamChannelStatusTest001
 * @tc.desc: set stream channel status without callback registered, early return for various status values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, SetStreamChannelStatusTest001, TestSize.Level1)
{
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_INIT);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_CLOSED);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_CONNECTING);
    int32_t ret = OnStreamUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: SetStreamChannelStatusTest002
 * @tc.desc: set stream channel status to STREAM_CONNECTED with callback, notify connected event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, SetStreamChannelStatusTest002, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_CONNECTED);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: SetStreamChannelStatusTest003
 * @tc.desc: set stream channel status to STREAM_CLOSED with callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, SetStreamChannelStatusTest003, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_CLOSED);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: SetStreamChannelStatusTest004
 * @tc.desc: set stream channel status to STREAM_INIT with callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, SetStreamChannelStatusTest004, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_INIT);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: SetStreamChannelStatusTest005
 * @tc.desc: set stream channel status to STREAM_OPENING with callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, SetStreamChannelStatusTest005, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_OPENING);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: SetStreamChannelStatusTest006
 * @tc.desc: set stream channel status to STREAM_CONNECTING with callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, SetStreamChannelStatusTest006, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_CONNECTING);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: SetStreamChannelStatusTest007
 * @tc.desc: set stream channel status to STREAM_CLOSING with callback, close stream udp channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, SetStreamChannelStatusTest007, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_CLOSING);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: SetStreamChannelStatusTest008
 * @tc.desc: set stream channel status to unsupported status value, default branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, SetStreamChannelStatusTest008, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    SetStreamChannelStatus(TEST_CHANNELID, STREAM_OPENED);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: OnStreamReceivedTest001
 * @tc.desc: on stream received without callback registered, early return for various channel ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnStreamReceivedTest001, TestSize.Level1)
{
    OnStreamReceived(TEST_CHANNELID, nullptr, nullptr, nullptr);
    OnStreamReceived(0, nullptr, nullptr, nullptr);
    OnStreamReceived(-1, nullptr, nullptr, nullptr);
    int32_t ret = OnStreamUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: OnStreamReceivedTest002
 * @tc.desc: on stream received with callback registered, call callback function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnStreamReceivedTest002, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    OnStreamReceived(TEST_CHANNELID, nullptr, nullptr, nullptr);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: OnQosEventTest001
 * @tc.desc: on qos event without callback registered, early return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnQosEventTest001, TestSize.Level1)
{
    QosTv *tvList = reinterpret_cast<QosTv *>(SoftBusCalloc(sizeof(QosTv)));
    ASSERT_TRUE(tvList != nullptr);
    OnQosEvent(TEST_CHANNELID, 21, 3, tvList);
    int32_t ret = OnStreamUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    SoftBusFree(tvList);
}

/**
 * @tc.name: OnQosEventTest002
 * @tc.desc: on qos event with callback registered, call callback function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnQosEventTest002, TestSize.Level1)
{
    QosTv *tvList = reinterpret_cast<QosTv *>(SoftBusCalloc(sizeof(QosTv)));
    ASSERT_TRUE(tvList != nullptr);
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    OnQosEvent(TEST_CHANNELID, 21, 3, tvList);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
    SoftBusFree(tvList);
}

/**
 * @tc.name: OnFrameStatsTest001
 * @tc.desc: on frame stats with various channel ids, notify server via ipc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnFrameStatsTest001, TestSize.Level1)
{
    StreamSendStats *data = reinterpret_cast<StreamSendStats *>(SoftBusCalloc(sizeof(StreamSendStats)));
    ASSERT_TRUE(data != nullptr);
    OnFrameStats(TEST_NORMALCHANNELID, data);
    OnFrameStats(0, data);
    OnFrameStats(-1, data);
    SoftBusFree(data);
}

/**
 * @tc.name: OnRippleStatsTest001
 * @tc.desc: on ripple stats with various channel ids, notify server via ipc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnRippleStatsTest001, TestSize.Level1)
{
    TrafficStats *data = reinterpret_cast<TrafficStats *>(SoftBusCalloc(sizeof(TrafficStats)));
    ASSERT_TRUE(data != nullptr);
    OnRippleStats(TEST_NORMALCHANNELID, data);
    OnRippleStats(0, data);
    OnRippleStats(-1, data);
    SoftBusFree(data);
}

/**
 * @tc.name: TransSendStreamTest001
 * @tc.desc: trans send stream with invalid and non-existent channel, returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransSendStreamTest001, TestSize.Level1)
{
    int32_t ret = TransSendStream(-1, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    StreamData *data = reinterpret_cast<StreamData *>(SoftBusCalloc(sizeof(StreamData)));
    StreamData *ext = reinterpret_cast<StreamData *>(SoftBusCalloc(sizeof(StreamData)));
    StreamFrameInfo *param = reinterpret_cast<StreamFrameInfo *>(SoftBusCalloc(sizeof(StreamFrameInfo)));
    if (data == nullptr || ext == nullptr || param == nullptr) {
        SoftBusFree(data);
        SoftBusFree(ext);
        SoftBusFree(param);
        return;
    }
    ret = TransSendStream(TEST_NORMALCHANNELID, data, ext, param);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(data);
    SoftBusFree(ext);
    SoftBusFree(param);
}

/**
 * @tc.name: TransOnstreamChannelOpenedTest001
 * @tc.desc: trans on stream channel opened with null params, returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransOnstreamChannelOpenedTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t streamPort = 2;
    ret = TransOnstreamChannelOpened(nullptr, &streamPort, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransOnstreamChannelOpened(channel, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransOnstreamChannelOpened(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
    TransClientDeinit();
}

/**
 * @tc.name: TransOnstreamChannelOpenedTest002
 * @tc.desc: trans on stream channel opened with INVALID stream type, returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransOnstreamChannelOpenedTest002, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t streamPort = 2;
    channel->streamType = INVALID;
    ret = TransOnstreamChannelOpened(channel, &streamPort, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
    TransClientDeinit();
}

/**
 * @tc.name: TransOnstreamChannelOpenedTest003
 * @tc.desc: trans on stream channel opened with VIDEO_SLICE_STREAM type, returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransOnstreamChannelOpenedTest003, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t streamPort = 2;
    channel->streamType = VIDEO_SLICE_STREAM;
    ret = TransOnstreamChannelOpened(channel, &streamPort, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
    TransClientDeinit();
}

/**
 * @tc.name: TransOnstreamChannelOpenedTest004
 * @tc.desc: trans on stream channel opened with RAW_STREAM type without callback, returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransOnstreamChannelOpenedTest004, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t streamPort = 2;
    channel->streamType = RAW_STREAM;
    channel->isServer = false;
    channel->channelId = -1;
    ret = TransOnstreamChannelOpened(channel, &streamPort, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
    TransClientDeinit();
}

/**
 * @tc.name: TransCloseStreamChannelTest001
 * @tc.desc: trans close stream channel with invalid channel ids, returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransCloseStreamChannelTest001, TestSize.Level1)
{
    int32_t ret = TransCloseStreamChannel(-1);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = TransCloseStreamChannel(0);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = TransCloseStreamChannel(1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED);
}

/**
 * @tc.name: OnStreamUdpChannelOpenedTest001
 * @tc.desc: on stream udp channel opened without callback, returns SOFTBUS_NO_INIT for various channel ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnStreamUdpChannelOpenedTest001, TestSize.Level1)
{
    int32_t ret = OnStreamUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = OnStreamUdpChannelOpened(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = OnStreamUdpChannelOpened(-1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: OnStreamUdpChannelOpenedTest002
 * @tc.desc: on stream udp channel opened with callback, returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnStreamUdpChannelOpenedTest002, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    ret = OnStreamUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransSetStreamMultiLayerTest001
 * @tc.desc: trans set stream multi layer with invalid channel ids, returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransSetStreamMultiLayerTest001, TestSize.Level1)
{
    int32_t ret = TransSetStreamMultiLayer(-1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransSetStreamMultiLayer(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransSetStreamMultiLayer(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: NotifyStreamChannelConnectedEventTest001
 * @tc.desc: notify stream channel connected event with negative and valid channel ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, NotifyStreamChannelConnectedEventTest001, TestSize.Level1)
{
    NotifyStreamChannelConnectedEvent(-1);
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(&g_testUdpChannelCb);
    NotifyStreamChannelConnectedEvent(TEST_NORMALCHANNELID);
    UnregisterStreamCb();
    ClientTransUdpMgrDeinit();
}
} // namespace OHOS
