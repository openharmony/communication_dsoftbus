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
#include <iostream>
#include <gtest/gtest.h>
#include <securec.h>

#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_stream.c"
#include "client_trans_stream.h"
#include "client_trans_udp_manager.h"
#include "softbus_adapter_mem.h"
#include "trans_server_proxy.h"

#define TEST_CHANNELID 1025

using namespace testing::ext;
namespace OHOS {
class ClientTransStreamTest : public testing::Test {
public:
    ClientTransStreamTest()
    {}
    ~ClientTransStreamTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void ClientTransStreamTest::SetUpTestCase(void)
{}

void ClientTransStreamTest::TearDownTestCase(void)
{}

static void TestOnStreamReceived(int32_t channelId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
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

static int32_t TestOnUdpChannelOpened(int32_t channelId)
{
    (void)channelId;
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

static int32_t TestOnRawStreamEncryptOptGet(int32_t channelId, bool *isEncrypt)
{
    (void)channelId;
    (void)isEncrypt;
    return SOFTBUS_OK;
}

static UdpChannelMgrCb g_testUdpChannelCb = {
    .OnStreamReceived = TestOnStreamReceived,
    .OnFileGetSessionId = TestOnFileGetSessionId,
    .OnMessageReceived = NULL,
    .OnUdpChannelOpened = TestOnUdpChannelOpened,
    .OnUdpChannelClosed = TestOnUdpChannelClosed,
    .OnQosEvent = TestOnQosEvent,
    .OnIdleTimeoutReset = TestOnIdleTimeoutReset,
    .OnRawStreamEncryptOptGet = TestOnRawStreamEncryptOptGet,
};

/**
 * @tc.name: RegisterStreamCb001
 * @tc.desc: RegisterStreamCb error.
 * @tc.desc: UnregisterStreamCb error.
 * @tc.desc: SetStreamChannelStatus error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, RegisterStreamCb001, TestSize.Level0)
{
    RegisterStreamCb(NULL);
    UnregisterStreamCb();
    int32_t channelId = 12;
    int32_t status = 2;
    SetStreamChannelStatus(channelId, status);

    UdpChannelMgrCb *streamCb = (UdpChannelMgrCb*)SoftBusMalloc(sizeof(UdpChannelMgrCb));
    ASSERT_TRUE(streamCb != nullptr);
    (void)memset_s(streamCb, sizeof(UdpChannelMgrCb), 0, sizeof(UdpChannelMgrCb));

    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(streamCb);
    SetStreamChannelStatus(channelId, status);

    status = STREAM_CONNECTED;
    SetStreamChannelStatus(channelId, status);

    status = STREAM_CLOSED;
    SetStreamChannelStatus(channelId, status);

    status = STREAM_INIT;
    SetStreamChannelStatus(channelId, status);

    status = STREAM_OPENING;
    SetStreamChannelStatus(channelId, status);

    status = STREAM_CONNECTING;
    SetStreamChannelStatus(channelId, status);

    status = STREAM_CLOSING;
    SetStreamChannelStatus(channelId, status);

    status = STREAM_OPENED;
    SetStreamChannelStatus(channelId, status);

    OnStreamReceived(channelId, NULL, NULL, NULL);
    UnregisterStreamCb();
    OnStreamReceived(channelId, NULL, NULL, NULL);
    if (streamCb != nullptr) {
        SoftBusFree(streamCb);
    }
}

/**
 * @tc.name: OnQosEvent001
 * @tc.desc: OnQosEvent error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnQosEvent001, TestSize.Level0)
{
    QosTv *tvList = (QosTv*)SoftBusMalloc(sizeof(QosTv));
    ASSERT_TRUE(tvList != nullptr);
    (void)memset_s(tvList, sizeof(QosTv), 0, sizeof(QosTv));
    int32_t channelId = 12;
    int32_t eventId = 21;
    int32_t tvCount = 3;

    OnQosEvent(channelId, eventId, tvCount, tvList);

    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnQosEvent(channelId, eventId, tvCount, tvList);

    ClientTransUdpMgrDeinit();
    if (tvList != nullptr) {
        SoftBusFree(tvList);
    }
}

/**
 * @tc.name: OnFrameStats001
 * @tc.desc: OnFrameStats error.
 * @tc.desc: OnRippleStats error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, OnFrameStats001, TestSize.Level0)
{
    StreamSendStats *dataStreamSendStats = (StreamSendStats*)SoftBusMalloc(sizeof(StreamSendStats));
    ASSERT_TRUE(dataStreamSendStats != nullptr);
    (void)memset_s(dataStreamSendStats, sizeof(StreamSendStats), 0, sizeof(StreamSendStats));
    TrafficStats *dataTrafficStats = (TrafficStats*)SoftBusMalloc(sizeof(TrafficStats));
    ASSERT_TRUE(dataTrafficStats != nullptr);
    (void)memset_s(dataTrafficStats, sizeof(TrafficStats), 0, sizeof(TrafficStats));
    UdpChannelMgrCb *streamCb = (UdpChannelMgrCb*)SoftBusMalloc(sizeof(UdpChannelMgrCb));
    ASSERT_TRUE(streamCb != nullptr);
    (void)memset_s(streamCb, sizeof(UdpChannelMgrCb), 0, sizeof(UdpChannelMgrCb));
    int32_t channelId = 12;

    OnFrameStats(channelId, dataStreamSendStats);
    OnRippleStats(channelId, dataTrafficStats);
    
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RegisterStreamCb(streamCb);
 
    OnFrameStats(channelId, dataStreamSendStats);
    OnRippleStats(channelId, dataTrafficStats);

    UnregisterStreamCb();
    if (dataStreamSendStats != nullptr) {
        SoftBusFree(dataStreamSendStats);
    }
    if (dataTrafficStats != nullptr) {
        SoftBusFree(dataTrafficStats);
    }
    if (streamCb != nullptr) {
        SoftBusFree(streamCb);
    }
}

/**
 * @tc.name: TransSendStream001
 * @tc.desc: TransSendStream error.
 * @tc.desc: OnRippleStats error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransSendStream001, TestSize.Level0)
{
    StreamData *dataStreamData = (StreamData*)SoftBusMalloc(sizeof(StreamData));
    ASSERT_TRUE(dataStreamData != nullptr);
    (void)memset_s(dataStreamData, sizeof(StreamData), 0, sizeof(StreamData));

    StreamData *extStreamData = (StreamData*)SoftBusMalloc(sizeof(StreamData));
    ASSERT_TRUE(extStreamData != nullptr);
    (void)memset_s(extStreamData, sizeof(StreamData), 0, sizeof(StreamData));

    StreamFrameInfo *paramStreamFrameInfo = (StreamFrameInfo*)SoftBusMalloc(sizeof(StreamFrameInfo));
    ASSERT_TRUE(paramStreamFrameInfo != nullptr);
    (void)memset_s(paramStreamFrameInfo, sizeof(StreamFrameInfo), 0, sizeof(StreamFrameInfo));

    int32_t channelId = 12;
    int32_t ret = TransSendStream(channelId, dataStreamData, extStreamData, paramStreamFrameInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    if (dataStreamData != nullptr) {
        SoftBusFree(dataStreamData);
    }
    if (extStreamData != nullptr) {
        SoftBusFree(extStreamData);
    }
    if (paramStreamFrameInfo != nullptr) {
        SoftBusFree(paramStreamFrameInfo);
    }
}

/**
 * @tc.name: TransOnstreamChannelOpened001
 * @tc.desc: Should return SOFTBUS_NO_INIT when given invalid parameters.
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given nullptr parameters.
 * @tc.desc: OnRippleStats error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransOnstreamChannelOpened001, TestSize.Level0)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ChannelInfo *channel = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);

    int32_t streamPort = 2;
    ret = TransOnstreamChannelOpened(NULL, &streamPort);

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOnstreamChannelOpened(channel, NULL);

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOnstreamChannelOpened(NULL, NULL);

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channel->streamType = INVALID;
    ret = TransOnstreamChannelOpened(channel, &streamPort);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channel->streamType = VIDEO_SLICE_STREAM;
    ret = TransOnstreamChannelOpened(channel, &streamPort);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channel->streamType = RAW_STREAM;
    channel->isServer = false;
    channel->channelId = -1;
    ret = TransOnstreamChannelOpened(channel, &streamPort);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    channel->isServer = true;
    ret = TransOnstreamChannelOpened(channel, &streamPort);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    if (channel != nullptr) {
        SoftBusFree(channel);
    }
    TransClientDeinit();
}

/**
 * @tc.name: TransCloseStreamChannel001
 * @tc.desc: TransCloseStreamChannel error.
 * @tc.desc: OnRippleStats error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransCloseStreamChannel001, TestSize.Level0)
{
    int32_t channelId = -1;
    int32_t ret = TransCloseStreamChannel(channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = 1;
    ret = TransCloseStreamChannel(channelId);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);

    ret = OnStreamUdpChannelOpened(TEST_CHANNELID);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = -1;
    ret = TransSendStream(channelId, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = TEST_CHANNELID;
    ret = TransSendStream(channelId, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = -1;
    ret = TransSetStreamMultiLayer(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = TEST_CHANNELID;
    ret = TransSetStreamMultiLayer(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransStreamTest001
 * @tc.desc: TransCloseStreamChannel error.
 * @tc.desc: OnRippleStats error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, ClientTransStreamTest001, TestSize.Level0)
{
    RegisterStreamCb(&g_testUdpChannelCb);
    OnQosEvent(TEST_CHANNELID, TEST_CHANNELID, TEST_CHANNELID, nullptr);
    int32_t ret = OnStreamUdpChannelOpened(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UnregisterStreamCb();
}
} // OHOS
