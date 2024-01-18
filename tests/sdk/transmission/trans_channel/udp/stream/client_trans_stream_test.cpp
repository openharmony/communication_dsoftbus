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
#include <iostream>
#include <gtest/gtest.h>
#include <securec.h>

#include "client_trans_session_manager.h"
#include "client_trans_stream.c"
#include "client_trans_stream.h"
#include "client_trans_udp_manager.h"
#include "softbus_adapter_mem.h"
#include "trans_server_proxy.h"

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
    ASSERT_TRUE(ret == SOFTBUS_OK);
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
    int channelId = 12;
    int eventId = 21;
    int tvCount = 3;

    OnQosEvent(channelId, eventId, tvCount, tvList);

    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
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
    int channelId = 12;

    OnFrameStats(channelId, dataStreamSendStats);
    OnRippleStats(channelId, dataTrafficStats);
    
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
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
    int ret = TransSendStream(channelId, dataStreamData, extStreamData, paramStreamFrameInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);

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
 * @tc.desc: TransOnstreamChannelOpened error.
 * @tc.desc: OnRippleStats error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransStreamTest, TransOnstreamChannelOpened001, TestSize.Level0)
{
    int ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ChannelInfo *channel = (ChannelInfo*)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    (void)memset_s(channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));

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
    EXPECT_EQ(SOFTBUS_TRANS_UDP_START_STREAM_CLIENT_FAILED, ret);

    channel->isServer = true;
    ret = TransOnstreamChannelOpened(channel, &streamPort);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_START_STREAM_SERVER_FAILED, ret);

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
    int ret = TransCloseStreamChannel(channelId);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channelId = 1;
    ret = TransCloseStreamChannel(channelId);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
} // OHOS
