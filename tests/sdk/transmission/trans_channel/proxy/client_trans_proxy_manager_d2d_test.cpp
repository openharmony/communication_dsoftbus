/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "client_trans_proxy_manager.h"
#include "client_trans_proxy_manager.c"
#include "client_trans_proxy_manager_d2d_mock.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "session.h"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_CHANNEL_ID    (-10)
#define TEST_DATA_LENGTH_2 100

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {

int32_t TransOnSessionOpened(
    const char *sessionName, const ChannelInfo *channel, SessionType flag, SocketAccessInfo *accessInfo)
{
    return SOFTBUS_OK;
}

int32_t TransOnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    return SOFTBUS_OK;
}

int32_t TransOnBytesReceived(
    int32_t channelId, int32_t channelType, const void *data, uint32_t len, SessionPktType type)
{
    return SOFTBUS_OK;
}

int32_t TransOnOnStreamRecevied(
    int32_t channelId, int32_t channelType, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    return SOFTBUS_OK;
}

int32_t TransOnGetSessionId(int32_t channelId, int32_t channelType, int32_t *sessionId)
{
    return SOFTBUS_OK;
}
int32_t TransOnQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    return SOFTBUS_OK;
}

static IClientSessionCallBack g_clientSessionCb = {
    .OnSessionOpened = TransOnSessionOpened,
    .OnSessionClosed = TransOnSessionClosed,
    .OnSessionOpenFailed = TransOnSessionOpenFailed,
    .OnDataReceived = TransOnBytesReceived,
    .OnStreamReceived = TransOnOnStreamRecevied,
    .OnQosEvent = TransOnQosEvent,
};

class ClientTransProxyD2DTest : public testing::Test {
public:
    ClientTransProxyD2DTest() { }
    ~ClientTransProxyD2DTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void ClientTransProxyD2DTest::SetUpTestCase(void)
{
    int32_t ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SetAccessTokenPermission("dsoftbusTransTest");
}

void ClientTransProxyD2DTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: TransProxyChannelAsyncSendMessageTest001
 * @tc.desc: trans proxy channel async send message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyChannelAsyncSendMessageTest001, TestSize.Level1)
{
    char data[] = "1111";
    uint32_t len = 5;
    uint16_t dataSeq = 1;
    int32_t channelId = 1;
    int32_t ret = TransProxyChannelAsyncSendMessage(channelId, nullptr, len, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyChannelAsyncSendMessage(channelId, data, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: ClientTransProxyPackAndSendDataTest001
 * @tc.desc: trans proxy channel async send data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyPackAndSendDataTest001, TestSize.Level1)
{
    char data[] = "1111";
    uint32_t len = 5;
    int32_t channelId = 1;
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyPackAndSendData(channelId, nullptr, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransProxyPackAndSendData(channelId, data, len, nullptr, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));

    ret = ClientTransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));

    ret = ClientTransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    businessType = BUSINESS_TYPE_D2D_VOICE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));
    EXPECT_CALL(managerMock, TransProxyPackD2DBytes).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransProxyProcessD2DBytesTest
 * @tc.desc: trans proxy process d2d bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyProcessD2DBytesTest, TestSize.Level1)
{
    uint8_t data[] = "1111";
    uint32_t len = 5;
    int32_t channelId = 1;
    ProxyChannelInfoDetail info;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, TransProxyPackD2DBytes).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyProcessD2DBytes(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransProxyFirstSliceProcessTest
 * @tc.desc: trans proxy process first slice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyFirstSliceProcessTest, TestSize.Level1)
{
    SliceProcessor processor;
    SliceHead head;
    char data[] = "1111";
    uint32_t len = 5;
    int32_t channelId = 1;
    int32_t businessType = BUSINESS_TYPE_D2D_VOICE;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));

    int32_t ret = ClientTransProxyFirstSliceProcess(&processor, &head, data, len, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    businessType = BUSINESS_TYPE_D2D_MESSAGE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));

    ret = ClientTransProxyFirstSliceProcess(&processor, &head, data, len, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyNoSubPacketProc
 * @tc.desc: trans proxy process first slice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNoSubPacketProc, TestSize.Level1)
{
    char data[] = "1111";
    uint32_t len = 5;
    int32_t channelId = 1;
    int32_t businessType = BUSINESS_TYPE_D2D_VOICE;

    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));

    int32_t ret = ClientTransProxyNoSubPacketProc(channelId, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    businessType = BUSINESS_TYPE_D2D_MESSAGE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));

    ret = ClientTransProxyNoSubPacketProc(channelId, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransProxyNoSubPacketD2DDataProcTest
 * @tc.desc: trans proxy process no sub packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNoSubPacketD2DDataProcTest, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = "1111111111111";
    uint32_t len = 14;
    int32_t channelId = 1;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    int32_t ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, nullptr, len, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, data, 0, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, data, len, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, TransProxyProcessD2DData).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    PacketD2DHead head;
    head.flags = TRANS_SESSION_BYTES;
    head.dataLen = 6;
    (void)memcpy_s(data, TEST_DATA_LENGTH_2, &head, sizeof(PacketD2DHead));
    businessType = BUSINESS_TYPE_D2D_VOICE;
    ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, data, len, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    businessType = BUSINESS_TYPE_D2D_MESSAGE;
    ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, data, len, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
}

/**
 * @tc.name: ClientTransProxyProcD2DDataTest
 * @tc.desc: trans proxy process d2d data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DDataTest, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = "1111111111111";
    int32_t channelId = 1;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    PacketD2DHead head;
    PacketD2DIvSource ivSource = {
        .dataSeq = 1,
        .nonce = 1,
    };

    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, TransProxyProcessD2DData).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ClientTransProxyProcD2DData(channelId, data, &head, businessType, &ivSource);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
    EXPECT_CALL(managerMock, TransProxyDecryptD2DData).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    ret = ClientTransProxyProcD2DData(channelId, data, &head, businessType, &ivSource);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    EXPECT_CALL(managerMock, TransProxyDecryptD2DData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, TransProxySessionDataLenCheck).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyProcD2DData(channelId, data, &head, businessType, &ivSource);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    EXPECT_CALL(managerMock, TransProxySessionDataLenCheck).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ClientTransProxyProcD2DData(channelId, data, &head, businessType, &ivSource);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: ClientTransProxyNotifyD2DTest
 * @tc.desc: trans proxy notify d2d data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNotifyD2DTest, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = "1111111111111";
    uint32_t len = 14;
    int32_t channelId = 1;
    uint16_t dataSeq = 1;
    int32_t ret = ClientTransProxyNotifyD2D(channelId, TRANS_SESSION_MESSAGE, dataSeq, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyNotifyD2D(channelId, TRANS_SESSION_ACK, dataSeq, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    ret = ClientTransProxyNotifyD2D(channelId, TRANS_SESSION_BYTES, dataSeq, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyNotifyD2D(channelId, TRANS_SESSION_ASYNC_MESSAGE, dataSeq, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyNotifyD2D(channelId, TRANS_SESSION_FILE_ACK_RESPONSE_SENT, dataSeq, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyProcD2DAckTest
 * @tc.desc: trans proxy d2d ack
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DAckTest, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = "1111111111111";
    uint32_t len = 14;
    int32_t channelId = 1;
    uint16_t dataSeq = 1;
    int32_t ret = ClientTransProxyProcD2DAck(channelId, nullptr, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    ret = ClientTransProxyProcD2DAck(channelId, data, 0, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    ret = ClientTransProxyProcD2DAck(channelId, data, len, 0);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    ret = ClientTransProxyProcD2DAck(channelId, data, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ClientGetSessionIdByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ClientTransProxyProcD2DAck(channelId, data, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    EXPECT_CALL(managerMock, ClientGetSessionCallbackAdapterById).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ClientTransProxyProcD2DAck(channelId, data, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    EXPECT_CALL(managerMock, DeleteDataSeqInfoList).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ClientTransProxyProcD2DAck(channelId, data, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/**
 * @tc.name: ClientTransProxySendD2DAckTest
 * @tc.desc: trans proxy channel send d2d ack
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxySendD2DAckTest, TestSize.Level1)
{
    int32_t channelId = 1;
    uint16_t dataSeq = 1;
    EXPECT_NO_FATAL_FAILURE(ClientTransProxySendD2DAck(channelId, dataSeq));

    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_NO_FATAL_FAILURE(ClientTransProxySendD2DAck(channelId, dataSeq));

    int32_t businessType = BUSINESS_TYPE_BYTE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(ClientTransProxySendD2DAck(channelId, dataSeq));

    businessType = BUSINESS_TYPE_D2D_MESSAGE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(ClientTransProxySendD2DAck(channelId, dataSeq));
}

/**
 * @tc.name: TransProxyChannelAsyncSendMessageTest
 * @tc.desc: trans proxy channel async send message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyChannelAsyncSendMessageTest, TestSize.Level1)
{
    char data[] = "1111";
    uint32_t len = 5;
    uint16_t dataSeq = 1;
    int32_t channelId = 1;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ServerIpcSendMessage).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransProxyAsyncPackAndSendMessage(channelId, nullptr, len, dataSeq, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyAsyncPackAndSendMessage(channelId, data, len, dataSeq, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ClientProxyChannelInfo *info = (ClientProxyChannelInfo *)SoftBusCalloc(sizeof(ClientProxyChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->channelId = 1;
    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyAsyncPackAndSendMessage(channelId, data, len, dataSeq, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    ret = ClientTransProxyDelChannelInfo(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyPackAsyncMessageTest
 * @tc.desc: trans proxy channel pack message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyPackAsyncMessageTest, TestSize.Level1)
{
    uint16_t dataSeq = 1;
    int32_t channelId = 1;
    ProxyChannelInfoDetail info;
    ProxyDataInfo dataInfo;
    int32_t ret = TransProxyPackAsyncMessage(channelId, nullptr, &dataInfo, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPackAsyncMessage(channelId, &info, nullptr, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyPackAsyncMessage(channelId, &info, &dataInfo, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR, ret);

    ProxyChannelInfoDetail info1 = {
        .pagingSessionkey = "111111111111111",
        .pagingNonce = "11111111111",
    };
    ProxyDataInfo dataInfo1 = {
        .inData = (uint8_t *)"1111",
        .inLen = 5,
    };
    ret = TransProxyPackAsyncMessage(channelId, &info1, &dataInfo1, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS