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

#include "client_trans_proxy_file_manager.h"
#include "client_trans_proxy_manager.c"
#include "client_trans_proxy_manager.h"
#include "client_trans_proxy_manager_d2d_mock.h"
#include "client_trans_session_manager.h"
#include "g_enhance_sdk_func.h"
#include "session.h"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_CHANNEL_ID    1
#define TEST_DATA_SEQ      1
#define TEST_DATA          "1111"
#define TEST_DATA_LEN      5
#define TEST_LONG_DATA     "1111111111111"
#define TEST_LONG_DATA_LEN 14
#define TEST_ACK_LEN       4
#define TEST_DATA_LENGTH_2 100
#define TEST_LEN           66666

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {

int32_t TransOnSessionOpened(
    const char *sessionName, const ChannelInfo *channel, SessionType flag, SocketAccessInfo *accessInfo)
{
    (void)sessionName;
    (void)channel;
    (void)flag;
    (void)accessInfo;
    return SOFTBUS_OK;
}

int32_t TransOnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    (void)channelId;
    (void)channelType;
    (void)reason;
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    (void)channelId;
    (void)channelType;
    (void)errCode;
    return SOFTBUS_OK;
}

int32_t TransOnBytesReceived(
    int32_t channelId, int32_t channelType, const void *data, uint32_t len, SessionPktType type)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)len;
    (void)type;
    return SOFTBUS_OK;
}

int32_t TransOnOnStreamRecevied(
    int32_t channelId, int32_t channelType, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)ext;
    (void)param;
    return SOFTBUS_OK;
}

int32_t TransOnGetSessionId(int32_t channelId, int32_t channelType, int32_t *sessionId)
{
    (void)channelId;
    (void)channelType;
    (void)sessionId;
    return SOFTBUS_OK;
}

int32_t TransOnQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    (void)channelId;
    (void)channelType;
    (void)eventId;
    (void)tvCount;
    (void)tvList;
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
    void SetUp(void) override { }
    void TearDown(void) override { }
};

void ClientTransProxyD2DTest::SetUpTestCase(void)
{
    int32_t ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SetAccessTokenPermission("dsoftbusTransTest");
}

void ClientTransProxyD2DTest::TearDownTestCase(void) { }

/*
 * @tc.name: TransProxyChannelAsyncSendMessageTest001
 * @tc.desc: trans proxy channel async send message with null data returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyChannelAsyncSendMessageTest001, TestSize.Level1)
{
    uint32_t len = TEST_DATA_LEN;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransProxyChannelAsyncSendMessage(channelId, nullptr, len, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyChannelAsyncSendMessageTest002
 * @tc.desc: trans proxy channel async send message with valid data but channel not found returns channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyChannelAsyncSendMessageTest002, TestSize.Level1)
{
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransProxyChannelAsyncSendMessage(channelId, data, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyPackAndSendDataTest001
 * @tc.desc: pack and send data with null data or null info returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyPackAndSendDataTest001, TestSize.Level1)
{
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyPackAndSendData(channelId, nullptr, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyPackAndSendData(channelId, data, len, nullptr, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyPackAndSendDataTest002
 * @tc.desc: pack and send data with business type byte returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyPackAndSendDataTest002, TestSize.Level1)
{
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));
    int32_t ret = ClientTransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyPackAndSendDataTest003
 * @tc.desc: pack and send data with d2d voice business type and pack fails returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyPackAndSendDataTest003, TestSize.Level1)
{
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    int32_t businessType = BUSINESS_TYPE_D2D_VOICE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));
    EXPECT_CALL(managerMock, TransProxyPackD2DBytes).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyProcessD2DBytesTest001
 * @tc.desc: process d2d bytes when pack d2d bytes fails returns pack error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyProcessD2DBytesTest001, TestSize.Level1)
{
    uint8_t data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, TransProxyPackD2DBytes).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyProcessD2DBytes(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyProcessD2DBytesTest002
 * @tc.desc: process d2d bytes when slice pack returns null returns malloc err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyProcessD2DBytesTest002, TestSize.Level1)
{
    uint8_t data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, TransProxyPackD2DBytes).WillRepeatedly(Return(SOFTBUS_OK));
    ProxyDataInfo dataInfo = { data, len, nullptr, len };
    dataInfo.outData = static_cast<uint8_t *>(SoftBusCalloc(dataInfo.outLen));
    ASSERT_TRUE(dataInfo.outData != nullptr);
    EXPECT_CALL(managerMock, TransProxyPackD2DData).WillRepeatedly(DoAll(SetArgPointee<0>(dataInfo), Return(nullptr)));
    int32_t ret = TransProxyProcessD2DBytes(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
}

/*
 * @tc.name: TransProxyProcessD2DBytesTest003
 * @tc.desc: process d2d bytes when slice pack returns valid data returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyProcessD2DBytesTest003, TestSize.Level1)
{
    uint8_t data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    uint8_t *testData = static_cast<uint8_t *>(SoftBusCalloc(len));
    ASSERT_TRUE(testData != nullptr);
    EXPECT_CALL(managerMock, TransProxyPackD2DBytes).WillRepeatedly(Return(SOFTBUS_OK));
    ProxyDataInfo dataInfo = { data, len, nullptr, len };
    dataInfo.outData = static_cast<uint8_t *>(SoftBusCalloc(dataInfo.outLen));
    ASSERT_TRUE(dataInfo.outData != nullptr);
    EXPECT_CALL(managerMock, TransProxyPackD2DData).WillRepeatedly(DoAll(SetArgPointee<0>(dataInfo), Return(testData)));
    EXPECT_CALL(managerMock, ServerIpcSendMessage).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransProxyProcessD2DBytes(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyFirstSliceProcessTest001
 * @tc.desc: first slice process with non-d2d business type returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyFirstSliceProcessTest001, TestSize.Level1)
{
    SliceProcessor processor;
    SliceHead head;
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId).WillOnce(Return(SOFTBUS_NOT_FIND));
    int32_t ret = ClientTransProxyFirstSliceProcess(&processor, &head, data, len, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyFirstSliceProcessTest002
 * @tc.desc: first slice process with d2d voice business type and get info fails returns channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyFirstSliceProcessTest002, TestSize.Level1)
{
    SliceProcessor processor;
    SliceHead head;
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    int32_t businessType = BUSINESS_TYPE_D2D_VOICE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));
    int32_t ret = ClientTransProxyFirstSliceProcess(&processor, &head, data, len, channelId);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketProcTest001
 * @tc.desc: no sub packet proc with business type getter failure returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNoSubPacketProcTest001, TestSize.Level1)
{
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId).WillOnce(Return(SOFTBUS_NOT_FIND));
    int32_t ret = ClientTransProxyNoSubPacketProc(channelId, data, len);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketProcTest002
 * @tc.desc: no sub packet proc with d2d voice business type and get info fails returns channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNoSubPacketProcTest002, TestSize.Level1)
{
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    int32_t businessType = BUSINESS_TYPE_D2D_VOICE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));
    int32_t ret = ClientTransProxyNoSubPacketProc(channelId, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketD2DDataProcTest001
 * @tc.desc: no sub packet d2d data proc with null data or zero len returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNoSubPacketD2DDataProcTest001, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    uint32_t len = TEST_LONG_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    int32_t ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, nullptr, len, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, data, 0, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketD2DDataProcTest002
 * @tc.desc: no sub packet d2d data proc with d2d voice and len mismatch returns invalid data head
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNoSubPacketD2DDataProcTest002, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    uint32_t len = TEST_LONG_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t businessType = BUSINESS_TYPE_D2D_VOICE;
    PacketD2DHead head;
    head.flags = TRANS_SESSION_BYTES;
    head.dataLen = 6;
    (void)memcpy_s(data, TEST_DATA_LENGTH_2, &head, sizeof(PacketD2DHead));
    int32_t ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, data, len, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketD2DDataProcTest003
 * @tc.desc: no sub packet d2d data proc with d2d message and len mismatch returns invalid data head
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNoSubPacketD2DDataProcTest003, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    uint32_t len = TEST_LONG_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t businessType = BUSINESS_TYPE_D2D_MESSAGE;
    PacketD2DHead head;
    head.flags = TRANS_SESSION_BYTES;
    head.dataLen = 6;
    (void)memcpy_s(data, TEST_DATA_LENGTH_2, &head, sizeof(PacketD2DHead));
    int32_t ret = ClientTransProxyNoSubPacketD2DDataProc(channelId, data, len, businessType);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
}

/*
 * @tc.name: ClientTransProxyProcD2DDataTest001
 * @tc.desc: proc d2d data with process d2d data ok but channel not found returns channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DDataTest001, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    int32_t channelId = TEST_CHANNEL_ID;
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
}

/*
 * @tc.name: ClientTransProxyProcD2DDataTest002
 * @tc.desc: proc d2d data with process d2d data failure returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DDataTest002, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    PacketD2DHead head;
    PacketD2DIvSource ivSource = {
        .dataSeq = 1,
        .nonce = 1,
    };
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, TransProxyProcessD2DData).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransProxyProcD2DData(channelId, data, &head, businessType, &ivSource);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyNotifyD2DTest001
 * @tc.desc: notify d2d with session message type returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNotifyD2DTest001, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    uint32_t len = TEST_LONG_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t ret = ClientTransProxyNotifyD2D(channelId, TRANS_SESSION_MESSAGE, dataSeq, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyNotifyD2DTest002
 * @tc.desc: notify d2d with session ack type returns invalid data length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNotifyD2DTest002, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    uint32_t len = TEST_LONG_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t ret = ClientTransProxyNotifyD2D(channelId, TRANS_SESSION_ACK, dataSeq, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: ClientTransProxyNotifyD2DTest003
 * @tc.desc: notify d2d with session bytes type returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNotifyD2DTest003, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    uint32_t len = TEST_LONG_DATA_LEN;
    int32_t channelId = TEST_CHANNEL_ID;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t ret = ClientTransProxyNotifyD2D(channelId, TRANS_SESSION_BYTES, dataSeq, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyProcD2DAckTest001
 * @tc.desc: proc d2d ack with null data returns assemble pack data null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DAckTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t len = TEST_ACK_LEN;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t ret = ClientTransProxyProcD2DAck(channelId, nullptr, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL, ret);
}

/*
 * @tc.name: ClientTransProxyProcD2DAckTest002
 * @tc.desc: proc d2d ack with zero len returns invalid data length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DAckTest002, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    int32_t channelId = TEST_CHANNEL_ID;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t ret = ClientTransProxyProcD2DAck(channelId, data, 0, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: ClientTransProxyProcD2DAckTest003
 * @tc.desc: proc d2d ack with zero data seq returns invalid data length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DAckTest003, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t len = TEST_ACK_LEN;
    int32_t ret = ClientTransProxyProcD2DAck(channelId, data, len, 0);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: ClientTransProxyProcD2DAckTest004
 * @tc.desc: proc d2d ack with session id not found returns session info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DAckTest004, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t len = TEST_ACK_LEN;
    uint16_t dataSeq = TEST_DATA_SEQ;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ClientGetSessionIdByChannelId).WillOnce(Return(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND));
    int32_t ret = ClientTransProxyProcD2DAck(channelId, data, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyProcD2DAckTest005
 * @tc.desc: proc d2d ack with on message sent null returns register listener failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcD2DAckTest005, TestSize.Level1)
{
    char data[TEST_DATA_LENGTH_2] = TEST_LONG_DATA;
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t len = TEST_ACK_LEN;
    uint16_t dataSeq = TEST_DATA_SEQ;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ClientGetSessionIdByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, ClientGetSessionCallbackAdapterById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DeleteDataSeqInfoList).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ClientTransProxyProcD2DAck(channelId, data, len, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_REGISTER_LISTENER_FAILED, ret);
}

/*
 * @tc.name: ClientTransProxySendD2DAckTest001
 * @tc.desc: send d2d ack does not crash when channel info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxySendD2DAckTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    uint16_t dataSeq = TEST_DATA_SEQ;
    EXPECT_NO_FATAL_FAILURE(ClientTransProxySendD2DAck(channelId, dataSeq));
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    int32_t businessType = BUSINESS_TYPE_D2D_MESSAGE;
    EXPECT_CALL(managerMock, ClientGetChannelBusinessTypeByChannelId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(businessType), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(ClientTransProxySendD2DAck(channelId, dataSeq));
}

/*
 * @tc.name: TransProxyAsyncPackAndSendMessageTest001
 * @tc.desc: async pack and send message with null data returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyAsyncPackAndSendMessageTest001, TestSize.Level1)
{
    uint32_t len = TEST_DATA_LEN;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransProxyAsyncPackAndSendMessage(channelId, nullptr, len, dataSeq, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyAsyncPackAndSendMessageTest002
 * @tc.desc: async pack and send message with valid data but channel not found returns channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyAsyncPackAndSendMessageTest002, TestSize.Level1)
{
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransProxyAsyncPackAndSendMessage(channelId, data, len, dataSeq, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransProxyAsyncPackAndSendMessageTest003
 * @tc.desc: async pack and send message with channel added and pack returns null returns malloc err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyAsyncPackAndSendMessageTest003, TestSize.Level1)
{
    char data[] = TEST_DATA;
    uint32_t len = TEST_DATA_LEN;
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, TransProxyPackD2DData).WillRepeatedly(Return(nullptr));
    ClientProxyChannelInfo *info = static_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->channelId = channelId;
    char sessionKey[] = "111111111111111";
    (void)memcpy_s(info->detail.pagingSessionkey, SHORT_SESSION_KEY_LENGTH, sessionKey, strlen(sessionKey));
    char pagingNonce[] = "11111111111";
    (void)memcpy_s(info->detail.pagingNonce, PAGING_NONCE_LEN, pagingNonce, strlen(pagingNonce));
    int32_t ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyAsyncPackAndSendMessage(channelId, data, len, dataSeq, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    ret = ClientTransProxyDelChannelInfo(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyPackAsyncMessageTest001
 * @tc.desc: pack async message with null data info or null info returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyPackAsyncMessageTest001, TestSize.Level1)
{
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    ProxyDataInfo dataInfo;
    int32_t ret = TransProxyPackAsyncMessage(channelId, nullptr, &dataInfo, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPackAsyncMessage(channelId, &info, nullptr, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyPackAsyncMessageTest002
 * @tc.desc: pack async message with empty session key returns sess encrypt err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyPackAsyncMessageTest002, TestSize.Level1)
{
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    ProxyDataInfo dataInfo;
    int32_t ret = TransProxyPackAsyncMessage(channelId, &info, &dataInfo, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR, ret);
}

/*
 * @tc.name: TransProxyPackAsyncMessageTest003
 * @tc.desc: pack async message with valid session key returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyPackAsyncMessageTest003, TestSize.Level1)
{
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info1 = {
        .pagingSessionkey = "111111111111111",
        .pagingNonce = "11111111111",
    };
    ProxyDataInfo dataInfo1 = {
        .inData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA)),
        .inLen = 5,
    };
    int32_t ret = TransProxyPackAsyncMessage(channelId, &info1, &dataInfo1, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyPackAsyncMessageTest004
 * @tc.desc: pack async message with is d2d and is support new head returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyPackAsyncMessageTest004, TestSize.Level1)
{
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info1 = {
        .pagingSessionkey = "111111111111111",
        .pagingNonce = "11111111111",
    };
    ProxyDataInfo dataInfo1 = {
        .inData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA)),
        .inLen = 5,
    };
    info1.isD2D = true;
    info1.isSupportNewHead = true;
    int32_t ret = TransProxyPackAsyncMessage(channelId, &info1, &dataInfo1, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyPackNewHeadAsyncMessageTest001
 * @tc.desc: pack new head async message with null data info or null info or overflow len returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyPackNewHeadAsyncMessageTest001, TestSize.Level1)
{
    uint16_t dataSeq = TEST_DATA_SEQ;
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    ProxyDataInfo dataInfo = {
        .inData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA)),
        .inLen = 5,
    };
    int32_t ret = TransProxyPackNewHeadAsyncMessage(channelId, nullptr, &info, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPackNewHeadAsyncMessage(channelId, &dataInfo, nullptr, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    dataInfo.inLen = TEST_LEN;
    ret = TransProxyPackNewHeadAsyncMessage(channelId, &dataInfo, &info, TRANS_SESSION_MESSAGE, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyGenerateIvTest001
 * @tc.desc: generate iv with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyGenerateIvTest001, TestSize.Level1)
{
    char sessionKey[] = "111111111111111";
    uint16_t nonce;
    AesGcm128CipherKey cipherKey;
    uint16_t seq = 1;
    int32_t ret = TransProxyGenerateIv(nullptr, &nonce, &cipherKey, &seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyGenerateIv(sessionKey, nullptr, &cipherKey, &seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyGenerateIv(sessionKey, &nonce, nullptr, &seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyGenerateIv(sessionKey, &nonce, &cipherKey, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyGenerateIvTest002
 * @tc.desc: generate iv with valid params returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxyGenerateIvTest002, TestSize.Level1)
{
    char sessionKey[] = "111111111111111";
    uint16_t nonce;
    AesGcm128CipherKey cipherKey;
    uint16_t seq = 1;
    int32_t ret = TransProxyGenerateIv(sessionKey, &nonce, &cipherKey, &seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyGetD2dPriorityTest001
 * @tc.desc: get d2d priority returns correct priority for each business type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyGetD2dPriorityTest001, TestSize.Level1)
{
    BusinessType type = BUSINESS_TYPE_D2D_MESSAGE;
    int32_t ret = ClientTransProxyGetD2dPriority(type);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_MESSAGE, ret);
    type = BUSINESS_TYPE_D2D_VOICE;
    ret = ClientTransProxyGetD2dPriority(type);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_BYTES, ret);
    type = BUSINESS_TYPE_MESSAGE;
    ret = ClientTransProxyGetD2dPriority(type);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_BUTT, ret);
}

/*
 * @tc.name: ClientTransProxySubD2dNeaHeadPacketProcTest001
 * @tc.desc: sub d2d nea head packet proc with null head or null data returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxySubD2dNeaHeadPacketProcTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    D2dSliceHead head;
    char data[] = "test";
    uint32_t len = 1;
    int32_t ret = ClientTransProxySubD2dNeaHeadPacketProc(channelId, nullptr, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxySubD2dNeaHeadPacketProc(channelId, &head, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyNewHeadSliceProcTest001
 * @tc.desc: new head slice proc with null data or short len returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyNewHeadSliceProcTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    char data[] = "test";
    uint32_t len = 1;
    int32_t ret = ClientTransProxyNewHeadSliceProc(channelId, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyNewHeadSliceProc(channelId, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxySliceAndSendMessageTest001
 * @tc.desc: slice and send message with null data info or null info returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxySliceAndSendMessageTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    ProxyDataInfo dataInfo;
    int32_t ret = TransProxySliceAndSendMessage(nullptr, &info, TRANS_SESSION_MESSAGE, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxySliceAndSendMessage(&dataInfo, nullptr, TRANS_SESSION_MESSAGE, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxySliceAndSendMessageTest002
 * @tc.desc: slice and send message with non-new-head and zero out len returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxySliceAndSendMessageTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    ProxyDataInfo dataInfo = { };
    int32_t ret = TransProxySliceAndSendMessage(&dataInfo, &info, TRANS_SESSION_MESSAGE, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxySliceAndSendMessageTest003
 * @tc.desc: slice and send message with non-new-head and pack returns valid data returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxySliceAndSendMessageTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info;
    ProxyDataInfo dataInfo = {
        .inData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA)),
        .inLen = 5,
    };
    dataInfo.outLen = TEST_DATA_LEN;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ServerIpcSendMessage).WillRepeatedly(Return(SOFTBUS_OK));
    uint8_t *sliceData = static_cast<uint8_t *>(SoftBusCalloc(TEST_DATA_LEN));
    ASSERT_TRUE(sliceData != nullptr);
    EXPECT_CALL(managerMock, TransProxyPackD2DData).WillRepeatedly(Return(sliceData));
    int32_t ret = TransProxySliceAndSendMessage(&dataInfo, &info, TRANS_SESSION_MESSAGE, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxySliceAndSendMessageTest004
 * @tc.desc: slice and send message with new head and pack returns valid data returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, TransProxySliceAndSendMessageTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyChannelInfoDetail info = {
        .pagingSessionkey = "111111111111111",
        .pagingNonce = "11111111111",
        .isD2D = true,
        .isSupportNewHead = true,
    };
    ProxyDataInfo dataInfo = {
        .inData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA)),
        .inLen = 5,
    };
    dataInfo.outLen = TEST_DATA_LEN;
    NiceMock<TransClientProxyD2DInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, ServerIpcSendMessage).WillRepeatedly(Return(SOFTBUS_OK));
    uint8_t *sliceData = static_cast<uint8_t *>(SoftBusCalloc(TEST_DATA_LEN));
    ASSERT_TRUE(sliceData != nullptr);
    EXPECT_CALL(managerMock, TransProxyPackNewHeadD2DData).WillRepeatedly(Return(sliceData));
    int32_t ret = TransProxySliceAndSendMessage(&dataInfo, &info, TRANS_SESSION_MESSAGE, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyProcAndNotifyD2DDataTest001
 * @tc.desc: proc and notify d2d data with null data info or null iv source returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcAndNotifyD2DDataTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyDataInfo dataInfo;
    PacketD2DIvSource ivSource;
    int32_t ret = ClientTransProxyProcAndNotifyD2DData(
        channelId, nullptr, TRANS_SESSION_MESSAGE, BUSINESS_TYPE_D2D_MESSAGE, &ivSource);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyProcAndNotifyD2DData(
        channelId, &dataInfo, TRANS_SESSION_MESSAGE, BUSINESS_TYPE_D2D_MESSAGE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyProcAndNotifyD2DDataTest002
 * @tc.desc: proc and notify d2d data with valid params but channel not found returns channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyD2DTest, ClientTransProxyProcAndNotifyD2DDataTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    ProxyDataInfo dataInfo;
    PacketD2DIvSource ivSource;
    int32_t ret = ClientTransProxyProcAndNotifyD2DData(
        channelId, &dataInfo, TRANS_SESSION_MESSAGE, BUSINESS_TYPE_D2D_MESSAGE, &ivSource);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}
} // namespace OHOS
