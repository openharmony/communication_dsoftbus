/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <sys/socket.h>

#include "client_trans_tcp_direct_message.c"

#include "client_trans_tcp_direct_message_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_thread.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_LEN 5
#define TEST_SESSIONKEY_LEN 32
#define TEST_SESSION_KEY "clientkey1234567899876543211212"
#define TEST_DATA_LEN_2M (2 * 1024 * 1024)

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class ClientTransTcpDirectMsgMockTest : public testing::Test {
public:
    ClientTransTcpDirectMsgMockTest()
    {}
    ~ClientTransTcpDirectMsgMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void ClientTransTcpDirectMsgMockTest::SetUpTestCase(void)
{
}

void ClientTransTcpDirectMsgMockTest::TearDownTestCase(void)
{
}

/*
 * @tc.name: TransTdcProcessPostDataTest001
 * @tc.desc: test TransTdcProcessPostData
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcProcessPostDataTest001, TestSize.Level1)
{
    TcpDirectChannelInfo *channel = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    char *buf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(buf != nullptr);
    channel->channelId = 1;
    (void)memcpy_s(channel->detail.sessionKey, TEST_SESSIONKEY_LEN, TEST_SESSION_KEY, TEST_SESSIONKEY_LEN);
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = 1;
    channel->detail.sequence = 1;
    int32_t ret = SoftBusMutexInit(&(channel->detail.fdLock), NULL);
    ASSERT_EQ(ret, SOFTBUS_OK);
    const char *data = "data";
    uint32_t len = TEST_LEN;
    int32_t flags = FLAG_ACK;
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, GetSupportTlvAndNeedAckById).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcessPostData(channel, data, len, flags);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    EXPECT_CALL(tcpDirectMsgMock, GetSupportTlvAndNeedAckById).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcessPostData(channel, data, len, flags);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);

    EXPECT_CALL(tcpDirectMsgMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackAllData).WillOnce(Return(buf));
    EXPECT_CALL(tcpDirectMsgMock, ClientGetSessionNameByChannelId).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcessPostData(channel, data, len, flags);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_NAME_NO_EXIST);

    char *bufTest = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(bufTest != nullptr);
    channel->detail.fdProtocol = LNN_PROTOCOL_HTP;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackAllData).WillOnce(Return(bufTest));
    EXPECT_CALL(tcpDirectMsgMock, ClientGetSessionNameByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSendData).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcessPostData(channel, data, len, flags);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    char *testBuf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(testBuf != nullptr);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackAllData).WillOnce(Return(testBuf));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSendData).WillOnce(Return(SOFTBUS_OK));
    ret = TransTdcProcessPostData(channel, data, len, flags);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcSendBytesTest001
 * @tc.desc: test TransTdcSendBytes
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcSendBytesTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t len = TEST_LEN;
    bool needAck = true;
    TcpDirectChannelInfo channel = {
        .detail.sequence = 1,
        .detail.needRelease =1,
        .detail.fdProtocol = LNN_PROTOCOL_HTP,
    };
    int32_t ret = SoftBusMutexInit(&(channel.detail.fdLock), NULL);
    ASSERT_EQ(ret, SOFTBUS_OK);
    char *buf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(buf != nullptr);

    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById).WillOnce(Return(nullptr));
    ret = TransTdcSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_GET_INFO_FAILED);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillOnce(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    EXPECT_CALL(tcpDirectMsgMock, AddPendingPacket).WillOnce(Return(SOFTBUS_NO_INIT));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    ret = TransTdcSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillOnce(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    EXPECT_CALL(tcpDirectMsgMock, AddPendingPacket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    ret = TransTdcSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);

    channel.detail.needRelease = false;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    EXPECT_CALL(tcpDirectMsgMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackAllData).WillOnce(Return(buf));
    EXPECT_CALL(tcpDirectMsgMock, ClientGetSessionNameByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSendData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, ProcPendingPacket).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransTdcSendBytesTest002
 * @tc.desc: test TransTdcSendBytes
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcSendBytesTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t len = TEST_LEN;
    bool needAck = false;
    TcpDirectChannelInfo channel = {
        .detail.sequence = 1,
        .detail.needRelease =false,
        .detail.fdProtocol = LNN_PROTOCOL_HTP,
    };
    int32_t ret = SoftBusMutexInit(&(channel.detail.fdLock), NULL);
    ASSERT_EQ(ret, SOFTBUS_OK);
    char *buf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(buf != nullptr);
    char *testBuf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(testBuf != nullptr);

    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    EXPECT_CALL(tcpDirectMsgMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackAllData).WillOnce(Return(buf));
    EXPECT_CALL(tcpDirectMsgMock, ClientGetSessionNameByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSendData).WillOnce(Return(SOFTBUS_NO_INIT));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    ret = TransTdcSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackAllData).WillOnce(Return(testBuf));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSendData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    ret = TransTdcSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcNeedAckProcessPostData001
 * @tc.desc: test TransTdcNeedAckProcessPostData
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcNeedAckProcessPostData001, TestSize.Level1)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    int32_t ret = SoftBusMutexInit(&(channel.detail.fdLock), NULL);
    ASSERT_EQ(ret, SOFTBUS_OK);
    const char *data = "test";
    uint32_t len = TEST_LEN;
    int32_t flags = FLAG_ACK;
    uint32_t dataSeq = 1;
    char *buf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(buf != nullptr);

    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, BuildDataHead).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcNeedAckProcessPostData(&channel, data, len, flags, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    flags = FLAG_BYTES;
    EXPECT_CALL(tcpDirectMsgMock, BuildDataHead).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, BuildNeedAckTlvData).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcNeedAckProcessPostData(&channel, data, len, flags, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    EXPECT_CALL(tcpDirectMsgMock, BuildNeedAckTlvData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackTlvData).WillOnce(Return(nullptr));
    EXPECT_CALL(tcpDirectMsgMock, ReleaseDataHeadResource).Times(1);
    ret = TransTdcNeedAckProcessPostData(&channel, data, len, flags, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PACK_TLV_DATA_FAILED);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackTlvData).WillOnce(Return(buf));
    EXPECT_CALL(tcpDirectMsgMock, ReleaseDataHeadResource).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcEncryptWithSeq).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcNeedAckProcessPostData(&channel, data, len, flags, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    char *testBuf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(testBuf != nullptr);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackTlvData).WillOnce(Return(testBuf));
    EXPECT_CALL(tcpDirectMsgMock, ReleaseDataHeadResource).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcEncryptWithSeq).WillOnce(Return(SOFTBUS_OK));
    ret = TransTdcNeedAckProcessPostData(&channel, data, len, flags, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
}

/*
 * @tc.name: TransTdcNeedAckProcessPostData002
 * @tc.desc: test TransTdcNeedAckProcessPostData
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcNeedAckProcessPostData002, TestSize.Level1)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    channel.detail.fdProtocol = LNN_PROTOCOL_HTP;
    int32_t ret = SoftBusMutexInit(&(channel.detail.fdLock), NULL);
    ASSERT_EQ(ret, SOFTBUS_OK);
    const char *data = "test";
    uint32_t len = TEST_LEN;
    int32_t flags = FLAG_ACK;
    uint32_t dataSeq = 1;
    char *buf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(buf != nullptr);
    EncrptyInfo enInfo = {0};
    uint32_t dataLen = TEST_LEN + OVERHEAD_LEN;
    enInfo.outLen = &dataLen;

    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, BuildDataHead).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, BuildNeedAckTlvData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackTlvData).WillOnce(Return(buf));
    EXPECT_CALL(tcpDirectMsgMock, ReleaseDataHeadResource).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcEncryptWithSeq)
        .WillRepeatedly(DoAll(SetArgPointee<2>(enInfo), Return(SOFTBUS_OK)));
    ret = TransTdcNeedAckProcessPostData(&channel, data, len, flags, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
}

/*
 * @tc.name: TransTdcAsyncSendBytes001
 * @tc.desc: test TransTdcAsyncSendBytes
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcAsyncSendBytes001, TestSize.Level1)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    channel.detail.fdProtocol = LNN_PROTOCOL_HTP;
    channel.detail.needRelease = true;
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t len = 0;
    uint32_t dataSeq = 1;
    int32_t ret = TransTdcAsyncSendBytes(channelId, nullptr, len, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcAsyncSendBytes(channelId, data, len, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    len = TEST_LEN;
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById).WillOnce(Return(nullptr));
    ret = TransTdcAsyncSendBytes(channelId, data, len, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    ret = TransTdcAsyncSendBytes(channelId, data, len, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);

    channel.detail.needRelease = false;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, BuildDataHead).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcAsyncSendBytes(channelId, data, len, dataSeq);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransTdcSendMessage001
 * @tc.desc: test TransTdcSendMessage
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcSendMessage001, TestSize.Level1)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    channel.detail.fdProtocol = LNN_PROTOCOL_HTP;
    channel.detail.needRelease = true;
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t len = 0;
    int32_t ret = TransTdcSendMessage(channelId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    len = TEST_LEN;
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById).WillOnce(Return(nullptr));
    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    EXPECT_CALL(tcpDirectMsgMock, AddPendingPacket).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    EXPECT_CALL(tcpDirectMsgMock, AddPendingPacket).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);

    channel.detail.needRelease = false;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channel), Return(&channel)));
    EXPECT_CALL(tcpDirectMsgMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, DelPendingPacketbyChannelId).Times(1);
    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransTdcSendMessage002
 * @tc.desc: test TransTdcSendMessage
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcSendMessage002, TestSize.Level1)
{
    TcpDirectChannelInfo *channel = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    channel->detail.fdProtocol = LNN_PROTOCOL_HTP;
    channel->detail.needRelease = false;
    channel->channelId = 1;
    (void)memcpy_s(channel->detail.sessionKey, TEST_SESSIONKEY_LEN, TEST_SESSION_KEY, TEST_SESSIONKEY_LEN);
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = 1;
    channel->detail.sequence = 1;
    int32_t ret = SoftBusMutexInit(&(channel->detail.fdLock), NULL);
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t len = TEST_LEN;
    char *buf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(buf != nullptr);

    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*channel), Return(channel)));
    EXPECT_CALL(tcpDirectMsgMock, AddPendingPacket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackAllData).WillOnce(Return(buf));
    EXPECT_CALL(tcpDirectMsgMock, ClientGetSessionNameByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSendData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, ProcPendingPacket).WillOnce(Return(SOFTBUS_OK));
    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcSendAck001
 * @tc.desc: test TransTdcSendMessage
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcSendAck001, TestSize.Level1)
{
    TcpDirectChannelInfo *channel = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    channel->detail.fdProtocol = LNN_PROTOCOL_HTP;
    channel->detail.needRelease = true;
    channel->channelId = 1;
    (void)memcpy_s(channel->detail.sessionKey, TEST_SESSIONKEY_LEN, TEST_SESSION_KEY, TEST_SESSIONKEY_LEN);
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = 1;
    channel->detail.sequence = 1;
    int32_t ret = SoftBusMutexInit(&(channel->detail.fdLock), NULL);
    int32_t channelId = 1;
    int32_t seq = 1;
    char *buf = (char *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(buf != nullptr);

    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById).WillOnce(Return(nullptr));
    ret = TransTdcSendAck(channelId, seq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_GET_INFO_FAILED);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*channel), Return(channel)));
    ret = TransTdcSendAck(channelId, seq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);

    channel->detail.needRelease = false;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*channel), Return(channel)));
    EXPECT_CALL(tcpDirectMsgMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcPackAllData).WillOnce(Return(buf));
    EXPECT_CALL(tcpDirectMsgMock, ClientGetSessionNameByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSendData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransUpdateFdState).Times(1);
    ret = TransTdcSendAck(channelId, seq);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcNeedSendAck001
 * @tc.desc: test TransTdcNeedSendAck
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcNeedSendAck001, TestSize.Level1)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    int32_t seq = 1;
    uint32_t dataSeq = 1;
    bool needAck = false;
    int32_t ret = TransTdcNeedSendAck(nullptr, seq, dataSeq, needAck);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcNeedSendAck(&channel, seq, dataSeq, needAck);
    EXPECT_EQ(ret, SOFTBUS_OK);

    needAck = true;
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, BuildDataHead).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcNeedSendAck(&channel, seq, dataSeq, needAck);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransGetDataBufNodeById001
 * @tc.desc: test TransGetDataBufNodeById
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransGetDataBufNodeById001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    DataBuf *buf = TransGetDataBufNodeById(channelId);
    EXPECT_EQ(buf, nullptr);
    int32_t ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    buf = TransGetDataBufNodeById(channelId);
    EXPECT_NE(buf, nullptr);
    channelId = 0;
    buf = TransGetDataBufNodeById(channelId);
    EXPECT_EQ(buf, nullptr);
    channelId = 1;
    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
}

/*
 * @tc.name: TransTdcProcessBytesDataByFlag001
 * @tc.desc: test TransTdcProcessBytesDataByFlag
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcProcessBytesDataByFlag001, TestSize.Level1)
{
    TcpDataTlvPacketHead pktHead = {
        .flags = FLAG_BYTES,
        .seq = 1,
        .dataSeq = 1,
        .needAck = false,
    };
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    char plain[] = "test";
    uint32_t plainLen = TEST_LEN;
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, ClientTransTdcOnDataReceived).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransTdcProcessBytesDataByFlag(&pktHead, &channel, plain, plainLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    pktHead.flags = FLAG_ACK;
    ret = TransTdcProcessBytesDataByFlag(&pktHead, &channel, plain, plainLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    pktHead.flags = FLAG_MESSAGE;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoIncFdRefById).WillOnce(Return(nullptr));
    ret = TransTdcProcessBytesDataByFlag(&pktHead, &channel, plain, plainLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    pktHead.flags = FILE_ONLYONE_FRAME;
    ret = TransTdcProcessBytesDataByFlag(&pktHead, &channel, plain, plainLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransTdcProcessTlvData001
 * @tc.desc: test TransTdcProcessTlvData
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcProcessTlvData001, TestSize.Level1)
{
    TcpDataTlvPacketHead pktHead = {
        .flags = FILE_ONLYONE_FRAME,
        .seq = 1,
        .dataSeq = 1,
        .needAck = false,
        .dataLen = TEST_SESSIONKEY_LEN,
    };
    int32_t channelId = 1;
    int32_t testChannelId = 0;
    int32_t fd = 1;
    int32_t pkgHeadSize = 1;
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoById).WillOnce(Return(SOFTBUS_NO_INIT));
    int32_t ret = TransTdcProcessTlvData(channelId, &pktHead, pkgHeadSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransTdcProcessTlvData(channelId, &pktHead, pkgHeadSize);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcProcessTlvData(testChannelId, &pktHead, pkgHeadSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcDecrypt).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcessTlvData(channelId, &pktHead, pkgHeadSize);
    EXPECT_EQ(ret, SOFTBUS_DECRYPT_ERR);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcDecrypt).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, MoveNode).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcessTlvData(channelId, &pktHead, pkgHeadSize);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_CALL(tcpDirectMsgMock, MoveNode).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransTdcProcessTlvData(channelId, &pktHead, pkgHeadSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
}

/*
 * @tc.name: TransTdcProcessData001
 * @tc.desc: test TransTdcProcessData
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcProcessData001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t testChannelId = 0;
    int32_t fd = 1;
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoById).WillOnce(Return(SOFTBUS_NO_INIT));
    int32_t ret = TransTdcProcessData(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransTdcProcessData(channelId);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcProcessData(testChannelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
    ret = TransTdcProcessData(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
}

/*
 * @tc.name: DfxReceiveRateStatistic001
 * @tc.desc: test DfxReceiveRateStatistic
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, DfxReceiveRateStatistic001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t dataLen = TEST_LEN;
    TcpDirectChannelInfo channel = {
        .timestamp = 1,
    };
    EXPECT_NO_FATAL_FAILURE(DfxReceiveRateStatistic(channelId, dataLen));
    dataLen = TEST_DATA_LEN_2M;
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoById).WillOnce(Return(SOFTBUS_NO_INIT));
    EXPECT_NO_FATAL_FAILURE(DfxReceiveRateStatistic(channelId, dataLen));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channel), Return(SOFTBUS_OK)));
    EXPECT_CALL(tcpDirectMsgMock, SoftBusGetTimeMs).WillOnce(Return(0));
    EXPECT_NO_FATAL_FAILURE(DfxReceiveRateStatistic(channelId, dataLen));
    EXPECT_CALL(tcpDirectMsgMock, SoftBusGetTimeMs).WillOnce(Return(channel.timestamp + 1));
    EXPECT_NO_FATAL_FAILURE(DfxReceiveRateStatistic(channelId, dataLen));
}

/*
 * @tc.name: TransTdcProcAllTlvData001
 * @tc.desc: test TransTdcProcAllTlvData
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcProcAllTlvData001, TestSize.Level1)
{
    int32_t channelId = 1;
    bool isMinTp = false;
    int32_t fd = 1;
    int32_t testChannelId = 0;
    int32_t ret = TransTdcProcAllTlvData(channelId, isMinTp);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSetTimestamp).Times(1);
    ret = TransTdcProcAllTlvData(testChannelId, isMinTp);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSetTimestamp).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcUnPackAllTlvData).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcAllTlvData(channelId, isMinTp);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSetTimestamp).Times(1);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcUnPackAllTlvData)
        .WillRepeatedly(DoAll(SetArgPointee<4>(true), Return(SOFTBUS_OK)));
    ret = TransTdcProcAllTlvData(channelId, isMinTp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcSetTimestamp).Times(2);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcUnPackAllTlvData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoById).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcAllTlvData(channelId, isMinTp);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    isMinTp = true;
    ret = TransTdcProcAllTlvData(channelId, isMinTp);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
}

/*
 * @tc.name: TransTdcProcAllData001
 * @tc.desc: test TransTdcProcAllData
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransTcpDirectMsgMockTest, TransTdcProcAllData001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    int32_t testChannelId = 0;
    int32_t ret = TransTdcProcAllData(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectMsgInterfaceMock> tcpDirectMsgMock;
    ret = TransTdcProcAllData(testChannelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcUnPackAllData).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcAllData(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcUnPackAllData)
        .WillRepeatedly(DoAll(SetArgPointee<2>(true), Return(SOFTBUS_OK)));
    ret = TransTdcProcAllData(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(tcpDirectMsgMock, TransTdcUnPackAllData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMsgMock, TransTdcGetInfoById).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    ret = TransTdcProcAllData(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
}
} // namespace OHOS