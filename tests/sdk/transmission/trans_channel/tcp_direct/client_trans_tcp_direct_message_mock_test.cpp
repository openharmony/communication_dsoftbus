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
#define TEST_SESSION_KET "clientkey"

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
    (void)memcpy_s(channel->detail.sessionKey, TEST_SESSIONKEY_LEN, TEST_SESSION_KET, TEST_SESSIONKEY_LEN);
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
} // namespace OHOS