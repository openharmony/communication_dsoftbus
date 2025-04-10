/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "client_trans_tcp_direct_listener.c"
#include "client_trans_tcp_direct_manager.c"
#include "client_trans_tcp_direct_message.c"

#include "softbus_access_token_test.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_tcp_direct_tlv_mock.h"
#include "trans_tcp_process_data.h"
#include "trans_tcp_process_data.c"

#define TDC_TLV_ELEMENT 5
#define DATA_SIZE 4
#define PKG_HEAD_SIZE 32
#define TRANS_TEST_FD 1000
#define TRANS_TEST_CHANNEL_ID 1
#define TEST_DATA_LEN 100

static int32_t g_fd = socket(AF_INET, SOCK_STREAM, 0);

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class TransTcpDirectMockTest : public testing::Test {
public:
    TransTcpDirectMockTest()
    {}
    ~TransTcpDirectMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectMockTest::SetUpTestCase(void)
{
    SetAccessTokenPermission("dsoftbusTransTest");
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
}

void TransTcpDirectMockTest::TearDownTestCase(void)
{
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/**
 * @tc.name: BuildNeedAckTlvData001
 * @tc.desc: BuildNeedAckTlvData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, BuildNeedAckTlvData001, TestSize.Level1)
{
    int32_t bufferSize = 0;
    DataHead *data = reinterpret_cast<DataHead *>(SoftBusCalloc(sizeof(DataHead)));
    ASSERT_NE(data, nullptr);
    data->magicNum = MAGIC_NUMBER;
    data->tlvCount = TDC_TLV_ELEMENT;
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, TransAssembleTlvData).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = BuildNeedAckTlvData(data, true, 1, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    SoftBusFree(data);
}

/**
 * @tc.name: BuildNeedAckTlvData002
 * @tc.desc: BuildNeedAckTlvData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, BuildNeedAckTlvData002, TestSize.Level1)
{
    int32_t bufferSize = 0;
    DataHead *data = reinterpret_cast<DataHead *>(SoftBusCalloc(sizeof(DataHead)));
    ASSERT_NE(data, nullptr);
    data->magicNum = MAGIC_NUMBER;
    data->tlvCount = TDC_TLV_ELEMENT;
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, TransAssembleTlvData).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_MALLOC_ERR));
    int32_t ret = BuildNeedAckTlvData(data, true, 1, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);
    SoftBusFree(data);
}

/**
 * @tc.name: BuildNeedAckTlvData003
 * @tc.desc: BuildNeedAckTlvData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, BuildNeedAckTlvData003, TestSize.Level1)
{
    int32_t bufferSize = 0;
    DataHead *data = reinterpret_cast<DataHead *>(SoftBusCalloc(sizeof(DataHead)));
    ASSERT_NE(data, nullptr);
    data->magicNum = MAGIC_NUMBER;
    data->tlvCount = TDC_TLV_ELEMENT;
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, TransAssembleTlvData).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = BuildNeedAckTlvData(data, true, 1, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(data);
}

/**
 * @tc.name: BuildDataHead001
 * @tc.desc: BuildDataHead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, BuildDataHead001, TestSize.Level1)
{
    int32_t bufferSize = 0;
    DataHead *data = reinterpret_cast<DataHead *>(SoftBusCalloc(sizeof(DataHead)));
    ASSERT_NE(data, nullptr);
    data->magicNum = MAGIC_NUMBER;
    data->tlvCount = TDC_TLV_ELEMENT;
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, TransAssembleTlvData).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = BuildDataHead(data, 1, 0, PKG_HEAD_SIZE, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    EXPECT_CALL(tcpDirectMock, TransAssembleTlvData).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_MALLOC_ERR));
    ret = BuildDataHead(data, 1, 0, PKG_HEAD_SIZE, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);

    EXPECT_CALL(tcpDirectMock, TransAssembleTlvData).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_OK)).WillOnce(
        Return(SOFTBUS_MALLOC_ERR));
    ret = BuildDataHead(data, 1, 0, PKG_HEAD_SIZE, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);

    EXPECT_CALL(tcpDirectMock, TransAssembleTlvData).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_OK)).WillOnce(
        Return(SOFTBUS_OK));
    ret = BuildDataHead(data, 1, 0, PKG_HEAD_SIZE, &bufferSize);
    SoftBusFree(data);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcParseTlv001
 * @tc.desc: TransTdcParseTlv and TcpDataPacketHead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcParseTlv001, TestSize.Level1)
{
    TcpDataPacketHead data;
    data.magicNumber = MAGIC_NUMBER;
    data.seq = 1;
    data.flags = 0;
    data.dataLen = DATA_SIZE;
    PackTcpDataPacketHead(&data);
    uint32_t bufferSize = 0;
    int32_t ret = TransTdcParseTlv(TEST_DATA_LEN, nullptr, nullptr, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransTdcSetPendingPacket001
 * @tc.desc: TransTdcSetPendingPacket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcSetPendingPacket001, TestSize.Level1)
{
    const char *data = "test";
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, ClientGetSessionIdByChannelId).WillOnce(Return(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND));
    int32_t ret = TransTdcSetPendingPacket(1, data, DATA_SIZE, 1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/**
 * @tc.name: TransTdcSetPendingPacket002
 * @tc.desc: TransTdcSetPendingPacket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcSetPendingPacket002, TestSize.Level1)
{
    const char *data = "test";
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, ClientGetSessionIdByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMock, ClientGetSessionCallbackAdapterById).WillOnce(Return(
        SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND));
    int32_t ret = TransTdcSetPendingPacket(1, data, DATA_SIZE, 1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/**
 * @tc.name: TransTdcSetPendingPacket003
 * @tc.desc: TransTdcSetPendingPacket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcSetPendingPacket003, TestSize.Level1)
{
    const char *data = "test";
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, ClientGetSessionIdByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMock, ClientGetSessionCallbackAdapterById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMock, DeleteDataSeqInfoList).WillOnce(Return(SOFTBUS_TRANS_DATA_SEQ_INFO_NOT_FOUND));
    int32_t ret = TransTdcSetPendingPacket(1, data, DATA_SIZE, 1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_DATA_SEQ_INFO_NOT_FOUND);
}

/**
 * @tc.name: TransTcpSetTos001
 * @tc.desc: TransTcpSetTos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTcpSetTos001, TestSize.Level1)
{
    TcpDirectChannelInfo channel;
    channel.channelId = 1;
    int32_t ret = TransTcpSetTos(nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, ClientGetSessionNameByChannelId).WillOnce(Return(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND));
    ret = TransTcpSetTos(&channel, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_NAME_NO_EXIST);

    EXPECT_CALL(tcpDirectMock, ClientGetSessionNameByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMock, SetIpTos).WillOnce(Return(SOFTBUS_TCP_SOCKET_ERR));
    ret = TransTcpSetTos(&channel, 0);
    EXPECT_EQ(ret, SOFTBUS_TCP_SOCKET_ERR);

    EXPECT_CALL(tcpDirectMock, ClientGetSessionNameByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectMock, SetIpTos).WillOnce(Return(SOFTBUS_OK));
    ret = TransTcpSetTos(&channel, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransSetTosSendData001
 * @tc.desc: TransSetTosSendData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransSetTosSendData001, TestSize.Level1)
{
    int32_t newPkgHeadSize = PKG_HEAD_SIZE;
    const char *buf = "test";
    uint32_t outLen = DATA_SIZE;
    int32_t ret = TransSetTosSendData(nullptr, const_cast<char *>(buf), newPkgHeadSize, 0, outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransTdcSendBytes001
 * @tc.desc: TransTdcSendBytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcSendBytes001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = DATA_SIZE;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);

    info->channelId = channelId;
    info->detail.needRelease = true;
    info->detail.sequence = 2;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, AddPendingPacket).WillOnce(Return(SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_PENDING));
    int32_t ret = TransTdcSendBytes(channelId, data, len, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_PENDING);

    EXPECT_CALL(tcpDirectMock, AddPendingPacket).WillOnce(Return(SOFTBUS_OK));
    ret = TransTdcSendBytes(channelId, data, len, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);
    ListDelete(&info->node);
    SoftBusFree(info);
}

/**
 * @tc.name: TransTdcSendBytes002
 * @tc.desc: TransTdcSendBytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcSendBytes002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = DATA_SIZE;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);

    info->channelId = channelId;
    info->detail.needRelease = false;
    info->detail.sequence = 2;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, AddPendingPacket).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransTdcSendBytes(channelId, data, len, true);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ListDelete(&info->node);
    SoftBusFree(info);
}

/**
 * @tc.name: TransTdcAsyncSendBytes001
 * @tc.desc: TransTdcAsyncSendBytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcAsyncSendBytes001, TestSize.Level1)
{
    int32_t ret = TransTdcAsyncSendBytes(1, nullptr, 1, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const char *data = "test";
    ret = TransTdcAsyncSendBytes(1, data, 0, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcAsyncSendBytes(1, nullptr, 0, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);

    info->channelId = 1;
    info->detail.needRelease = true;
    info->detail.sequence = 2;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    ret = TransTdcAsyncSendBytes(1, data, DATA_SIZE, 1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);
    ListDelete(&info->node);
    SoftBusFree(info);
}

/**
 * @tc.name: TransTdcSendAck001
 * @tc.desc: TransTdcSendAck
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcSendAck001, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);

    info->channelId = channelId;
    info->detail.needRelease = true;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    int32_t ret = TransTdcSendAck(channelId, 1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);
    ListDelete(&info->node);
    SoftBusFree(info);
}

/**
 * @tc.name: TransTdcNeedSendAck002
 * @tc.desc: TransTdcNeedSendAck
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcNeedSendAck001, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);

    info->channelId = channelId;
    info->detail.needRelease = false;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransTdcNeedSendAck(info, 1, 0, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
}

/**
 * @tc.name: TransTdcProcessBytesDataByFlag001
 * @tc.desc: TransTdcProcessBytesDataByFlag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcProcessBytesDataByFlag001, TestSize.Level1)
{
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);
    info->detail.needRelease = false;
    info->channelId = TRANS_TEST_CHANNEL_ID;
    info->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->detail.fd = TRANS_TEST_FD;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TcpDataTlvPacketHead *head = reinterpret_cast<TcpDataTlvPacketHead *>(SoftBusCalloc(sizeof(TcpDataTlvPacketHead)));
    ASSERT_NE(head, nullptr);
    head->flags = FLAG_BYTES;
    const char *plain = "plain";
    head->seq = 1;
    head->dataSeq = 0;
    head->needAck = false;
    head->flags = FLAG_ACK;
    int32_t ret = TransTdcProcessBytesDataByFlag(head, info, const_cast<char *>(plain), (uint32_t)strlen(plain));
    EXPECT_EQ(ret, SOFTBUS_OK);

    head->flags = FILE_FIRST_FRAME;
    ret = TransTdcProcessBytesDataByFlag(head, info, const_cast<char *>(plain), (uint32_t)strlen(plain));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ListDelete(&info->node);
    SoftBusFree(info);
    SoftBusFree(head);
}

/**
 * @tc.name: TransTdcProcessTlvData001
 * @tc.desc: TransTdcProcessTlvData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMockTest, TransTdcProcessTlvData001, TestSize.Level1)
{
    TransDataListInit();
    TcpDirectChannelInfo channel;
    channel.channelId = 1;
    TcpDataTlvPacketHead *head = reinterpret_cast<TcpDataTlvPacketHead *>(SoftBusCalloc(sizeof(TcpDataTlvPacketHead)));
    ASSERT_NE(head, nullptr);
    head->flags = FLAG_BYTES;
    int32_t ret = TransTdcProcessTlvData(channel.channelId, head, PKG_HEAD_SIZE);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    SoftBusFree(head);
    TransDataListDeinit();
}
} // namespace OHOS