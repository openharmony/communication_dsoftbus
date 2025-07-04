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
#include "securec.h"

#include "client_trans_proxy_file_manager.h"
#include "client_trans_proxy_manager.c"
#include "client_trans_proxy_manager_mock.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "session.h"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_proxy_process_data.h"

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

int32_t TransOnQosEvent(
    int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    return SOFTBUS_OK;
}

static SoftBusList *InitSoftBusList(void)
{
    int32_t ret = 0;
    SoftBusList *list = reinterpret_cast<SoftBusList *>(SoftBusCalloc(sizeof(SoftBusList)));
    (void)memset_s(list, sizeof(SoftBusList), 0, sizeof(SoftBusList));

    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&list->lock, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&list->list);
    return list;
}

static IClientSessionCallBack g_clientSessionCb = {
    .OnSessionOpened = TransOnSessionOpened,
    .OnSessionClosed = TransOnSessionClosed,
    .OnSessionOpenFailed = TransOnSessionOpenFailed,
    .OnDataReceived = TransOnBytesReceived,
    .OnStreamReceived = TransOnOnStreamRecevied,
    .OnQosEvent = TransOnQosEvent,
};

class ClientTransProxyManagerMockTest : public testing::Test {
public:
    ClientTransProxyManagerMockTest() {}
    ~ClientTransProxyManagerMockTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransProxyManagerMockTest::SetUpTestCase(void)
{
    return;
}

void ClientTransProxyManagerMockTest::TearDownTestCase(void)
{
    return;
}

/**
 * @tc.name: ClientTransProxyInit001
 * @tc.desc: ClientTransProxyInit, use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyInit001, TestSize.Level1)
{
    int32_t ret = 0;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillOnce(Return(SOFTBUS_TIMOUT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return((SoftBusList *)NULL));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_TIMOUT));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxyOnChannelClosed001
 * @tc.desc: ClientTransProxyOnChannelClosed, use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyOnChannelClosed001, TestSize.Level1)
{
    IClientSessionCallBack temcb = g_clientSessionCb;
    temcb.OnSessionClosed = [] (int32_t channelId, int32_t channelType, ShutdownReason reason)
                                -> int32_t {return SOFTBUS_INVALID_PARAM;};
    int32_t channelId = 1;
    ShutdownReason reason = SHUTDOWN_REASON_UNKNOWN;
    int32_t ret = 0;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&temcb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyOnChannelClosed(channelId, reason);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxySendSessionAck001
 * @tc.desc: ClientTransProxySendSessionAck, use the nomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxySendSessionAck001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    int32_t Seq = 0;
    uint8_t *temSliceData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(uint8_t)));
    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, SoftBusHtoLl).WillRepeatedly(Return(Seq));
    EXPECT_CALL(ClientProxyManagerMock, ServerIpcSendMessage).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackData).WillRepeatedly(Return(temSliceData));
    ClientTransProxySendSessionAck(channelId, Seq);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxySendSessionAck002
 * @tc.desc: ClientTransProxySendSessionAck, enter the banormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxySendSessionAck002, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    int32_t Seq = 0;
    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE + 1;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, SoftBusHtoNl).WillRepeatedly(Return(Seq));
    EXPECT_CALL(ClientProxyManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_TIMOUT));
    ClientTransProxySendSessionAck(channelId, Seq);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxyProcSendMsgAck001
 * @tc.desc: ClientTransProxyProcSendMsgAck, enter the banormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyProcSendMsgAck001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    const char *data = "000";
    int32_t len = PROXY_ACK_SIZE;
    int32_t dataHeadSeq = 0;
    uint32_t dataSeq = 1;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    EXPECT_CALL(ClientProxyManagerMock, ClientGetSessionIdByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, ClientGetSessionCallbackAdapterById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, DeleteDataSeqInfoList).WillOnce(Return(SOFTBUS_TIMOUT));
    ret = ClientTransProxyProcSendMsgAck(channelId, data, len, dataHeadSeq, dataSeq);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);

    EXPECT_CALL(ClientProxyManagerMock, ClientGetSessionIdByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, ClientGetSessionCallbackAdapterById).WillOnce(Return(SOFTBUS_TIMOUT));
    ret = ClientTransProxyProcSendMsgAck(channelId, data, len, dataHeadSeq, dataSeq);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxySendBytesAck001
 * @tc.desc: ClientTransProxySendBytesAck, enter the normal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxySendBytesAck001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    int32_t Seq = 0;
    uint32_t dataSeq = 0;
    bool needAck = true;
    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, SoftBusHtoLl).WillOnce(Return(Seq));
    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackTlvBytes).WillOnce(Return(SOFTBUS_TIMOUT));
    ClientTransProxySendBytesAck(channelId, Seq, dataSeq, needAck);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxySendBytesAck002
 * @tc.desc: ClientTransProxySendBytesAck, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxySendBytesAck002, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    int32_t Seq = 0;
    uint32_t dataSeq = 1;
    bool needAck = true;
    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE + 1;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackTlvBytes).WillOnce(Return(SOFTBUS_TIMOUT));
    ClientTransProxySendBytesAck(channelId, Seq, dataSeq, needAck);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxyProcessSessionData001
 * @tc.desc: ClientTransProxyProcessSessionData, enter the normal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyProcessSessionData001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    PacketHead *dataHead = reinterpret_cast<PacketHead *>(SoftBusCalloc(sizeof(PacketHead)));
    dataHead->dataLen = OVERHEAD_LEN + 8;
    dataHead->flags = 12;
    const char *data = "000";

    EXPECT_CALL(ClientProxyManagerMock, TransProxyDecryptPacketData).WillOnce(Return(SOFTBUS_OK));
    ret = ClientTransProxyProcessSessionData(channelId, dataHead, data);
    EXPECT_EQ(SOFTBUS_OK, ret);

    (void)ClientTransProxyListDeinit();
    SoftBusFree(dataHead);
}

/**
 * @tc.name: ClientTransProxyProcessSessionData002
 * @tc.desc: ClientTransProxyProcessSessionData, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyProcessSessionData002, TestSize.Level1)
{
    int32_t ret = 0;
    IClientSessionCallBack temcb = g_clientSessionCb;
    temcb.OnDataReceived = [] (int32_t channelId, int32_t channelType,
            const void *data, uint32_t len, SessionPktType type) -> int32_t {return SOFTBUS_TIMOUT;};

    int32_t channelId = 1;
    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&temcb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    PacketHead *dataHead = (PacketHead *)SoftBusCalloc(sizeof(PacketHead));
    dataHead->dataLen = OVERHEAD_LEN + 8;
    dataHead->flags = 12;
    const char *data = "000";

    ret = ClientTransProxyProcessSessionData(channelId, dataHead, data);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    EXPECT_CALL(ClientProxyManagerMock, TransProxySessionDataLenCheck).WillOnce(Return(SOFTBUS_TIMOUT));
    ret = ClientTransProxyProcessSessionData(channelId, dataHead, data);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    (void)ClientTransProxyListDeinit();
    SoftBusFree(dataHead);
}

/**
 * @tc.name: ClientTransProxyProcData001
 * @tc.desc: ClientTransProxyProcData, enter the normal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyProcData001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DataHeadTlvPacketHead *dataHead = (DataHeadTlvPacketHead *)SoftBusCalloc(sizeof(DataHeadTlvPacketHead));
    dataHead->dataLen = OVERHEAD_LEN + 8;
    dataHead->flags = 12;
    const char *data = "000";

    ret = ClientTransProxyProcData(channelId, dataHead, data);
    EXPECT_EQ(SOFTBUS_OK, ret);

    (void)ClientTransProxyListDeinit();
    SoftBusFree(dataHead);
}

/**
 * @tc.name: ClientTransProxyProcData002
 * @tc.desc: ClientTransProxyProcData, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyProcData002, TestSize.Level1)
{
    int32_t ret = 0;
    IClientSessionCallBack temcb = g_clientSessionCb;
    temcb.OnDataReceived = [] (int32_t channelId, int32_t channelType,
        const void *data, uint32_t len, SessionPktType type) -> int32_t {return SOFTBUS_TIMOUT;};

    int32_t channelId = 1;
    ClientProxyChannelInfo *info =
        reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&temcb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DataHeadTlvPacketHead *dataHead = (DataHeadTlvPacketHead *)SoftBusCalloc(sizeof(DataHeadTlvPacketHead));
    dataHead->dataLen = OVERHEAD_LEN + 8;
    dataHead->flags = 12;
    const char *data = "000";

    ret = ClientTransProxyProcData(channelId, dataHead, data);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    EXPECT_CALL(ClientProxyManagerMock, TransProxySessionDataLenCheck).WillOnce(Return(SOFTBUS_TIMOUT));
    ret = ClientTransProxyProcData(channelId, dataHead, data);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    (void)ClientTransProxyListDeinit();
    SoftBusFree(dataHead);
}

/**
 * @tc.name: TransProxyAsyncPackAndSendData001
 * @tc.desc: TransProxyAsyncPackAndSendData, enter the normal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, TransProxyAsyncPackAndSendData001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    const void *data = SoftBusCalloc(sizeof(int32_t));
    uint32_t len = 4 * 1024;
    uint32_t dataSeq = 0;
    uint8_t *temSliceData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(uint8_t)));
    SessionPktType pktType = TRANS_SESSION_BYTES;

    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackTlvBytes).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackData).WillRepeatedly(Return(temSliceData));
    EXPECT_CALL(ClientProxyManagerMock, ServerIpcSendMessage).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyAsyncPackAndSendData(channelId, data, len, dataSeq, pktType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: TransProxyAsyncPackAndSendData002
 * @tc.desc: TransProxyAsyncPackAndSendData, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, TransProxyAsyncPackAndSendData002, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    const void *data = SoftBusCalloc(sizeof(int32_t));
    uint32_t len = 4 * 1024;
    uint32_t dataSeq = 0;
    uint8_t *temSliceData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(uint8_t)));
    SessionPktType pktType = TRANS_SESSION_BYTES;

    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransProxyAsyncPackAndSendData(channelId, NULL, len, dataSeq, pktType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyAsyncPackAndSendData(channelId, data, len, dataSeq, pktType);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, GetSupportTlvAndNeedAckById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransProxyAsyncPackAndSendData(channelId, data, len, dataSeq, pktType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(ClientProxyManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackTlvBytes).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackData).WillOnce(Return(temSliceData));
    EXPECT_CALL(ClientProxyManagerMock, ServerIpcSendMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransProxyAsyncPackAndSendData(channelId, data, len, dataSeq, pktType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    const void *newData = SoftBusCalloc(sizeof(int32_t));
    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackTlvBytes).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackData).WillOnce(Return((uint8_t *)NULL));
    ret = TransProxyAsyncPackAndSendData(channelId, newData, len, dataSeq, pktType);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: TransProxyChannelSendBytes001
 * @tc.desc: TransProxyChannelSendBytes, enter the normal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, TransProxyChannelSendBytes001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    const void *data = SoftBusCalloc(sizeof(int32_t));
    uint32_t len = 1;
    uint8_t *temSliceData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(uint8_t)));
    bool needAck = true;

    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.isEncrypted = true;
    detail.sequence = 1;
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, TransProxyPackData).WillOnce(Return(temSliceData));
    EXPECT_CALL(ClientProxyManagerMock, ServerIpcSendMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, ProcPendingPacket).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, GetSupportTlvAndNeedAckById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, AddPendingPacket).WillOnce(Return(SOFTBUS_OK));
    ret = TransProxyChannelSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(SOFTBUS_OK, ret);

    (void)ClientTransProxyListDeinit();
    (void)PendingDeinit(PENDING_TYPE_PROXY);
}

/**
 * @tc.name: TransProxyChannelSendBytes002
 * @tc.desc: TransProxyChannelSendBytes, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, TransProxyChannelSendBytes002, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    const void *data = SoftBusCalloc(sizeof(int32_t));
    uint32_t len = 1;
    bool needAck = true;

    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.isEncrypted = false;
    detail.sequence = 1;
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransProxyChannelSendBytes(channelId, NULL, len, needAck);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, ServerIpcSendMessage).WillOnce(Return(SOFTBUS_OK));
    ret = TransProxyChannelSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(SOFTBUS_OK, ret);

    (void)ClientTransProxyListDeinit();
    (void)PendingDeinit(PENDING_TYPE_PROXY);
}

/**
 * @tc.name: TransProxyChannelSendBytes003
 * @tc.desc: TransProxyChannelSendBytes, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, TransProxyChannelSendBytes003, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    const void *data = SoftBusCalloc(sizeof(int32_t));
    uint32_t len = 1;
    bool needAck = true;

    ClientProxyChannelInfo *info = reinterpret_cast<ClientProxyChannelInfo *>(SoftBusCalloc(sizeof(ClientProxyChannelInfo)));
    ProxyChannelInfoDetail detail = {0};
    detail.isEncrypted = true;
    detail.sequence = 1;
    detail.osType = OH_TYPE;
    info->channelId = channelId;
    info->detail = detail;
    info->node.next = NULL;
    info->node.prev = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyManagerMock, AddPendingPacket).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransProxyChannelSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(ClientProxyManagerMock, AddPendingPacket).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = TransProxyChannelSendBytes(channelId, data, len, needAck);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    (void)ClientTransProxyListDeinit();
    (void)PendingDeinit(PENDING_TYPE_PROXY);
}

/**
 * @tc.name: ClientTransProxyOnChannelBind001
 * @tc.desc: ClientTransProxyOnChannelBind, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyOnChannelBind001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    int32_t ChannelType = 2;

    IClientSessionCallBack temcb = g_clientSessionCb;
    temcb.OnChannelBind = [](int32_t channelId, int32_t channelType) -> int32_t {return SOFTBUS_INVALID_PARAM;};

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&temcb);

    ret = ClientTransProxyOnChannelBind(channelId, ChannelType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxyOnChannelBind002
 * @tc.desc: ClientTransProxyOnChannelBind, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyOnChannelBind002, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    int32_t ChannelType = 2;

    IClientSessionCallBack temcb = g_clientSessionCb;
    temcb.OnChannelBind = [](int32_t channelId, int32_t channelType) -> int32_t {return SOFTBUS_NOT_NEED_UPDATE;};

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&temcb);

    ret = ClientTransProxyOnChannelBind(channelId, ChannelType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    (void)ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxyOnChannelBind003
 * @tc.desc: ClientTransProxyOnChannelBind, enter the abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerMockTest, ClientTransProxyOnChannelBind003, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    int32_t ChannelType = 2;

    IClientSessionCallBack temcb = g_clientSessionCb;
    temcb.OnChannelBind = NULL;

    NiceMock<ClientTransProxyManagerInterfaceMock> ClientProxyManagerMock;
    SoftBusList *infoList = InitSoftBusList();
    SoftBusList *sliceList = InitSoftBusList();
    EXPECT_CALL(ClientProxyManagerMock, ClinetTransProxyFileManagerInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyManagerMock, CreateSoftBusList).WillOnce(Return(infoList)).WillOnce(Return(sliceList));
    ret = ClientTransProxyInit(&temcb);

    ret = ClientTransProxyOnChannelBind(channelId, ChannelType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    (void)ClientTransProxyListDeinit();
}
} // namespace OHOS