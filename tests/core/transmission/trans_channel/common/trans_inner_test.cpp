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

#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_inner.h"
#include "trans_inner.c"
#include "trans_inner_test_mock.h"


using namespace testing;
using namespace testing::ext;

const char *PKG_NAME = "ohos.trans_inner_test";
const char *NETWORK_ID = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *SESSION_KEY = "test_session_key";

#define TRANS_TEST_CHANNEL_ID 2048
#define TRANS_TEST_FD 100
#define TRANS_TEST_IVALID_LEN 4194305
#define TEST_DATA_LEN 40
#define TEST_SEND_DATA_LEN 21
#define TEST_SLICE_NUM 10

namespace OHOS {
class TransInnerTest : public testing::Test {
public:
    TransInnerTest()
    {}
    ~TransInnerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransInnerTest::SetUpTestCase(void)
{
}

void TransInnerTest::TearDownTestCase(void)
{
}

static int32_t TestInnerMessageHandler(int32_t sessionId, const void *data, uint32_t dataLen)
{
    (void)data;
    (void)dataLen;
    TRANS_LOGE(TRANS_CTRL, "inner session channelId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

/**
 * @tc.name: TransInnerAddDataBufNodeTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_InnerListener is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerAddDataBufNodeTest001, TestSize.Level1)
{
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListInit();
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: InnerAddSessionTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, InnerAddSessionTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_PROXY,
        .supportTlv = false,
    };
    int32_t ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = InnerAddSession(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    innerInfo.listener = &Innerlistener;
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    innerInfo.channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    InnerListDeinit();
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, ClientIpcOnChannelClosed).WillOnce(Return(SOFTBUS_OK));
    DirectOnChannelClose(TRANS_TEST_CHANNEL_ID, PKG_NAME);
}

/**
 * @tc.name: GetSessionInfoByFdTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByFdTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByFd(TRANS_TEST_FD, &info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = GetSessionInfoByFd(TRANS_TEST_FD, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, &info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    InnerListInit();
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetSessionInfoByFd(TRANS_TEST_FD + 1, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = GetSessionInfoByFd(TRANS_TEST_FD, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID + 1, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, ClientIpcOnChannelClosed).WillRepeatedly(Return(SOFTBUS_OK));
    TransCloseInnerSessionByNetworkId(NETWORK_ID);
    InnerListDeinit();
    TransCloseInnerSessionByNetworkId(NETWORK_ID);
}

/**
 * @tc.name: GetSessionInfoByChanIdTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByChanIdTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_PROXY,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    TransInnerSessionInfo info = {};
    InnerListInit();
    int32_t ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyGetAppInfoByChanId).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, &info);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    EXPECT_CALL(TransInnerMock, TransProxyGetAppInfoByChanId).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID + 1, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    InnerListDeinit();
}

/**
 * @tc.name: TransInnerGetTdcDataBufByIdTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerGetTdcDataBufByIdTest001, TestSize.Level1)
{
    size_t len = 0;
    int32_t ret = TransInnerGetTdcDataBufById(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransInnerGetTdcDataBufById(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, &len);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransInnerGetTdcDataBufById(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, &len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    ret = TransInnerGetTdcDataBufById(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, &len);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    InnerListDeinit();
}

/**
 * @tc.name: TransInnerUpdateTdcDataBufWInfoTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerUpdateTdcDataBufWInfoTest001, TestSize.Level1)
{
    int32_t recvLen = TRANS_TEST_IVALID_LEN;
    char *recvBuf = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(recvBuf);
    int32_t ret = TransInnerUpdateTdcDataBufWInfo(TRANS_TEST_CHANNEL_ID, nullptr, recvLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransInnerUpdateTdcDataBufWInfo(TRANS_TEST_CHANNEL_ID, recvBuf, recvLen);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransInnerUpdateTdcDataBufWInfo(TRANS_TEST_CHANNEL_ID, recvBuf, recvLen);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    recvLen = 0;
    ret = TransInnerUpdateTdcDataBufWInfo(TRANS_TEST_CHANNEL_ID, recvBuf, recvLen);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    DataBuf *testdata = TransGetInnerDataBufNodeById(TRANS_TEST_CHANNEL_ID);
    ASSERT_TRUE(testdata);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    DataBuf *testdataLen = TransGetInnerDataBufNodeById(TRANS_TEST_CHANNEL_ID);
    ASSERT_FALSE(testdataLen);
    ret = TransInnerUpdateTdcDataBufWInfo(TRANS_TEST_CHANNEL_ID, recvBuf, recvLen);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    InnerListDeinit();
    SoftBusFree(recvBuf);
}

/**
 * @tc.name: TransTdcProcessInnerTlvDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerTlvDataTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    TcpDataTlvPacketHead pktHead { .dataLen = 1 };
    uint32_t newPktHeadSize = 0;
    info.listener.func = nullptr;
    int32_t ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransTdcProcessInnerTlvData(nullptr, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransTdcProcessInnerTlvData(&info, nullptr, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    InnerListInit();
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    pktHead.dataLen = TEST_DATA_LEN;
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcDecrypt).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    EXPECT_CALL(TransInnerMock, TransTdcDecrypt).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, MoveNode).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, MoveNode).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: TransInnerTdcProcAllTlvDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllTlvDataTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    int32_t ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransInnerTdcProcAllTlvData(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    InnerListInit();
    ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcUnPackAllTlvData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransTdcUnPackAllTlvData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: TransTdcProcessInnerDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerDataTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    info.listener.func = nullptr;
    int32_t ret = TransTdcProcessInnerData(&info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransTdcProcessInnerData(nullptr);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    ret = TransTdcProcessInnerData(&info);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    InnerListInit();
    ret = TransTdcProcessInnerData(&info);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransTdcProcessInnerData(&info);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: TransInnerTdcProcAllDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllDataTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    int32_t ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransInnerTdcProcAllData(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    InnerListInit();
    ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcUnPackAllData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransTdcUnPackAllData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: TdcDataReceivedTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcDataReceivedTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_PROXY,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    DirectChannelCloseSocket(-1);
    DirectChannelCloseSocket(TRANS_TEST_FD);
    InnerListInit();
    int32_t ret = TdcDataReceived(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TdcDataReceived(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcRecvFirstData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TdcDataReceived(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransTdcRecvFirstData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TdcDataReceived(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    EXPECT_CALL(TransInnerMock, TransLaneMgrDelLane).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransDelTcpChannelInfoByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, DelTrigger).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, SoftBusSocketShutDown).WillOnce(Return(SOFTBUS_ADAPTER_OK));
    EXPECT_CALL(TransInnerMock, SoftBusSocketClose).WillOnce(Return(SOFTBUS_ADAPTER_OK));
    DirectChannelCloseSocket(TRANS_TEST_FD);
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: DirectChannelOnDataEventTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, DirectChannelOnDataEventTest001, TestSize.Level1)
{
    int32_t event = SOFTBUS_SOCKET_OUT;
    ListenerModule module = AUTH_RAW_P2P_CLIENT;
    int32_t ret = DirectChannelOnDataEvent(module, event, TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_OK, ret);
    event = SOFTBUS_SOCKET_IN;
    ret = DirectChannelOnDataEvent(module, event, TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: DirectChannelCreateListenerTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, DirectChannelCreateListenerTest001, TestSize.Level1)
{
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, CreateListenerModule).WillRepeatedly(Return(AUTH_RAW_P2P_CLIENT));
    EXPECT_CALL(TransInnerMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, AddTrigger).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = DirectChannelCreateListener(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DirectChannelCreateListener(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TdcSendDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.recvBuf、testRecvBuf、 and testRecvBufTest will free in TdcSendData return failed:
 */
HWTEST_F(TransInnerTest, TdcSendDataTest001, TestSize.Level1)
{
    char *recvBuf = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(recvBuf);
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    int32_t ret = TdcSendData(TRANS_TEST_CHANNEL_ID, nullptr, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), DATA_BUF_MAX + 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(nullptr));
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(recvBuf));
    EXPECT_CALL(TransInnerMock, SetIpTos).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    char *testRecvBuf = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(testRecvBuf);
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(testRecvBuf));
    EXPECT_CALL(TransInnerMock, SetIpTos).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransTdcSendData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    char *testRecvBufTest = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(testRecvBufTest);
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(testRecvBufTest));
    EXPECT_CALL(TransInnerMock, TransTdcSendData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: ClientTransInnerProxyProcDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransInnerProxyProcDataTest001, TestSize.Level1)
{
    DataHeadTlvPacketHead dataHead = {0};
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    int32_t ret = ClientTransInnerProxyProcData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyProcData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransInnerProxyProcData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: ClientTransProxyInnerNoSubPacketTlvProcTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxyInnerNoSubPacketTlvProcTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyParseTlv).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransProxyInnerNoSubPacketTlvProc(TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransProxyParseTlv).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransProxyNoSubPacketTlvProc).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyInnerNoSubPacketTlvProc(TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransProxyNoSubPacketTlvProc).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ClientTransProxyInnerNoSubPacketTlvProc(TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: ClientTransInnerProxyProcessSessionDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransInnerProxyProcessSessionDataTest001, TestSize.Level1)
{
    PacketHead dataHead = {0};
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    int32_t ret = ClientTransInnerProxyProcessSessionData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = ClientTransInnerProxyNoSubPacketProc(
        TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyProcessSessionData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransInnerProxyProcessSessionData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: ClientTransProxyGetChannelSliceTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxyGetChannelSliceTest001, TestSize.Level1)
{
    InnerListInit();
    ChannelSliceProcessor *node = ClientTransProxyGetChannelSlice(TRANS_TEST_CHANNEL_ID);
    ASSERT_TRUE(node);
    node = ClientTransProxyGetChannelSlice(TRANS_TEST_CHANNEL_ID);
    ASSERT_TRUE(node);
    int32_t ret = TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID + 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    InnerListDeinit();
    ret = TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: IsValidCheckoutSliceProcessTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, IsValidCheckoutSliceProcessTest001, TestSize.Level1)
{
    InnerListInit();
    ChannelSliceProcessor *node = ClientTransProxyGetChannelSlice(TRANS_TEST_CHANNEL_ID);
    ASSERT_TRUE(node);
    bool res = IsValidCheckoutSliceProcess(TRANS_TEST_CHANNEL_ID);
    EXPECT_TRUE(res);
    res = IsValidCheckoutSliceProcess(TRANS_TEST_CHANNEL_ID + 1);
    EXPECT_FALSE(res);
    int32_t ret = TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    InnerListDeinit();
}

/**
 * @tc.name: ClientTransProxyLastSliceProcessTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxyLastSliceProcessTest001, TestSize.Level1)
{
    SliceProcessor processor = { 0 };
    SliceHead head = { 0 };
    const char *data = "trans_inner_test.cpp";
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxySliceProcessChkPkgIsValid).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransProxyLastSliceProcess(&processor, &head, data, TEST_SEND_DATA_LEN, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransProxySliceProcessChkPkgIsValid).WillOnce(Return(SOFTBUS_OK));
    ret = ClientTransProxyLastSliceProcess(&processor, &head, data, TEST_SEND_DATA_LEN, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
}

/**
 * @tc.name: ClientTransProxySubPacketProcTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxySubPacketProcTest001, TestSize.Level1)
{
    SliceHead head = { 0 };
    const char *data = "trans_inner_test.cpp";
    int32_t ret = ClientTransProxySubPacketProc(TRANS_TEST_CHANNEL_ID, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxySliceProcessChkPkgIsValid).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxySubPacketProc(TRANS_TEST_CHANNEL_ID, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    head.sliceNum = TEST_SLICE_NUM;
    head.sliceSeq = TEST_SLICE_NUM - 1;
    ret = ClientTransProxySubPacketProc(TRANS_TEST_CHANNEL_ID, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    head.sliceSeq = 1;
    EXPECT_CALL(TransInnerMock, TransProxyNormalSliceProcess).WillOnce(Return(SOFTBUS_OK));
    ret = ClientTransProxySubPacketProc(TRANS_TEST_CHANNEL_ID, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    InnerListDeinit();
}

/**
 * @tc.name: TransInnerProxyPackBytesTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerProxyPackBytesTest001, TestSize.Level1)
{
    ProxyDataInfo dataInfo = { 0 };
    TransInnerSessionInfo info = { 0 };
    int32_t ret = TransInnerProxyPackBytes(TRANS_TEST_CHANNEL_ID, nullptr, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransInnerProxyPackBytes(TRANS_TEST_CHANNEL_ID, &dataInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    info.supportTlv = true;
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyPackTlvBytes).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransInnerProxyPackBytes(TRANS_TEST_CHANNEL_ID, &dataInfo, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.supportTlv = false;
    EXPECT_CALL(TransInnerMock, TransProxyPackBytes).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransInnerProxyPackBytes(TRANS_TEST_CHANNEL_ID, &dataInfo, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ProxySendDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ProxySendDataTest001, TestSize.Level1)
{
    const char *data = "trans_inner_test.cpp";
    TransInnerSessionInfo info = { 0 };
    int32_t ret = ProxySendData(TRANS_TEST_CHANNEL_ID, nullptr, TEST_SEND_DATA_LEN, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ProxySendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ProxySendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), DATA_BUF_MAX + 1, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyPackBytes).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = ProxySendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransSendDataTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransSendDataTest001, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    int32_t ret = TransSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(nullptr));
    ret = TransSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: TransSendDataTest002
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransSendDataTest002, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_PROXY,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    int32_t ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyPackBytes).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = TransSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/**
 * @tc.name: ServerSideSendAck001
 * @tc.desc: Should return SOFTBUS_NO_INIT when g_sessionList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ServerSideSendAck001, TestSize.Level1)
{
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(TransInnerMock, TransDealProxyChannelOpenResult).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ServerSideSendAck(TRANS_TEST_CHANNEL_ID, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransDealTdcChannelOpenResult).WillOnce(Return(SOFTBUS_OK));
    ret = ServerSideSendAck(TRANS_TEST_CHANNEL_ID, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}
