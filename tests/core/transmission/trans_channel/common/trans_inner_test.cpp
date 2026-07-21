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

/*
 * @tc.name: TransInnerAddDataBufNodeTest001
 * @tc.desc: proxy channel type returns SOFTBUS_OK immediately without list operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerAddDataBufNodeTest001, TestSize.Level1)
{
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransInnerAddDataBufNode(0, 0, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID + 1, TRANS_TEST_FD + 1, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransInnerAddDataBufNodeTest002
 * @tc.desc: tcp_direct channel type after init returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerAddDataBufNodeTest002, TestSize.Level1)
{
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: InnerAddSessionTest001
 * @tc.desc: null param returns SOFTBUS_INVALID_PARAM and no init returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, InnerAddSessionTest001, TestSize.Level1)
{
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_PROXY,
        .supportTlv = false,
    };
    int32_t ret = InnerAddSession(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: InnerAddSessionTest002
 * @tc.desc: after init, missing listener returns SOFTBUS_MEM_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, InnerAddSessionTest002, TestSize.Level1)
{
    InnerSessionInfo innerInfo = {
        .fd = TRANS_TEST_FD,
        .channelId = TRANS_TEST_CHANNEL_ID,
        .channelType = CHANNEL_TYPE_PROXY,
        .supportTlv = false,
    };
    InnerListInit();
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    int32_t ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    InnerListDeinit();
}

/*
 * @tc.name: InnerAddSessionTest003
 * @tc.desc: valid proxy and tcp_direct sessions return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, InnerAddSessionTest003, TestSize.Level1)
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
    InnerListInit();
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    int32_t ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    innerInfo.channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = InnerAddSession(&innerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: DeleteSessionTest001
 * @tc.desc: no init returns SOFTBUS_NO_INIT, valid delete returns SOFTBUS_OK, double delete returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, DeleteSessionTest001, TestSize.Level1)
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
    InnerListInit();
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    int32_t ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    InnerListDeinit();
    ret = DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: DirectOnChannelCloseTest001
 * @tc.desc: DirectOnChannelClose calls ClientIpcOnChannelClosed with channel info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, DirectOnChannelCloseTest001, TestSize.Level1)
{
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, ClientIpcOnChannelClosed).WillRepeatedly(Return(SOFTBUS_OK));
    DirectOnChannelClose(TRANS_TEST_CHANNEL_ID, PKG_NAME);
    DirectOnChannelClose(TRANS_TEST_CHANNEL_ID + 1, PKG_NAME);
    DirectOnChannelClose(0, PKG_NAME);
}

/*
 * @tc.name: GetSessionInfoByFdTest001
 * @tc.desc: null param returns SOFTBUS_INVALID_PARAM and no init returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByFdTest001, TestSize.Level1)
{
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByFd(TRANS_TEST_FD, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetSessionInfoByFd(TRANS_TEST_FD, &info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: GetSessionInfoByFdTest002
 * @tc.desc: valid fd found returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByFdTest002, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByFd(TRANS_TEST_FD, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: GetSessionInfoByFdTest003
 * @tc.desc: fd not found returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByFdTest003, TestSize.Level1)
{
    InnerListInit();
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByFd(TRANS_TEST_FD + 1, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: GetSessionInfoByChanIdTest001
 * @tc.desc: null param returns SOFTBUS_INVALID_PARAM and no init returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByChanIdTest001, TestSize.Level1)
{
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, &info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: GetSessionInfoByChanIdTest002
 * @tc.desc: tcp_direct channel found returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByChanIdTest002, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: GetSessionInfoByChanIdTest003
 * @tc.desc: channelId not found returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByChanIdTest003, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID + 1, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: GetSessionInfoByChanIdTest004
 * @tc.desc: proxy channel with TransProxyGetAppInfoByChanId error returns that error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByChanIdTest004, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyGetAppInfoByChanId).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, &info);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: GetSessionInfoByChanIdTest005
 * @tc.desc: proxy channel with TransProxyGetAppInfoByChanId success returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, GetSessionInfoByChanIdTest005, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyGetAppInfoByChanId).WillRepeatedly(Return(SOFTBUS_OK));
    TransInnerSessionInfo info = {};
    int32_t ret = GetSessionInfoByChanId(TRANS_TEST_CHANNEL_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransCloseInnerSessionByNetworkIdTest001
 * @tc.desc: close session by networkId calls ClientIpcOnChannelClosed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransCloseInnerSessionByNetworkIdTest001, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, ClientIpcOnChannelClosed).WillRepeatedly(Return(SOFTBUS_OK));
    TransCloseInnerSessionByNetworkId(NETWORK_ID);
    InnerListDeinit();
    TransCloseInnerSessionByNetworkId(NETWORK_ID);
}

/*
 * @tc.name: TransInnerGetTdcDataBufByIdTest001
 * @tc.desc: null len returns SOFTBUS_INVALID_PARAM and no init returns SOFTBUS_NO_INIT
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
}

/*
 * @tc.name: TransInnerGetTdcDataBufByIdTest002
 * @tc.desc: valid get returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerGetTdcDataBufByIdTest002, TestSize.Level1)
{
    size_t len = 0;
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransInnerGetTdcDataBufById(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, &len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerGetTdcDataBufByIdTest003
 * @tc.desc: channel not found returns SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerGetTdcDataBufByIdTest003, TestSize.Level1)
{
    size_t len = 0;
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    ret = TransInnerGetTdcDataBufById(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, &len);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerUpdateTdcDataBufWInfoTest001
 * @tc.desc: null recvBuf returns SOFTBUS_INVALID_PARAM and no init returns SOFTBUS_NO_INIT
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
    SoftBusFree(recvBuf);
}

/*
 * @tc.name: TransInnerUpdateTdcDataBufWInfoTest002
 * @tc.desc: invalid data length returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerUpdateTdcDataBufWInfoTest002, TestSize.Level1)
{
    int32_t recvLen = TRANS_TEST_IVALID_LEN;
    char *recvBuf = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(recvBuf);
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransInnerUpdateTdcDataBufWInfo(TRANS_TEST_CHANNEL_ID, recvBuf, recvLen);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
    SoftBusFree(recvBuf);
}

/*
 * @tc.name: TransInnerUpdateTdcDataBufWInfoTest003
 * @tc.desc: zero recvLen returns SOFTBUS_MEM_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerUpdateTdcDataBufWInfoTest003, TestSize.Level1)
{
    int32_t recvLen = 0;
    char *recvBuf = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(recvBuf);
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransInnerUpdateTdcDataBufWInfo(TRANS_TEST_CHANNEL_ID, recvBuf, recvLen);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
    SoftBusFree(recvBuf);
}

/*
 * @tc.name: TransInnerUpdateTdcDataBufWInfoTest004
 * @tc.desc: channel not found returns SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerUpdateTdcDataBufWInfoTest004, TestSize.Level1)
{
    int32_t recvLen = 0;
    char *recvBuf = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(recvBuf);
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    ret = TransInnerUpdateTdcDataBufWInfo(TRANS_TEST_CHANNEL_ID, recvBuf, recvLen);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    InnerListDeinit();
    SoftBusFree(recvBuf);
}

/*
 * @tc.name: TransTdcProcessInnerTlvDataTest001
 * @tc.desc: null info, null pktHead, or null listener.func returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerTlvDataTest001, TestSize.Level1)
{
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
}

/*
 * @tc.name: TransTdcProcessInnerTlvDataTest002
 * @tc.desc: no data buf node returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerTlvDataTest002, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransTdcProcessInnerTlvData(&info, nullptr, 0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListDeinit();
}

/*
 * @tc.name: TransTdcProcessInnerTlvDataTest003
 * @tc.desc: malloc error with dataLen=1 returns SOFTBUS_MALLOC_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerTlvDataTest003, TestSize.Level1)
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
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransTdcProcessInnerTlvDataTest004
 * @tc.desc: decrypt error returns SOFTBUS_DECRYPT_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerTlvDataTest004, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    TcpDataTlvPacketHead pktHead { .dataLen = TEST_DATA_LEN };
    uint32_t newPktHeadSize = 0;
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcDecrypt).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransTdcProcessInnerTlvDataTest005
 * @tc.desc: MoveNode error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerTlvDataTest005, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    TcpDataTlvPacketHead pktHead { .dataLen = TEST_DATA_LEN };
    uint32_t newPktHeadSize = 0;
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcDecrypt).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, MoveNode).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransTdcProcessInnerTlvDataTest006
 * @tc.desc: success returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerTlvDataTest006, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    TcpDataTlvPacketHead pktHead { .dataLen = TEST_DATA_LEN };
    uint32_t newPktHeadSize = 0;
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcDecrypt).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, MoveNode).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransTdcProcessInnerTlvData(&info, &pktHead, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerTdcProcAllTlvDataTest001
 * @tc.desc: null param returns SOFTBUS_INVALID_PARAM and no init returns SOFTBUS_NO_INIT
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
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    int32_t ret = TransInnerTdcProcAllTlvData(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransInnerTdcProcAllTlvDataTest002
 * @tc.desc: no data buf node returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllTlvDataTest002, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerTdcProcAllTlvDataTest003
 * @tc.desc: unpack error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllTlvDataTest003, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcUnPackAllTlvData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerTdcProcAllTlvDataTest004
 * @tc.desc: unpack success but process malloc error returns SOFTBUS_MALLOC_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllTlvDataTest004, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcUnPackAllTlvData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerTdcProcAllTlvDataTest005
 * @tc.desc: null mutex returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllTlvDataTest005, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    uintptr_t originalMutex = 0;
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();

    originalMutex = g_innerChannelDataBufList->lock.mutex;
    g_innerChannelDataBufList->lock.mutex = 0;
    int32_t ret = TransInnerTdcProcAllTlvData(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    g_innerChannelDataBufList->lock.mutex = originalMutex;
    InnerListDeinit();
}

/*
 * @tc.name: TransTdcProcessInnerDataTest001
 * @tc.desc: null info or null listener.func returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerDataTest001, TestSize.Level1)
{
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
}

/*
 * @tc.name: TransTdcProcessInnerDataTest002
 * @tc.desc: no data buf node returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerDataTest002, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransTdcProcessInnerData(&info);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: TransTdcProcessInnerDataTest003
 * @tc.desc: malloc error returns SOFTBUS_MALLOC_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransTdcProcessInnerDataTest003, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransTdcProcessInnerData(&info);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerTdcProcAllDataTest001
 * @tc.desc: null param returns SOFTBUS_INVALID_PARAM and no init returns SOFTBUS_NO_INIT
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
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    int32_t ret = TransInnerTdcProcAllData(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransInnerTdcProcAllDataTest002
 * @tc.desc: no data buf node returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllDataTest002, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerTdcProcAllDataTest003
 * @tc.desc: unpack error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllDataTest003, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcUnPackAllData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerTdcProcAllDataTest004
 * @tc.desc: unpack success but process malloc error returns SOFTBUS_MALLOC_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllDataTest004, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcUnPackAllData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerTdcProcAllDataTest005
 * @tc.desc: null mutex returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerTdcProcAllDataTest005, TestSize.Level1)
{
    SessionInnerCallback Innerlistener = { 0 };
    uintptr_t originalMutex = 0;
    Innerlistener.func = TestInnerMessageHandler;
    TransInnerSessionInfo info = {
        .channelId = TRANS_TEST_CHANNEL_ID,
        .fd = TRANS_TEST_FD,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
    };
    (void)memcpy_s(&info.listener, sizeof(info.listener), &Innerlistener, sizeof(SessionInnerCallback));
    InnerListInit();

    originalMutex = g_innerChannelDataBufList->lock.mutex;
    g_innerChannelDataBufList->lock.mutex = 0;
    int32_t ret = TransInnerTdcProcAllData(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    g_innerChannelDataBufList->lock.mutex = originalMutex;
    InnerListDeinit();
}

/*
 * @tc.name: DirectChannelCloseSocketTest001
 * @tc.desc: close socket with session calls mock functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, DirectChannelCloseSocketTest001, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransLaneMgrDelLane).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransDelTcpChannelInfoByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, DelTrigger).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, SoftBusSocketShutDown).WillOnce(Return(SOFTBUS_ADAPTER_OK));
    EXPECT_CALL(TransInnerMock, SoftBusSocketClose).WillOnce(Return(SOFTBUS_ADAPTER_OK));
    DirectChannelCloseSocket(TRANS_TEST_FD);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TdcDataReceivedTest001
 * @tc.desc: fd not found returns SOFTBUS_NOT_FIND with no session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcDataReceivedTest001, TestSize.Level1)
{
    InnerListInit();
    int32_t ret = TdcDataReceived(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = TdcDataReceived(TRANS_TEST_FD + 1);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: TdcDataReceivedTest002
 * @tc.desc: no data buf node returns SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcDataReceivedTest002, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    int32_t ret = TdcDataReceived(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TdcDataReceivedTest003
 * @tc.desc: TransTdcRecvFirstData error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcDataReceivedTest003, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcRecvFirstData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TdcDataReceived(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TdcDataReceivedTest004
 * @tc.desc: data processing malloc error returns SOFTBUS_MALLOC_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcDataReceivedTest004, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    int32_t ret = TransInnerAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcRecvFirstData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TdcDataReceived(TRANS_TEST_FD);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    TransSrvDelInnerDataBufNode(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: DirectChannelOnDataEventTest001
 * @tc.desc: socket out event returns SOFTBUS_OK and socket in event returns error
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

/*
 * @tc.name: DirectChannelCreateListenerTest001
 * @tc.desc: create listener and add trigger returns SOFTBUS_OK
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

/*
 * @tc.name: TdcSendDataTest001
 * @tc.desc: invalid param and no session error branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcSendDataTest001, TestSize.Level1)
{
    const char *data = "trans_inner_test.cpp";
    int32_t ret = TdcSendData(TRANS_TEST_CHANNEL_ID, nullptr, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), DATA_BUF_MAX + 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TdcSendDataTest002
 * @tc.desc: pack error returns SOFTBUS_ENCRYPT_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcSendDataTest002, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(nullptr));
    int32_t ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TdcSendDataTest003
 * @tc.desc: send data error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcSendDataTest003, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    char *testRecvBuf = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(testRecvBuf);
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(testRecvBuf));
    EXPECT_CALL(TransInnerMock, SetIpTos).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(TransInnerMock, TransTdcSendData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TdcSendDataTest004
 * @tc.desc: success returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TdcSendDataTest004, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    char *testRecvBuf = reinterpret_cast<char *>(SoftBusCalloc(TRANS_TEST_FD));
    ASSERT_TRUE(testRecvBuf);
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(testRecvBuf));
    EXPECT_CALL(TransInnerMock, TransTdcSendData).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TdcSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransInnerProxyProcDataTest001
 * @tc.desc: no session returns error from GetSessionInfoByChanId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransInnerProxyProcDataTest001, TestSize.Level1)
{
    DataHeadTlvPacketHead dataHead = {0};
    const char *data = "trans_inner_test.cpp";
    int32_t ret = ClientTransInnerProxyProcData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = ClientTransInnerProxyProcData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransInnerProxyProcDataTest002
 * @tc.desc: TransProxyProcData error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransInnerProxyProcDataTest002, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyProcData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransInnerProxyProcData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransProxyInnerNoSubPacketTlvProcTest001
 * @tc.desc: TransProxyParseTlv error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxyInnerNoSubPacketTlvProcTest001, TestSize.Level1)
{
    const char *data = "trans_inner_test.cpp";
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyParseTlv).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransProxyInnerNoSubPacketTlvProc(TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransProxyParseTlv).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransProxyNoSubPacketTlvProc).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyInnerNoSubPacketTlvProc(TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyInnerNoSubPacketTlvProcTest002
 * @tc.desc: parse success but proc error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxyInnerNoSubPacketTlvProcTest002, TestSize.Level1)
{
    const char *data = "trans_inner_test.cpp";
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyParseTlv).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransProxyNoSubPacketTlvProc).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ClientTransProxyInnerNoSubPacketTlvProc(TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: ClientTransInnerProxyProcessSessionDataTest001
 * @tc.desc: no init and no session error branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransInnerProxyProcessSessionDataTest001, TestSize.Level1)
{
    PacketHead dataHead = {0};
    const char *data = "trans_inner_test.cpp";
    int32_t ret = ClientTransInnerProxyProcessSessionData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = ClientTransInnerProxyProcessSessionData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransInnerProxyProcessSessionDataTest002
 * @tc.desc: TransProxyProcessSessionData error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransInnerProxyProcessSessionDataTest002, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyProcessSessionData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransInnerProxyProcessSessionData(TRANS_TEST_CHANNEL_ID, &dataHead, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransInnerProxyNoSubPacketProcTest001
 * @tc.desc: no init and no session error branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransInnerProxyNoSubPacketProcTest001, TestSize.Level1)
{
    const char *data = "trans_inner_test.cpp";
    int32_t ret = ClientTransInnerProxyNoSubPacketProc(TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    InnerListInit();
    ret = ClientTransInnerProxyNoSubPacketProc(TRANS_TEST_CHANNEL_ID, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransProxyGetChannelSliceTest001
 * @tc.desc: get channel slice returns valid node for existing and new channels
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
    (void)TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransProxyDelSliceProcessorByChannelIdTest001
 * @tc.desc: delete existing, non-existing, and no init branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransProxyDelSliceProcessorByChannelIdTest001, TestSize.Level1)
{
    InnerListInit();
    (void)ClientTransProxyGetChannelSlice(TRANS_TEST_CHANNEL_ID);
    int32_t ret = TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID + 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    InnerListDeinit();
    ret = TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: IsValidCheckoutSliceProcessTest001
 * @tc.desc: valid channelId returns true and invalid channelId returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, IsValidCheckoutSliceProcessTest001, TestSize.Level1)
{
    InnerListInit();
    (void)ClientTransProxyGetChannelSlice(TRANS_TEST_CHANNEL_ID);
    bool res = IsValidCheckoutSliceProcess(TRANS_TEST_CHANNEL_ID);
    EXPECT_TRUE(res);
    res = IsValidCheckoutSliceProcess(TRANS_TEST_CHANNEL_ID + 1);
    EXPECT_FALSE(res);
    (void)TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransProxyLastSliceProcessTest001
 * @tc.desc: check pkg error returns that error code
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
}

/*
 * @tc.name: ClientTransProxyLastSliceProcessTest002
 * @tc.desc: check pkg success but memcpy error returns SOFTBUS_MEM_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxyLastSliceProcessTest002, TestSize.Level1)
{
    SliceProcessor processor = { 0 };
    SliceHead head = { 0 };
    const char *data = "trans_inner_test.cpp";
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxySliceProcessChkPkgIsValid).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = ClientTransProxyLastSliceProcess(&processor, &head, data, TEST_SEND_DATA_LEN, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
}

/*
 * @tc.name: ClientTransProxySubPacketProcTest001
 * @tc.desc: no init returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxySubPacketProcTest001, TestSize.Level1)
{
    SliceHead head = { 0 };
    const char *data = "trans_inner_test.cpp";
    int32_t ret = ClientTransProxySubPacketProc(TRANS_TEST_CHANNEL_ID, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = ClientTransProxySubPacketProc(0, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: ClientTransProxySubPacketProcTest002
 * @tc.desc: first slice process error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxySubPacketProcTest002, TestSize.Level1)
{
    SliceHead head = { 0 };
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    int32_t ret = ClientTransProxySubPacketProc(TRANS_TEST_CHANNEL_ID, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    (void)TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransProxySubPacketProcTest003
 * @tc.desc: last slice check error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxySubPacketProcTest003, TestSize.Level1)
{
    SliceHead head = { 0 };
    head.sliceNum = TEST_SLICE_NUM;
    head.sliceSeq = TEST_SLICE_NUM - 1;
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxySliceProcessChkPkgIsValid).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransProxySubPacketProc(TRANS_TEST_CHANNEL_ID, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: ClientTransProxySubPacketProcTest004
 * @tc.desc: normal slice process returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ClientTransProxySubPacketProcTest004, TestSize.Level1)
{
    SliceHead head = { 0 };
    head.sliceNum = TEST_SLICE_NUM;
    head.sliceSeq = 1;
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyNormalSliceProcess).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = ClientTransProxySubPacketProc(TRANS_TEST_CHANNEL_ID, &head, data, TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)TransProxyDelSliceProcessorByChannelId(TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransInnerProxyPackBytesTest001
 * @tc.desc: null dataInfo or null info returns SOFTBUS_INVALID_PARAM
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
}

/*
 * @tc.name: TransInnerProxyPackBytesTest002
 * @tc.desc: tlv pack returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerProxyPackBytesTest002, TestSize.Level1)
{
    ProxyDataInfo dataInfo = { 0 };
    TransInnerSessionInfo info = { 0 };
    info.supportTlv = true;
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyPackTlvBytes).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransInnerProxyPackBytes(TRANS_TEST_CHANNEL_ID, &dataInfo, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransInnerProxyPackBytesTest003
 * @tc.desc: non-tlv pack returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransInnerProxyPackBytesTest003, TestSize.Level1)
{
    ProxyDataInfo dataInfo = { 0 };
    TransInnerSessionInfo info = { 0 };
    info.supportTlv = false;
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyPackBytes).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransInnerProxyPackBytes(TRANS_TEST_CHANNEL_ID, &dataInfo, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProxySendDataTest001
 * @tc.desc: null data, null info, or oversized data returns SOFTBUS_INVALID_PARAM
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
}

/*
 * @tc.name: ProxySendDataTest002
 * @tc.desc: pack error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ProxySendDataTest002, TestSize.Level1)
{
    const char *data = "trans_inner_test.cpp";
    TransInnerSessionInfo info = { 0 };
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyPackBytes).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ProxySendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransSendDataTest001
 * @tc.desc: no session returns error from GetSessionInfoByChanId
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    int32_t ret = TransSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransSendDataTest002
 * @tc.desc: tcp_direct pack error returns SOFTBUS_ENCRYPT_ERR
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
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .supportTlv = false,
        .listener = &Innerlistener,
    };
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransTdcPackAllData).WillOnce(Return(nullptr));
    int32_t ret = TransSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: TransSendDataTest003
 * @tc.desc: proxy channel pack error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, TransSendDataTest003, TestSize.Level1)
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
    (void)memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NETWORK_ID, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, SESSION_KEY, SESSION_KEY_LENGTH);
    const char *data = "trans_inner_test.cpp";
    InnerListInit();
    EXPECT_EQ(SOFTBUS_OK, InnerAddSession(&innerInfo));
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransProxyPackBytes).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransSendData(TRANS_TEST_CHANNEL_ID, reinterpret_cast<const void *>(data), TEST_SEND_DATA_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)DeleteSession(TRANS_TEST_FD, TRANS_TEST_CHANNEL_ID);
    InnerListDeinit();
}

/*
 * @tc.name: ServerSideSendAckTest001
 * @tc.desc: proxy channel open result error returns that error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ServerSideSendAckTest001, TestSize.Level1)
{
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(TransInnerMock, TransDealProxyChannelOpenResult).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ServerSideSendAck(TRANS_TEST_CHANNEL_ID, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ServerSideSendAckTest002
 * @tc.desc: tcp_direct channel open result success returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerTest, ServerSideSendAckTest002, TestSize.Level1)
{
    NiceMock<TransInnerInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransDealTdcChannelOpenResult).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = ServerSideSendAck(TRANS_TEST_CHANNEL_ID, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

}
