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

#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_transmission_interface.h"
#include "trans_inner.h"
#include "trans_inner_self_adaptive.h"
#include "trans_inner_session.c"
#include "trans_inner_session_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

const char *PKG_NAME = "ohos.trans_inner_test";
const char *SESSION_NAME = "ohos.trans_inner_session_test";
const char *NETWORK_ID = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";

#define TRANS_TEST_DATA "test auth message data"
#define TRANS_TEST_SESSION_ID 2048
#define TRANS_TEST_REQ_ID 100

class TransInnerSessionTest : public testing::Test {
public:
    TransInnerSessionTest()
    {}
    ~TransInnerSessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransInnerSessionTest::SetUpTestCase(void)
{
}

void TransInnerSessionTest::TearDownTestCase(void)
{
}

static int32_t OnSessionOpened(int32_t channelId, int32_t channelType, char *peerNetworkId, int32_t result)
{
    (void)channelType;
    (void)peerNetworkId;
    (void)result;
    TRANS_LOGI(TRANS_TEST, "on session opened, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int32_t channelId)
{
    TRANS_LOGI(TRANS_TEST, "on session close, channelId=%{public}d", channelId);
}

static void OnBytesReceived(int32_t channelId, const void *data, uint32_t dataLen)
{
    (void)data;
    (void)dataLen;
    TRANS_LOGI(TRANS_TEST, "data recv, channelId=%{public}d", channelId);
}

static int32_t OnSetChannelInfoByReqId(uint32_t reqId, int32_t channelId, int32_t channelType)
{
    (void)reqId;
    (void)channelType;
    TRANS_LOGI(TRANS_TEST, "seq reqid, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static void OnLinkDown(const char *networkId)
{
    TRANS_LOGI(TRANS_TEST, "link down, networkId=%{public}s", networkId);
}

static ISessionListenerInner g_innerSessionListener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnLinkDown = OnLinkDown,
    .OnSetChannelInfoByReqId = OnSetChannelInfoByReqId,
};

/*
 * @tc.name: InnerMessageHandlerTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, InnerMessageHandlerTest001, TestSize.Level1)
{
    int32_t ret = InnerMessageHandler(
        TRANS_TEST_SESSION_ID, TRANS_TEST_DATA, static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransOnSetChannelInfoByReqIdTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSetChannelInfoByReqIdTest001, TestSize.Level1)
{
    int32_t ret = TransOnSetChannelInfoByReqId(
        TRANS_TEST_REQ_ID, TRANS_TEST_SESSION_ID, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransOnSessionOpenedInnerTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSessionOpenedInnerTest001, TestSize.Level1)
{
    int32_t result = 0;
    int32_t ret = TransOnSessionOpenedInner(
        TRANS_TEST_SESSION_ID, CHANNEL_TYPE_UNDEFINED, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: GetIsClientInfoByIdTest001
 * @tc.desc: Should return SOFTBUS_OK
 *           when given valid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, GetIsClientInfoByIdTest001, TestSize.Level1)
{
    bool isClient = 0;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    NiceMock<TransInnerSessionInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, &isClient);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, &isClient);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelType = CHANNEL_TYPE_PROXY;
    EXPECT_CALL(TransInnerMock, TransProxyGetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, &isClient);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TransInnerMock, TransProxyGetAppInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, &isClient);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransCreateSessionServerInnerTest001
 * @tc.desc: Should return SOFTBUS_OK
 *           when param is valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransCreateSessionServerInnerTest001, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransCreateSessionServer).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransCreateSessionServerInner(
        PKG_NAME, SESSION_NAME, &g_innerSessionListener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnLinkDownInner(NETWORK_ID);
}

/*
 * @tc.name: TransOnSetChannelInfoByReqIdTest002
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSetChannelInfoByReqIdTest002, TestSize.Level1)
{
    int32_t ret = TransOnSetChannelInfoByReqId(
        TRANS_TEST_REQ_ID, TRANS_TEST_SESSION_ID, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransOnSessionOpenedInnerTest002
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSessionOpenedInnerTest002, TestSize.Level1)
{
    int32_t result = 0;
    int32_t ret = TransOnSessionOpenedInner(
        TRANS_TEST_SESSION_ID, CHANNEL_TYPE_UNDEFINED, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransInnerSessionInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, ProxyDataRecvHandler).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransOnBytesReceivedInner(TRANS_TEST_SESSION_ID, TRANS_TEST_DATA, static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
}


/*
 * @tc.name: TransOnSessionOpenedInnerTest003
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSessionOpenedInnerTest003, TestSize.Level1)
{
    int32_t result = SOFTBUS_INVALID_PARAM;
    int32_t ret = TransOnSessionOpenedInner(
        TRANS_TEST_SESSION_ID, CHANNEL_TYPE_TCP_DIRECT, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransOnSessionOpenedInnerTest004
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSessionOpenedInnerTest004, TestSize.Level1)
{
    int32_t result = SOFTBUS_OK;
    NiceMock<TransInnerSessionInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, DirectChannelCreateListener).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransOnSessionOpenedInner(
        TRANS_TEST_SESSION_ID, CHANNEL_TYPE_TCP_DIRECT, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: InnerMessageHandlerTest002
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is not null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, InnerMessageHandlerTest002, TestSize.Level1)
{
    int32_t ret = InnerMessageHandler(
        TRANS_TEST_SESSION_ID, TRANS_TEST_DATA, static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: OnSessionOpenedInnerTest002
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is not null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, OnSessionOpenedInnerTest002, TestSize.Level1)
{
    int32_t result = 0;
    NiceMock<TransInnerSessionInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, DirectChannelCreateListener).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, GetAppInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(TransInnerMock, TransProxyGetAppInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransProxyGetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, InnerAddSession).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, InnerAddSession).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, TransInnerAddDataBufNode).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransInnerAddDataBufNode).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransInnerMock, ServerSideSendAck).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, ServerSideSendAck).WillRepeatedly(Return(SOFTBUS_OK));
    ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransOpenSessionInnerTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOpenSessionInnerTest001, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransOpenChannel).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransOpenSessionInner(SESSION_NAME, const_cast<char *>(NETWORK_ID), TRANS_TEST_REQ_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransOpenChannel).WillOnce(Return(SOFTBUS_OK));
    ret = TransOpenSessionInner(SESSION_NAME, const_cast<char *>(NETWORK_ID), TRANS_TEST_REQ_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransSendDataInnerTest001
 * @tc.desc: Should return SOFTBUS_NO_INIT
 *           when g_InnerListener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransSendDataInnerTest001, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> TransInnerMock;
    EXPECT_CALL(TransInnerMock, TransSendData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransSendData(TRANS_TEST_SESSION_ID, TRANS_TEST_DATA, static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransInnerMock, TransSendData).WillOnce(Return(SOFTBUS_OK));
    ret = TransSendData(TRANS_TEST_SESSION_ID, TRANS_TEST_DATA, static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}
