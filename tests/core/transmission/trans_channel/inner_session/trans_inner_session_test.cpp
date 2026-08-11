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
    TransInnerSessionTest(void)
    {}
    ~TransInnerSessionTest(void)
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

static void OnLinkDown(const char *networkId, int32_t routeType, const char *pkgName)
{
    (void)pkgName;
    TRANS_LOGI(TRANS_TEST, "link down, networkId=%{public}s, routeType=%{public}d", networkId, routeType);
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
 * @tc.desc: inner message handler returns no init when inner listener is null
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
 * @tc.desc: trans on set channel info by req id returns invalid param when inner listener is null
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
 * @tc.desc: trans on session opened inner returns no init when inner listener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSessionOpenedInnerTest001, TestSize.Level1)
{
    int32_t result = 0;
    int32_t ret = TransOnSessionOpenedInner(
        TRANS_TEST_SESSION_ID, CHANNEL_TYPE_UNDEFINED, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransOnSessionClosedInnerTest001
 * @tc.desc: trans on session closed inner handles gracefully when inner listener is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSessionClosedInnerTest001, TestSize.Level1)
{
    int32_t channelId = TRANS_TEST_SESSION_ID;
    EXPECT_NO_FATAL_FAILURE(TransOnSessionClosedInner(channelId));
    EXPECT_NO_FATAL_FAILURE(TransOnSessionClosedInner(0));
    EXPECT_NO_FATAL_FAILURE(TransOnSessionClosedInner(-1));
    EXPECT_NO_FATAL_FAILURE(TransOnSessionClosedInner(1));
}

/*
 * @tc.name: GetIsClientInfoByIdTest001
 * @tc.desc: get is client info by id returns invalid param when isClient pointer is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, GetIsClientInfoByIdTest001, TestSize.Level1)
{
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    int32_t ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelType = CHANNEL_TYPE_PROXY;
    ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: GetIsClientInfoByIdTest002
 * @tc.desc: get is client info by id returns ok for tcp direct channel when GetAppInfoById succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, GetIsClientInfoByIdTest002, TestSize.Level1)
{
    bool isClient = false;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, &isClient);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetIsClientInfoByIdTest003
 * @tc.desc: get is client info by id returns error for tcp direct when GetAppInfoById fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, GetIsClientInfoByIdTest003, TestSize.Level1)
{
    bool isClient = false;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, &isClient);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: GetIsClientInfoByIdTest004
 * @tc.desc: get is client info by id returns ok for proxy channel when TransProxyGetAppInfoById succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, GetIsClientInfoByIdTest004, TestSize.Level1)
{
    bool isClient = false;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyGetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, &isClient);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetIsClientInfoByIdTest005
 * @tc.desc: get is client info by id returns error for proxy when TransProxyGetAppInfoById fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, GetIsClientInfoByIdTest005, TestSize.Level1)
{
    bool isClient = false;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyGetAppInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = GetIsClientInfoById(TRANS_TEST_SESSION_ID, channelType, &isClient);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransCreateSessionServerInnerTest001
 * @tc.desc: trans create session server inner returns ok when TransCreateSessionServer succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransCreateSessionServerInnerTest001, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, TransCreateSessionServer).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransCreateSessionServerInner(
        PKG_NAME, SESSION_NAME, &g_innerSessionListener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransOnLinkDownInnerTest001
 * @tc.desc: trans on link down inner handles link down event for non block mode route type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnLinkDownInnerTest001, TestSize.Level1)
{
    int32_t routeType = 1;
    EXPECT_NO_FATAL_FAILURE(TransOnLinkDownInner(NETWORK_ID, routeType, PKG_NAME));
    EXPECT_NO_FATAL_FAILURE(TransOnLinkDownInner(nullptr, routeType, nullptr));
    EXPECT_NO_FATAL_FAILURE(TransOnLinkDownInner(NETWORK_ID, 0, PKG_NAME));
}

/*
 * @tc.name: TransOnSetChannelInfoByReqIdTest002
 * @tc.desc: trans on set channel info by req id returns ok when inner listener is set
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
 * @tc.desc: trans on session opened inner returns ok for undefined channel type with listener set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSessionOpenedInnerTest002, TestSize.Level1)
{
    int32_t result = 0;
    int32_t ret = TransOnSessionOpenedInner(
        TRANS_TEST_SESSION_ID, CHANNEL_TYPE_UNDEFINED, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransOnBytesReceivedInnerTest001
 * @tc.desc: trans on bytes received inner calls ProxyDataRecvHandler with channel data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnBytesReceivedInnerTest001, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, ProxyDataRecvHandler).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransOnBytesReceivedInner(TRANS_TEST_SESSION_ID, TRANS_TEST_DATA,
        static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
}

/*
 * @tc.name: TransOnSessionOpenedInnerTest003
 * @tc.desc: trans on session opened inner returns ok when result is not ok for tcp direct channel
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
 * @tc.desc: trans on session opened inner returns invalid param when DirectChannelCreateListener fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOnSessionOpenedInnerTest004, TestSize.Level1)
{
    int32_t result = SOFTBUS_OK;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, DirectChannelCreateListener).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransOnSessionOpenedInner(
        TRANS_TEST_SESSION_ID, CHANNEL_TYPE_TCP_DIRECT, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: InnerMessageHandlerTest002
 * @tc.desc: inner message handler returns ok when inner listener is set
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
 * @tc.name: OnSessionOpenedInnerTest001
 * @tc.desc: on session opened inner returns invalid param when DirectChannelCreateListener fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, OnSessionOpenedInnerTest001, TestSize.Level1)
{
    int32_t result = 0;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, DirectChannelCreateListener).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: OnSessionOpenedInnerTest002
 * @tc.desc: on session opened inner returns error when GetAppInfoById fails for tcp direct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, OnSessionOpenedInnerTest002, TestSize.Level1)
{
    int32_t result = 0;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: OnSessionOpenedInnerTest003
 * @tc.desc: on session opened inner returns error when TransProxyGetAppInfoById fails for proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, OnSessionOpenedInnerTest003, TestSize.Level1)
{
    int32_t result = 0;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, TransProxyGetAppInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: OnSessionOpenedInnerTest004
 * @tc.desc: on session opened inner returns invalid param when InnerAddSession fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, OnSessionOpenedInnerTest004, TestSize.Level1)
{
    int32_t result = 0;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, TransProxyGetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InnerAddSession).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: OnSessionOpenedInnerTest005
 * @tc.desc: on session opened inner returns invalid param when TransInnerAddDataBufNode fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, OnSessionOpenedInnerTest005, TestSize.Level1)
{
    int32_t result = 0;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, TransProxyGetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InnerAddSession).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransInnerAddDataBufNode).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: OnSessionOpenedInnerTest006
 * @tc.desc: on session opened inner returns invalid param when ServerSideSendAck fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, OnSessionOpenedInnerTest006, TestSize.Level1)
{
    int32_t result = 0;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, TransProxyGetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InnerAddSession).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransInnerAddDataBufNode).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ServerSideSendAck).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: OnSessionOpenedInnerTest007
 * @tc.desc: on session opened inner returns ok when all steps succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, OnSessionOpenedInnerTest007, TestSize.Level1)
{
    int32_t result = 0;
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, GetAppInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, TransProxyGetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InnerAddSession).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransInnerAddDataBufNode).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ServerSideSendAck).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = OnSessionOpenedInner(TRANS_TEST_SESSION_ID, const_cast<char *>(NETWORK_ID), result);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnSessionClosedInner(TRANS_TEST_SESSION_ID);
}

/*
 * @tc.name: TransOpenSessionInnerTest001
 * @tc.desc: trans open session inner returns error when TransOpenChannel fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOpenSessionInnerTest001, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, TransOpenChannel).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransOpenSessionInner(SESSION_NAME, const_cast<char *>(NETWORK_ID), TRANS_TEST_REQ_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransOpenSessionInnerTest002
 * @tc.desc: trans open session inner returns ok when TransOpenChannel succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransOpenSessionInnerTest002, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, TransOpenChannel).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransOpenSessionInner(SESSION_NAME, const_cast<char *>(NETWORK_ID), TRANS_TEST_REQ_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransSendDataInnerTest001
 * @tc.desc: trans send data inner returns error when TransSendData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransSendDataInnerTest001, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, TransSendData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransSendDataInner(TRANS_TEST_SESSION_ID, TRANS_TEST_DATA,
        static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransSendDataInnerTest002
 * @tc.desc: trans send data inner returns ok when TransSendData succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransInnerSessionTest, TransSendDataInnerTest002, TestSize.Level1)
{
    NiceMock<TransInnerSessionInterfaceMock> mock;
    EXPECT_CALL(mock, TransSendData).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransSendDataInner(TRANS_TEST_SESSION_ID, TRANS_TEST_DATA,
        static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}
