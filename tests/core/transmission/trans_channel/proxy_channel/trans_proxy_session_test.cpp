/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "gtest/gtest.h"
#include "message_handler.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_utils.h"
#include "trans_auth_mock.h"
#include "trans_conn_mock.h"
#include "trans_common_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_CHANNEL_IDENTITY_LEN 33

typedef struct {
    int32_t priority;
    int32_t sliceNum;
    int32_t sliceSeq;
    int32_t reserved;
} TestSliceHead;

class TransProxySessionTest : public testing::Test {
public:
    TransProxySessionTest()
    {}
    ~TransProxySessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

int32_t TestSessionDataReceived(const char *pkgName, int32_t channelId, int32_t channelType,
    const void *data, uint32_t len, int32_t type)
{
    (void)pkgName;
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)len;
    (void)type;
    return SOFTBUS_OK;
}

void TransProxySessionTest::SetUpTestCase(void)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));

    SoftbusConfigInit();
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());

    IServerChannelCallBack callBack;
    callBack.OnDataReceived = TestSessionDataReceived;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnSetConnectCallback).WillRepeatedly(Return(SOFTBUS_OK));
    ASSERT_EQ(SOFTBUS_OK, TransProxyManagerInit(&callBack));
}

void TransProxySessionTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

void TestAddProxyChannel(int32_t channelId, AppType appType, ProxyChannelStatus status)
{
    TransCommInterfaceMock commMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusGenerateRandomArray)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthGetLatestIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_OK));

    AppInfo appInfo;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authId = channelId;
    chan->connId = channelId;
    chan->myId = channelId;
    chan->peerId = channelId;
    chan->reqId = channelId;
    chan->channelId = channelId;
    chan->seq = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, std::to_string(channelId).c_str());
    chan->status = status;
    appInfo.appType = appType;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    ASSERT_TRUE(SOFTBUS_OK == ret);
}

/**
 * @tc.name: TransProxyPostSessionDataTest001
 * @tc.desc: test proxy post session data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyPostSessionDataTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = SOFTBUS_ERR;

    for (uint32_t flags = TRANS_SESSION_BYTES; flags <= TRANS_SESSION_FILE_ACK_RESPONSE_SENT; ++flags) {
        ret = TransProxyPostSessionData(channelId, NULL, 0, (SessionPktType)flags);
        EXPECT_NE(SOFTBUS_OK, ret);
    }

    const char *data = "test data";
    uint32_t len = strlen(data);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyPostSessionDataTest002
 * @tc.desc: test proxy post session data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyPostSessionDataTest002, TestSize.Level1)
{
    int32_t channelId = 50;
    int32_t ret = SOFTBUS_ERR;
    TestAddProxyChannel(channelId, APP_TYPE_AUTH, PROXY_CHANNEL_STATUS_COMPLETED);

    const char *data = "test data";
    uint32_t len = strlen(data);

    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(24));
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillOnce(Return(SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL))
        .WillRepeatedly(Return(SOFTBUS_OK));

    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyPostSessionDataTest003
 * @tc.desc: test proxy post session data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyPostSessionDataTest003, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = 51;
    TestAddProxyChannel(channelId, APP_TYPE_NORMAL, PROXY_CHANNEL_STATUS_COMPLETED);

    const char *data = "test data";
    uint32_t len = strlen(data);

    TransConnInterfaceMock connMock;
    TransCommInterfaceMock commMock;
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(24));
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusEncryptDataWithSeq)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillOnce(DoAll(SetArgPointee<4>(0), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));

    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnNormalMsgReceivedTest001
 * @tc.desc: test proxy on normal msg received.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransOnNormalMsgReceivedTest001, TestSize.Level1)
{
    const char *pkgName = "com.test.trans.proxysession";
    int32_t channelId = -1;
    char buf[100] = {0};
    TestSliceHead head;
    uint32_t len = 10;
    int32_t ret = TransOnNormalMsgReceived(pkgName, channelId, NULL, len);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransOnNormalMsgReceived(pkgName, channelId, buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);
    head.priority  = -1;
    len += 50;
    (void)memcpy_s(buf, 100, &head, sizeof(TestSliceHead));
    ret = TransOnNormalMsgReceived(pkgName, channelId, buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    head.priority  = 3;
    (void)memcpy_s(buf, 100, &head, sizeof(TestSliceHead));
    ret = TransOnNormalMsgReceived(pkgName, channelId, buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);
    head.priority  = 2;
    head.sliceNum = 2;
    head.sliceSeq = 2;
    (void)memcpy_s(buf, 100, &head, sizeof(TestSliceHead));
    ret = TransOnNormalMsgReceived(pkgName, channelId, buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnAuthMsgReceivedTest001
 * @tc.desc: test proxy on auth msg received.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransOnAuthMsgReceivedTest001, TestSize.Level1)
{
    const char *pkgName = "com.test.trans.proxysession";
    int32_t channelId = -1;
    const char * data = "test data";
    int32_t ret = TransOnAuthMsgReceived(pkgName, channelId, NULL, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    uint32_t len = 70 * 1024;
    ret = TransOnAuthMsgReceived(pkgName, channelId, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
    len = 20;
    ret = TransOnAuthMsgReceived(pkgName, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyDelSliceProcessorByChannelIdTest001
 * @tc.desc: test del slice processor by channelId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyDelSliceProcessorByChannelIdTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = TransProxyDelSliceProcessorByChannelId(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

} // namespace OHOS
