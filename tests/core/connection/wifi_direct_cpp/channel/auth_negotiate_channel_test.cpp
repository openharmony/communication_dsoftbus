/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>

#include "softbus_error_code.h"
#include "auth_negotiate_channel.h"
#include "wifi_direct_mock.h"
#include "wifi_direct_test_context.h"
#include "conn_log.h"
#include "softbus_utils.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
namespace OHOS::SoftBus {
constexpr int64_t AUTH_SEQ = 1;
class AuthNegotiateChannelTest : public testing::Test {
public:
    static void SetUpTestCase() {
    }
    static void TearDownTestCase() {}
    void SetUp() override
    {
        PrepareContext();
    }
    void TearDown() override
    {
        context_.Reset();
    }

protected:
    void PrepareContext();
    std::shared_ptr<AuthNegotiateChannel> NewAuthNegotiateChannel(WifiDirectInterfaceMock &mock);
    WifiDirectTestContext<TestContextKey> context_;
};

void AuthNegotiateChannelTest::PrepareContext()
{
    context_.Set(TestContextKey::REMOTE_NETWORK_ID, std::string("remote_network_id_0123456789ABCDEFGH"));
    context_.Set(TestContextKey::REMOTE_UUID, std::string("remote_uuid_0123456789ABCDEFGH"));
}

std::shared_ptr<AuthNegotiateChannel> AuthNegotiateChannelTest::NewAuthNegotiateChannel(WifiDirectInterfaceMock &mock)
{
    auto networkId = context_.Get(TestContextKey::REMOTE_NETWORK_ID, std::string(""));
    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    EXPECT_CALL(mock, AuthGetDeviceUuid(_, _, _))
        .WillRepeatedly([this](int64_t authId, char *uuid, uint16_t size) {
            auto id = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));;
            EXPECT_EQ(EOK, strcpy_s(uuid, size, id.c_str()));
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, LnnGetNetworkIdByUuid(deviceId, _, _))
        .WillRepeatedly([this](const std::string &uuid, char *buf, uint32_t len) {
            auto id = context_.Get(TestContextKey::REMOTE_NETWORK_ID, std::string(""));
            EXPECT_EQ(EOK, strcpy_s(buf, len, id.c_str()));
            return SOFTBUS_OK;
        });
    AuthHandle authHandle = { .authId = AUTH_SEQ, .type = AUTH_LINK_TYPE_WIFI };
    return std::make_shared<AuthNegotiateChannel>(authHandle);
}

/*
 * @tc.name: SendMessage
 * @tc.desc: ProtocolType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelTest, SendMessage, TestSize.Level1)
{
    int ret = SOFTBUS_CONN_AUTH_POST_DATA_FAILED;
    NegotiateMessage msg;
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = NewAuthNegotiateChannel(mock);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = true;
            return SOFTBUS_OK;
        });
    ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = false;
            return SOFTBUS_OK;
        });
    ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = true;
            return SOFTBUS_OK;
        });
    ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SendMessageAndWaitResponse_001
 * @tc.desc: SendMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelTest, SendMessageAndWaitResponse_001, TestSize.Level1)
{
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = NewAuthNegotiateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_CONN_AUTH_POST_DATA_FAILED));
    NegotiateMessage msg;
    NegotiateMessage response = channel->SendMessageAndWaitResponse(msg);
    EXPECT_EQ(response.GetMessageType(), NegotiateMessageType::CMD_DETECT_LINK_RSP);
    EXPECT_EQ(response.GetResultCode(), SOFTBUS_CONN_AUTH_POST_DATA_FAILED);
}

/*
 * @tc.name: SendMessageAndWaitResponse_002
 * @tc.desc: SendMessage success, detect response timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelTest, SendMessageAndWaitResponse_002, TestSize.Level1)
{
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = NewAuthNegotiateChannel(mock);
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    NegotiateMessage msg;
    NegotiateMessage response = channel->SendMessageAndWaitResponse(msg);
    EXPECT_EQ(response.GetMessageType(), NegotiateMessageType::CMD_DETECT_LINK_RSP);
    EXPECT_EQ(response.GetResultCode(), SOFTBUS_TIMOUT);
}

/*
 * @tc.name: OpenConnection_001
 * @tc.desc: channel != nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelTest, OpenConnection_001, TestSize.Level1)
{
    AuthNegotiateChannel::OpenParam param;
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = NewAuthNegotiateChannel(mock);
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { 0 };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    uint32_t authReqId = 0;
    auto ret = channel->OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OpenConnection_002
 * @tc.desc: needudid = 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelTest, OpenConnection_002, TestSize.Level1)
{
    AuthNegotiateChannel::OpenParam param;
    param.remoteUuid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00112233";
    const char *udid = "testuuid";
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, AuthGetMetaType(_, _))
        .WillOnce([](int64_t authId, bool *isMetaAuth) {
            *isMetaAuth = true;
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { 0 };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    auto channel = NewAuthNegotiateChannel(mock);
    uint32_t authReqId = 0;
    auto ret = channel->OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OpenConnection_003
 * @tc.desc: needudid = 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelTest, OpenConnection_003, TestSize.Level1)
{
    AuthNegotiateChannel::OpenParam param;
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { 0 };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    auto channel = NewAuthNegotiateChannel(mock);
    uint32_t authReqId = 0;
    auto ret = channel->OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OpenConnection_004
 * @tc.desc: AuthOpenConn return error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelTest, OpenConnection_004, TestSize.Level1)
{
    AuthNegotiateChannel::OpenParam param;
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { 0 };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_INVALID_PARAM;
        });
    auto channel = NewAuthNegotiateChannel(mock);
    uint32_t authReqId = 0;
    auto ret = channel->OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
}