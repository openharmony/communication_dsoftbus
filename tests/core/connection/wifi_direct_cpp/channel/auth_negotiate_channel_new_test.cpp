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
#include <cstring>
#include <future>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_negotiate_channel.h"
#include "conn_log.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "wifi_direct_mock.h"
#include "wifi_direct_test_context.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace OHOS::SoftBus {

static constexpr int64_t TEST_AUTH_ID = 100;

class AuthNegotiateChannelNewTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override
    {
        PrepareContext();
    }

    void TearDown() override
    {
        testContext_.Reset();
    }

protected:
    void PrepareContext();
    std::shared_ptr<AuthNegotiateChannel> CreateChannel(WifiDirectInterfaceMock &mock);
    std::shared_ptr<AuthNegotiateChannel> CreateChannelWithEmptyDeviceId(WifiDirectInterfaceMock &mock);
    WifiDirectTestContext<TestContextKey> testContext_;
};

void AuthNegotiateChannelNewTest::PrepareContext()
{
    testContext_.Set(TestContextKey::REMOTE_NETWORK_ID, std::string("test_network_id_0123456789ABCDEFGH"));
    testContext_.Set(TestContextKey::REMOTE_UUID, std::string("test_uuid_0123456789ABCDEFGH"));
}

std::shared_ptr<AuthNegotiateChannel> AuthNegotiateChannelNewTest::CreateChannel(WifiDirectInterfaceMock &mock)
{
    auto deviceId = testContext_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    EXPECT_CALL(mock, AuthGetDeviceUuid(_, _, _)).WillRepeatedly([this](int64_t authId, char *uuid, uint16_t size) {
        auto id = testContext_.Get(TestContextKey::REMOTE_UUID, std::string(""));
        if (strcpy_s(uuid, size, id.c_str()) != EOK) {
            CONN_LOGE(CONN_WIFI_DIRECT, "string copy fail");
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, LnnGetNetworkIdByUuid(deviceId, _, _))
        .WillRepeatedly([this](const std::string &uuid, char *buf, uint32_t len) {
            auto id = testContext_.Get(TestContextKey::REMOTE_NETWORK_ID, std::string(""));
            if (strcpy_s(buf, len, id.c_str()) != EOK) {
                CONN_LOGE(CONN_WIFI_DIRECT, "string copy fail");
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        });
    AuthHandle authHandle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    return std::make_shared<AuthNegotiateChannel>(authHandle);
}

std::shared_ptr<AuthNegotiateChannel> AuthNegotiateChannelNewTest::CreateChannelWithEmptyDeviceId(
    WifiDirectInterfaceMock &mock)
{
    EXPECT_CALL(mock, AuthGetDeviceUuid(_, _, _)).WillRepeatedly([](int64_t authId, char *uuid, uint16_t size) {
        return SOFTBUS_INVALID_PARAM;
    });
    AuthHandle authHandle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    return std::make_shared<AuthNegotiateChannel>(authHandle);
}

/*
 * @tc.name: Constructor_GetDeviceUuidFail
 * @tc.desc: test constructor when AuthGetDeviceUuid fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, Constructor_GetDeviceUuidFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Constructor_GetDeviceUuidFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, AuthGetDeviceUuid(_, _, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    AuthHandle authHandle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    auto channel = std::make_shared<AuthNegotiateChannel>(authHandle);
    EXPECT_TRUE(channel->GetRemoteDeviceId().empty());
    CONN_LOGI(CONN_WIFI_DIRECT, "----Constructor_GetDeviceUuidFail out----");
}

/*
 * @tc.name: Constructor_GetDeviceUuidSuccess
 * @tc.desc: test constructor when AuthGetDeviceUuid succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, Constructor_GetDeviceUuidSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Constructor_GetDeviceUuidSuccess in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_FALSE(channel->GetRemoteDeviceId().empty());
    EXPECT_EQ(channel->GetRemoteDeviceId(), testContext_.Get(TestContextKey::REMOTE_UUID, std::string("")));
    CONN_LOGI(CONN_WIFI_DIRECT, "----Constructor_GetDeviceUuidSuccess out----");
}

/*
 * @tc.name: OperatorEqual_SameAuthHandle
 * @tc.desc: test operator== with same AuthHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OperatorEqual_SameAuthHandle, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OperatorEqual_SameAuthHandle in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel1 = CreateChannel(mock);
    auto channel2 = CreateChannel(mock);
    EXPECT_TRUE(*channel1 == *channel2);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OperatorEqual_SameAuthHandle out----");
}

/*
 * @tc.name: OperatorEqual_SameAuthId_DiffType
 * @tc.desc: test operator== with same authId but different type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OperatorEqual_SameAuthId_DiffType, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OperatorEqual_SameAuthId_DiffType in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel1 = CreateChannel(mock);
    AuthHandle diffHandle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_P2P };
    EXPECT_FALSE(*channel1 == diffHandle);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OperatorEqual_SameAuthId_DiffType out----");
}

/*
 * @tc.name: IsMeta_GetMetaTypeSuccess
 * @tc.desc: test IsMeta when AuthGetMetaType returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, IsMeta_GetMetaTypeSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----IsMeta_GetMetaTypeSuccess in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, AuthGetMetaType(_, _)).WillOnce([](int64_t authId, bool *isMetaAuth) {
        *isMetaAuth = true;
        return SOFTBUS_OK;
    });
    EXPECT_TRUE(channel->IsMeta());
    CONN_LOGI(CONN_WIFI_DIRECT, "----IsMeta_GetMetaTypeSuccess out----");
}

/*
 * @tc.name: IsMeta_GetMetaTypeFail
 * @tc.desc: test IsMeta when AuthGetMetaType fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, IsMeta_GetMetaTypeFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----IsMeta_GetMetaTypeFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, AuthGetMetaType(_, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_FALSE(channel->IsMeta());
    CONN_LOGI(CONN_WIFI_DIRECT, "----IsMeta_GetMetaTypeFail out----");
}

/*
 * @tc.name: IsMeta_ReturnFalse
 * @tc.desc: test IsMeta returns false when not meta
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, IsMeta_ReturnFalse, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----IsMeta_ReturnFalse in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, AuthGetMetaType(_, _)).WillOnce([](int64_t authId, bool *isMetaAuth) {
        *isMetaAuth = false;
        return SOFTBUS_OK;
    });
    EXPECT_FALSE(channel->IsMeta());
    CONN_LOGI(CONN_WIFI_DIRECT, "----IsMeta_ReturnFalse out----");
}

/*
 * @tc.name: SetClose_DestructorCloseConnection
 * @tc.desc: test SetClose and destructor closes connection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, SetClose_DestructorCloseConnection, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SetClose_DestructorCloseConnection in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    bool closeConnCalled = false;
    EXPECT_CALL(mock, AuthCloseConn(_)).WillOnce([&closeConnCalled](AuthHandle handle) {
        closeConnCalled = true;
    });
    {
        auto channel = CreateChannel(mock);
        channel->SetClose();
    }
    EXPECT_TRUE(closeConnCalled);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SetClose_DestructorCloseConnection out----");
}

/*
 * @tc.name: GetAuthHandle_ReturnsCorrectHandle
 * @tc.desc: test GetAuthHandle returns correct AuthHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, GetAuthHandle_ReturnsCorrectHandle, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----GetAuthHandle_ReturnsCorrectHandle in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    AuthHandle handle = channel->GetAuthHandle();
    EXPECT_EQ(handle.authId, TEST_AUTH_ID);
    EXPECT_EQ(handle.type, AUTH_LINK_TYPE_WIFI);
    CONN_LOGI(CONN_WIFI_DIRECT, "----GetAuthHandle_ReturnsCorrectHandle out----");
}

/*
 * @tc.name: GetType_ReturnsAuthChannel
 * @tc.desc: test GetType returns AUTH_CHANNEL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, GetType_ReturnsAuthChannel, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----GetType_ReturnsAuthChannel in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_EQ(channel->GetType(), NegotiateChannelType::AUTH_CHANNEL);
    CONN_LOGI(CONN_WIFI_DIRECT, "----GetType_ReturnsAuthChannel out----");
}

/*
 * @tc.name: SendMessage_LocalNotSupportTlv
 * @tc.desc: test SendMessage when local does not support TLV
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, SendMessage_LocalNotSupportTlv, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_LocalNotSupportTlv in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_LocalNotSupportTlv out----");
}

/*
 * @tc.name: SendMessage_RemoteNotSupportTlv
 * @tc.desc: test SendMessage when remote does not support TLV
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, SendMessage_RemoteNotSupportTlv, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_RemoteNotSupportTlv in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([](const std::string &networkId, InfoKey key, bool *info) {
            *info = false;
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_RemoteNotSupportTlv out----");
}

/*
 * @tc.name: SendMessage_BothSupportTlv
 * @tc.desc: test SendMessage when both support TLV
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, SendMessage_BothSupportTlv, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_BothSupportTlv in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([](const std::string &networkId, InfoKey key, bool *info) {
            *info = true;
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_BothSupportTlv out----");
}

/*
 * @tc.name: SendMessage_EmptyRemoteDeviceId
 * @tc.desc: test SendMessage with empty remote device id uses TLV
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, SendMessage_EmptyRemoteDeviceId, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_EmptyRemoteDeviceId in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannelWithEmptyDeviceId(mock);
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_EmptyRemoteDeviceId out----");
}

/*
 * @tc.name: SendMessage_PostDataFail
 * @tc.desc: test SendMessage when AuthPostTransData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, SendMessage_PostDataFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_PostDataFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_CONN_AUTH_POST_DATA_FAILED);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_PostDataFail out----");
}

/*
 * @tc.name: SendMessageAndWaitResponse_SendFail
 * @tc.desc: test SendMessageAndWaitResponse when SendMessage fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, SendMessageAndWaitResponse_SendFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessageAndWaitResponse_SendFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_CONN_AUTH_POST_DATA_FAILED));
    NegotiateMessage msg;
    NegotiateMessage response = channel->SendMessageAndWaitResponse(msg);
    EXPECT_EQ(response.GetMessageType(), NegotiateMessageType::CMD_DETECT_LINK_RSP);
    EXPECT_EQ(response.GetResultCode(), SOFTBUS_CONN_AUTH_POST_DATA_FAILED);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessageAndWaitResponse_SendFail out----");
}

/*
 * @tc.name: SendMessageAndWaitResponse_Timeout
 * @tc.desc: test SendMessageAndWaitResponse times out
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, SendMessageAndWaitResponse_Timeout, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessageAndWaitResponse_Timeout in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    NegotiateMessage msg;
    NegotiateMessage response = channel->SendMessageAndWaitResponse(msg);
    EXPECT_EQ(response.GetMessageType(), NegotiateMessageType::CMD_DETECT_LINK_RSP);
    EXPECT_EQ(response.GetResultCode(), SOFTBUS_TIMOUT);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessageAndWaitResponse_Timeout out----");
}

/*
 * @tc.name: OpenConnection_NullChannel
 * @tc.desc: test OpenConnection with null channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_NullChannel, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_NullChannel in----");
    AuthNegotiateChannel::OpenParam param;
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, nullptr, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_NullChannel out----");
}

/*
 * @tc.name: OpenConnection_WithValidChannel
 * @tc.desc: test OpenConnection with valid channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_WithValidChannel, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_WithValidChannel in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    EXPECT_CALL(mock, AuthGetMetaType(_, _)).WillOnce([](int64_t authId, bool *isMetaAuth) {
        *isMetaAuth = false;
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_WithValidChannel out----");
}

/*
 * @tc.name: OpenConnection_ShortUuid_NoUdid
 * @tc.desc: test OpenConnection with short uuid does not need udid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_ShortUuid_NoUdid, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_ShortUuid_NoUdid in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.remoteUuid = "short_uuid";
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_ShortUuid_NoUdid out----");
}

/*
 * @tc.name: OpenConnection_LongUuid_NeedUdid
 * @tc.desc: test OpenConnection with long uuid needs udid conversion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_LongUuid_NeedUdid, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_LongUuid_NeedUdid in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    AuthNegotiateChannel::OpenParam param;
    param.remoteUuid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00112233";
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    EXPECT_CALL(mock, AuthGetMetaType(_, _)).WillOnce([](int64_t authId, bool *isMetaAuth) {
        *isMetaAuth = false;
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, LnnConvertDLidToUdid(_, _, _, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    auto channel = CreateChannel(mock);
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_LongUuid_NeedUdid out----");
}

/*
 * @tc.name: OpenConnection_LnnConvertFail
 * @tc.desc: test OpenConnection when LnnConvertDLidToUdid fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_LnnConvertFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_LnnConvertFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    AuthNegotiateChannel::OpenParam param;
    param.remoteUuid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00112233";
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    EXPECT_CALL(mock, AuthGetMetaType(_, _)).WillOnce([](int64_t authId, bool *isMetaAuth) {
        *isMetaAuth = false;
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, LnnConvertDLidToUdid(_, _, _, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    auto channel = CreateChannel(mock);
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_CONN_OPEN_CONNECTION_GET_REMOTE_UUID_FAILED);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_LnnConvertFail out----");
}

/*
 * @tc.name: OpenConnection_AuthOpenConnFail
 * @tc.desc: test OpenConnection when AuthOpenConn fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_AuthOpenConnFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_AuthOpenConnFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _)).WillOnce(Return(SOFTBUS_CONN_AUTH_POST_DATA_FAILED));
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_CONN_AUTH_POST_DATA_FAILED);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_AuthOpenConnFail out----");
}

/*
 * @tc.name: OpenConnection_OnConnOpenFailed
 * @tc.desc: test OpenConnection callback onConnOpenFailed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_OnConnOpenFailed, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_OnConnOpenFailed in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            callback->onConnOpenFailed(requestId, SOFTBUS_CONN_AUTH_POST_DATA_FAILED);
            return SOFTBUS_OK;
        });
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_OnConnOpenFailed out----");
}

/*
 * @tc.name: OpenConnection_MetaChannel_P2pLink_NoUdid
 * @tc.desc: test OpenConnection with meta channel and P2P link type does not need udid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_MetaChannel_P2pLink_NoUdid, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_MetaChannel_P2pLink_NoUdid in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    AuthNegotiateChannel::OpenParam param;
    param.type = AUTH_LINK_TYPE_P2P;
    param.remoteUuid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00112233";
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    EXPECT_CALL(mock, AuthGetMetaType(_, _)).WillOnce([](int64_t authId, bool *isMetaAuth) {
        *isMetaAuth = true;
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_P2P };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    auto channel = CreateChannel(mock);
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, channel, authReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_MetaChannel_P2pLink_NoUdid out----");
}

/*
 * @tc.name: OpenConnection_WithPromise
 * @tc.desc: test OpenConnection with promise parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, OpenConnection_WithPromise, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_WithPromise in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    auto promise = std::make_shared<std::promise<AuthOpenEvent>>();
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, channel, authReqId, promise);
    EXPECT_EQ(ret, SOFTBUS_OK);
    auto event = promise->get_future().get();
    EXPECT_EQ(event.reason_, SOFTBUS_OK);
    EXPECT_EQ(event.handle_.authId, TEST_AUTH_ID);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OpenConnection_WithPromise out----");
}

/*
 * @tc.name: StartListening_Success
 * @tc.desc: test StartListening succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, StartListening_Success, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----StartListening_Success in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, AuthStartListeningForWifiDirect(_, _, _, _))
        .WillOnce([](AuthLinkType type, const char *ip, int32_t port, ListenerModule *moduleId) {
            *moduleId = static_cast<ListenerModule>(1);
            return 5000;
        });
    auto result = AuthNegotiateChannel::StartListening(AUTH_LINK_TYPE_WIFI, "192.168.1.1", 0);
    EXPECT_EQ(result.first, 5000);
    EXPECT_EQ(result.second, static_cast<ListenerModule>(1));
    CONN_LOGI(CONN_WIFI_DIRECT, "----StartListening_Success out----");
}

/*
 * @tc.name: StopListening_Success
 * @tc.desc: test StopListening calls underlying function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, StopListening_Success, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----StopListening_Success in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    bool stopCalled = false;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect(_, _))
        .WillOnce([&stopCalled](AuthLinkType type, ListenerModule moduleId) {
            stopCalled = true;
        });
    AuthNegotiateChannel::StopListening(AUTH_LINK_TYPE_WIFI, static_cast<ListenerModule>(1));
    EXPECT_TRUE(stopCalled);
    CONN_LOGI(CONN_WIFI_DIRECT, "----StopListening_Success out----");
}

/*
 * @tc.name: AssignValueForAuthConnInfo_Success
 * @tc.desc: test AssignValueForAuthConnInfo with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, AssignValueForAuthConnInfo_Success, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignValueForAuthConnInfo_Success in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.type = AUTH_LINK_TYPE_WIFI;
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    param.module = static_cast<ListenerModule>(1);
    AuthConnInfo authConnInfo = {};
    int ret = AuthNegotiateChannel::AssignValueForAuthConnInfo(false, false, param, channel, authConnInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(authConnInfo.type, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(authConnInfo.info.ipInfo.port, 8080);
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignValueForAuthConnInfo_Success out----");
}

/*
 * @tc.name: AssignValueForAuthConnInfo_MetaWithChannel
 * @tc.desc: test AssignValueForAuthConnInfo with meta and valid channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, AssignValueForAuthConnInfo_MetaWithChannel, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignValueForAuthConnInfo_MetaWithChannel in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.type = AUTH_LINK_TYPE_WIFI;
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    param.module = static_cast<ListenerModule>(1);
    AuthConnInfo authConnInfo = {};
    int ret = AuthNegotiateChannel::AssignValueForAuthConnInfo(true, false, param, channel, authConnInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(authConnInfo.info.ipInfo.authId, TEST_AUTH_ID);
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignValueForAuthConnInfo_MetaWithChannel out----");
}

/*
 * @tc.name: AssignValueForAuthConnInfo_NeedUdidSuccess
 * @tc.desc: test AssignValueForAuthConnInfo with udid conversion success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, AssignValueForAuthConnInfo_NeedUdidSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignValueForAuthConnInfo_NeedUdidSuccess in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, LnnConvertDLidToUdid(_, _, _, _))
        .WillOnce([](const char *id, IdCategory type, char *udid, uint32_t len) {
            EXPECT_EQ(EOK, strcpy_s(udid, len, "test_udid"));
            return SOFTBUS_OK;
        });
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.type = AUTH_LINK_TYPE_WIFI;
    param.remoteUuid = "test_uuid";
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    param.module = static_cast<ListenerModule>(1);
    AuthConnInfo authConnInfo = {};
    int ret = AuthNegotiateChannel::AssignValueForAuthConnInfo(false, true, param, channel, authConnInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignValueForAuthConnInfo_NeedUdidSuccess out----");
}

/*
 * @tc.name: AssignValueForAuthConnInfo_NeedUdidFail
 * @tc.desc: test AssignValueForAuthConnInfo with udid conversion failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, AssignValueForAuthConnInfo_NeedUdidFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignValueForAuthConnInfo_NeedUdidFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, LnnConvertDLidToUdid(_, _, _, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    auto channel = CreateChannel(mock);
    AuthNegotiateChannel::OpenParam param;
    param.type = AUTH_LINK_TYPE_WIFI;
    param.remoteUuid = "test_uuid";
    param.remoteIp = "192.168.1.1";
    param.remotePort = 8080;
    param.module = static_cast<ListenerModule>(1);
    AuthConnInfo authConnInfo = {};
    int ret = AuthNegotiateChannel::AssignValueForAuthConnInfo(false, true, param, channel, authConnInfo);
    EXPECT_EQ(ret, SOFTBUS_CONN_OPEN_CONNECTION_GET_REMOTE_UUID_FAILED);
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignValueForAuthConnInfo_NeedUdidFail out----");
}

/*
 * @tc.name: Register_SyncDBACDataHook
 * @tc.desc: test Register and SyncDBACData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNegotiateChannelNewTest, Register_SyncDBACDataHook, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Register_SyncDBACDataHook in----");
    bool hookCalled = false;
    std::vector<uint8_t> receivedData;
    AuthNegotiateChannel::Register([&hookCalled, &receivedData](const std::vector<uint8_t> &data) {
        hookCalled = true;
        receivedData = data;
    });
    std::vector<uint8_t> testData = { 0x01, 0x02, 0x03 };
    AuthNegotiateChannel::SyncDBACData(testData);
    EXPECT_TRUE(hookCalled);
    EXPECT_EQ(receivedData, testData);
    CONN_LOGI(CONN_WIFI_DIRECT, "----Register_SyncDBACDataHook out----");
}
} // namespace OHOS::SoftBus
