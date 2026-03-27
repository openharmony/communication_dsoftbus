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
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "negotiate_command.h"
#include "proxy_negotiate_channel.h"
#include "softbus_error_code.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_executor.h"
#include "wifi_direct_mock.h"
#include "wifi_direct_scheduler.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace OHOS::SoftBus {

static constexpr int32_t TEST_CHANNEL_ID = 1001;
static constexpr int32_t TEST_CHANNEL_ID_SECONDARY = 2002;
static constexpr const char *TEST_UUID = "test_uuid_0123456789ABCDEFGH";

class ProxyNegotiateChannelNewTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override { }

    void TearDown() override { }

protected:
    std::shared_ptr<CoCProxyNegotiateChannel> CreateChannel(WifiDirectInterfaceMock &mock);
    std::shared_ptr<CoCProxyNegotiateChannel> CreateChannelWithEmptyUuid(WifiDirectInterfaceMock &mock);
};

std::shared_ptr<CoCProxyNegotiateChannel> ProxyNegotiateChannelNewTest::CreateChannel(WifiDirectInterfaceMock &mock)
{
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(TEST_CHANNEL_ID, _, _))
        .WillRepeatedly([](int32_t channelId, char *uuid, uint32_t uuidLen) {
            EXPECT_EQ(EOK, strcpy_s(uuid, UUID_BUF_LEN, TEST_UUID));
            return SOFTBUS_OK;
        });
    return std::make_shared<CoCProxyNegotiateChannel>(TEST_CHANNEL_ID);
}

std::shared_ptr<CoCProxyNegotiateChannel> ProxyNegotiateChannelNewTest::CreateChannelWithEmptyUuid(
    WifiDirectInterfaceMock &mock)
{
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(_, _, _))
        .WillRepeatedly([](int32_t channelId, char *uuid, uint32_t uuidLen) {
            return SOFTBUS_NOT_FIND;
        });
    return std::make_shared<CoCProxyNegotiateChannel>(TEST_CHANNEL_ID);
}

/*
 * @tc.name: Constructor_GetUuidSuccess
 * @tc.desc: test constructor when GetUuidByChannelId succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, Constructor_GetUuidSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Constructor_GetUuidSuccess in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_EQ(channel->GetRemoteDeviceId(), TEST_UUID);
    CONN_LOGI(CONN_WIFI_DIRECT, "----Constructor_GetUuidSuccess out----");
}

/*
 * @tc.name: Constructor_GetUuidFail
 * @tc.desc: test constructor when GetUuidByChannelId fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, Constructor_GetUuidFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Constructor_GetUuidFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannelWithEmptyUuid(mock);
    EXPECT_TRUE(channel->GetRemoteDeviceId().empty());
    CONN_LOGI(CONN_WIFI_DIRECT, "----Constructor_GetUuidFail out----");
}

/*
 * @tc.name: CopyConstructor_Success
 * @tc.desc: test copy constructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, CopyConstructor_Success, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----CopyConstructor_Success in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel1 = CreateChannel(mock);
    CoCProxyNegotiateChannel channel2(*channel1);
    EXPECT_EQ(channel2.GetRemoteDeviceId(), TEST_UUID);
    CONN_LOGI(CONN_WIFI_DIRECT, "----CopyConstructor_Success out----");
}

/*
 * @tc.name: AssignmentOperator_Success
 * @tc.desc: test assignment operator
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, AssignmentOperator_Success, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignmentOperator_Success in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel1 = CreateChannel(mock);
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(TEST_CHANNEL_ID_SECONDARY, _, _))
        .WillRepeatedly([](int32_t channelId, char *uuid, uint32_t uuidLen) {
            EXPECT_EQ(EOK, strcpy_s(uuid, UUID_BUF_LEN, "other_uuid"));
            return SOFTBUS_OK;
        });
    CoCProxyNegotiateChannel channel2(TEST_CHANNEL_ID_SECONDARY);
    channel2 = *channel1;
    EXPECT_EQ(channel2.GetRemoteDeviceId(), TEST_UUID);
    CONN_LOGI(CONN_WIFI_DIRECT, "----AssignmentOperator_Success out----");
}

/*
 * @tc.name: OperatorEqual_SameChannelId
 * @tc.desc: test operator== with same channel id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, OperatorEqual_SameChannelId, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OperatorEqual_SameChannelId in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel1 = CreateChannel(mock);
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(TEST_CHANNEL_ID, _, _))
        .WillRepeatedly([](int32_t channelId, char *uuid, uint32_t uuidLen) {
            EXPECT_EQ(EOK, strcpy_s(uuid, UUID_BUF_LEN, TEST_UUID));
            return SOFTBUS_OK;
        });
    auto channel2 = std::make_shared<CoCProxyNegotiateChannel>(TEST_CHANNEL_ID);
    EXPECT_TRUE(*channel1 == *channel2);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OperatorEqual_SameChannelId out----");
}

/*
 * @tc.name: OperatorEqual_DifferentChannelId
 * @tc.desc: test operator== with different channel id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, OperatorEqual_DifferentChannelId, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OperatorEqual_DifferentChannelId in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel1 = CreateChannel(mock);
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(TEST_CHANNEL_ID_SECONDARY, _, _))
        .WillRepeatedly([](int32_t channelId, char *uuid, uint32_t uuidLen) {
            EXPECT_EQ(EOK, strcpy_s(uuid, UUID_BUF_LEN, TEST_UUID));
            return SOFTBUS_OK;
        });
    auto channel2 = std::make_shared<CoCProxyNegotiateChannel>(TEST_CHANNEL_ID_SECONDARY);
    EXPECT_FALSE(*channel1 == *channel2);
    CONN_LOGI(CONN_WIFI_DIRECT, "----OperatorEqual_DifferentChannelId out----");
}

/*
 * @tc.name: GetRemoteDeviceId_ValidUuid
 * @tc.desc: test GetRemoteDeviceId returns valid uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, GetRemoteDeviceId_ValidUuid, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----GetRemoteDeviceId_ValidUuid in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_EQ(channel->GetRemoteDeviceId(), TEST_UUID);
    CONN_LOGI(CONN_WIFI_DIRECT, "----GetRemoteDeviceId_ValidUuid out----");
}

/*
 * @tc.name: GetRemoteDeviceId_EmptyUuid
 * @tc.desc: test GetRemoteDeviceId returns empty when uuid retrieval fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, GetRemoteDeviceId_EmptyUuid, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----GetRemoteDeviceId_EmptyUuid in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannelWithEmptyUuid(mock);
    EXPECT_TRUE(channel->GetRemoteDeviceId().empty());
    CONN_LOGI(CONN_WIFI_DIRECT, "----GetRemoteDeviceId_EmptyUuid out----");
}

/*
 * @tc.name: Init_RegisterListenerSuccess
 * @tc.desc: test Init registers listener successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, Init_RegisterListenerSuccess, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Init_RegisterListenerSuccess in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPipelineRegisterListener(_, _)).WillOnce(Return(SOFTBUS_OK));
    int ret = CoCProxyNegotiateChannel::Init();
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----Init_RegisterListenerSuccess out----");
}

/*
 * @tc.name: Init_RegisterListenerFail
 * @tc.desc: test Init returns error when registration fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, Init_RegisterListenerFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Init_RegisterListenerFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPipelineRegisterListener(_, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int ret = CoCProxyNegotiateChannel::Init();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_WIFI_DIRECT, "----Init_RegisterListenerFail out----");
}

/*
 * @tc.name: SendMessage_LocalNotSupportTlv
 * @tc.desc: test SendMessage when local does not support TLV
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, SendMessage_LocalNotSupportTlv, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_LocalNotSupportTlv in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, TransProxyPipelineSendMessage(_, _, _, _)).WillOnce(Return(SOFTBUS_OK));
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
HWTEST_F(ProxyNegotiateChannelNewTest, SendMessage_RemoteNotSupportTlv, TestSize.Level1)
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
    EXPECT_CALL(mock, TransProxyPipelineSendMessage(_, _, _, _)).WillOnce(Return(SOFTBUS_OK));
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
HWTEST_F(ProxyNegotiateChannelNewTest, SendMessage_BothSupportTlv, TestSize.Level1)
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
    EXPECT_CALL(mock, TransProxyPipelineSendMessage(_, _, _, _)).WillOnce(Return(SOFTBUS_OK));
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_BothSupportTlv out----");
}

/*
 * @tc.name: SendMessage_PipelineSendFail
 * @tc.desc: test SendMessage when TransProxyPipelineSendMessage fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, SendMessage_PipelineSendFail, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_PipelineSendFail in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, TransProxyPipelineSendMessage(_, _, _, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_PipelineSendFail out----");
}

/*
 * @tc.name: SendMessage_VerifyChannelIdInCall
 * @tc.desc: test SendMessage passes correct channel id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, SendMessage_VerifyChannelIdInCall, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_VerifyChannelIdInCall in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    int32_t capturedChannelId = 0;
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, TransProxyPipelineSendMessage(_, _, _, _))
        .WillOnce([&capturedChannelId](
                      int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type) {
            capturedChannelId = channelId;
            return SOFTBUS_OK;
        });
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(capturedChannelId, TEST_CHANNEL_ID);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_VerifyChannelIdInCall out----");
}

/*
 * @tc.name: SendMessage_VerifyMsgType
 * @tc.desc: test SendMessage passes correct message type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, SendMessage_VerifyMsgType, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_VerifyMsgType in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    TransProxyPipelineMsgType capturedMsgType = MSG_TYPE_CNT;
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, TransProxyPipelineSendMessage(_, _, _, _))
        .WillOnce([&capturedMsgType](
                      int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type) {
            capturedMsgType = type;
            return SOFTBUS_OK;
        });
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(capturedMsgType, MSG_TYPE_P2P_NEGO);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_VerifyMsgType out----");
}

/*
 * @tc.name: OnDisconnected_CallbackRegistered
 * @tc.desc: test onDisconnected callback is registered and callable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, OnDisconnected_CallbackRegistered, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----OnDisconnected_CallbackRegistered in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    ITransProxyPipelineListener capturedListener = {};
    bool listenerCaptured = false;
    EXPECT_CALL(mock, TransProxyPipelineRegisterListener(_, _))
        .WillOnce([&capturedListener, &listenerCaptured](
                      TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener) {
            capturedListener = *listener;
            listenerCaptured = true;
            return SOFTBUS_OK;
        });
    int ret = CoCProxyNegotiateChannel::Init();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(listenerCaptured);
    EXPECT_NE(capturedListener.onDisconnected, nullptr);
    EXPECT_NO_FATAL_FAILURE(capturedListener.onDisconnected(TEST_CHANNEL_ID));
    CONN_LOGI(CONN_WIFI_DIRECT, "----OnDisconnected_CallbackRegistered out----");
}

/*
 * @tc.name: Destructor_ChannelDestroyed
 * @tc.desc: test destructor properly destroys channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, Destructor_ChannelDestroyed, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Destructor_ChannelDestroyed in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    std::string remoteDeviceId;
    {
        auto channel = CreateChannel(mock);
        remoteDeviceId = channel->GetRemoteDeviceId();
        EXPECT_FALSE(remoteDeviceId.empty());
        EXPECT_EQ(remoteDeviceId, TEST_UUID);
    }
    EXPECT_EQ(remoteDeviceId, TEST_UUID);
    CONN_LOGI(CONN_WIFI_DIRECT, "----Destructor_ChannelDestroyed out----");
}

/*
 * @tc.name: MultipleChannels_IndependentState
 * @tc.desc: test multiple channels have independent state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, MultipleChannels_IndependentState, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----MultipleChannels_IndependentState in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(TEST_CHANNEL_ID, _, _))
        .WillRepeatedly([](int32_t channelId, char *uuid, uint32_t uuidLen) {
            EXPECT_EQ(EOK, strcpy_s(uuid, UUID_BUF_LEN, "uuid_channel_1"));
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(TEST_CHANNEL_ID_SECONDARY, _, _))
        .WillRepeatedly([](int32_t channelId, char *uuid, uint32_t uuidLen) {
            EXPECT_EQ(EOK, strcpy_s(uuid, UUID_BUF_LEN, "uuid_channel_2"));
            return SOFTBUS_OK;
        });
    auto channel1 = std::make_shared<CoCProxyNegotiateChannel>(TEST_CHANNEL_ID);
    auto channel2 = std::make_shared<CoCProxyNegotiateChannel>(TEST_CHANNEL_ID_SECONDARY);
    EXPECT_EQ(channel1->GetRemoteDeviceId(), "uuid_channel_1");
    EXPECT_EQ(channel2->GetRemoteDeviceId(), "uuid_channel_2");
    EXPECT_FALSE(*channel1 == *channel2);
    CONN_LOGI(CONN_WIFI_DIRECT, "----MultipleChannels_IndependentState out----");
}

/*
 * @tc.name: SendMessage_VerifyDataNotEmpty
 * @tc.desc: test SendMessage sends non-empty data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, SendMessage_VerifyDataNotEmpty, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_VerifyDataNotEmpty in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    auto channel = CreateChannel(mock);
    uint32_t capturedDataLen = 0;
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, TransProxyPipelineSendMessage(_, _, _, _))
        .WillOnce([&capturedDataLen](
                      int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type) {
            capturedDataLen = dataLen;
            EXPECT_NE(data, nullptr);
            return SOFTBUS_OK;
        });
    NegotiateMessage msg;
    int ret = channel->SendMessage(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(capturedDataLen, 0u);
    CONN_LOGI(CONN_WIFI_DIRECT, "----SendMessage_VerifyDataNotEmpty out----");
}

/*
 * @tc.name: Init_VerifyMsgType
 * @tc.desc: test Init registers with correct message type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, Init_VerifyMsgType, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Init_VerifyMsgType in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    TransProxyPipelineMsgType capturedMsgType = MSG_TYPE_CNT;
    EXPECT_CALL(mock, TransProxyPipelineRegisterListener(_, _))
        .WillOnce([&capturedMsgType](TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener) {
            capturedMsgType = type;
            return SOFTBUS_OK;
        });
    int ret = CoCProxyNegotiateChannel::Init();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(capturedMsgType, MSG_TYPE_P2P_NEGO);
    CONN_LOGI(CONN_WIFI_DIRECT, "----Init_VerifyMsgType out----");
}

/*
 * @tc.name: Init_ListenerNotNull
 * @tc.desc: test Init registers non-null listener callbacks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyNegotiateChannelNewTest, Init_ListenerNotNull, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "----Init_ListenerNotNull in----");
    NiceMock<WifiDirectInterfaceMock> mock;
    const ITransProxyPipelineListener *capturedListener = nullptr;
    EXPECT_CALL(mock, TransProxyPipelineRegisterListener(_, _))
        .WillOnce([&capturedListener](TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener) {
            capturedListener = listener;
            return SOFTBUS_OK;
        });
    int ret = CoCProxyNegotiateChannel::Init();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NE(capturedListener, nullptr);
    EXPECT_NE(capturedListener->onDisconnected, nullptr);
    CONN_LOGI(CONN_WIFI_DIRECT, "----Init_ListenerNotNull out----");
}
} // namespace OHOS::SoftBus
