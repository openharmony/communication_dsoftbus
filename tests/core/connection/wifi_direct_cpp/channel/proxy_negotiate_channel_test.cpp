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
#include "proxy_negotiate_channel.h"
#include "wifi_direct_mock.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_executor.h"
#include "wifi_direct_scheduler.h"
#include "negotiate_command.h"
using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
namespace OHOS::SoftBus {
int32_t CID = 123;
const int32_t DELAY_TIME = 100;
class ProxyNegotiateChannelTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
protected:
    std::shared_ptr<CoCProxyNegotiateChannel> NewCoCProxyNegotiateChannel(WifiDirectInterfaceMock &mock);
};

std::shared_ptr<CoCProxyNegotiateChannel> ProxyNegotiateChannelTest::NewCoCProxyNegotiateChannel(
    WifiDirectInterfaceMock &mock)
{
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(_, _, _))
        .WillRepeatedly([this](int32_t channelId, char *uuid, uint32_t uuidLen) {
            std::string id = "uuid_0123456789ABCDEFGH";
            EXPECT_EQ(EOK, strcpy_s(uuid, UUID_BUF_LEN, id.c_str()));
            return SOFTBUS_OK;
        });
    auto channel = std::make_shared<CoCProxyNegotiateChannel>(CID);
    EXPECT_EQ(channel->GetRemoteDeviceId(), "uuid_0123456789ABCDEFGH");
    return channel;
}

/*
* @tc.name: CoCProxyNegotiateChannel
* @tc.desc: auth get uuid failed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProxyNegotiateChannelTest, CoCProxyNegotiateChannel, TestSize.Level1)
{
    NiceMock<WifiDirectInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPipelineGetUuidByChannelId(_, _, _))
        .WillRepeatedly([this](int32_t channelId, char *uuid, uint32_t uuidLen) {
            std::string id = "uuid_0123456789ABCDEFGH";
            EXPECT_EQ(EOK, strcpy_s(uuid, UUID_BUF_LEN, id.c_str()));
            return SOFTBUS_NOT_FIND;
        });
    std::shared_ptr<OHOS::SoftBus::CoCProxyNegotiateChannel> testInst = std::make_shared<CoCProxyNegotiateChannel>(CID);
    EXPECT_NE(testInst->GetRemoteDeviceId(), "uuid_0123456789ABCDEFGH");
}

/*
* @tc.name: onDataReceived
* @tc.desc: json/tlv branch test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProxyNegotiateChannelTest, onDataReceived, TestSize.Level1)
{
    NiceMock<WifiDirectInterfaceMock> mock;
    int ret = SOFTBUS_INVALID_PARAM;
    const char *testData = "test:123";
    auto channel = NewCoCProxyNegotiateChannel(mock);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = true;
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, TransProxyPipelineRegisterListener(_, _))
        .WillRepeatedly([testData](TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener) {
            listener->onDataReceived(CID, testData, strlen(testData));
            return SOFTBUS_OK;
        });
    ret = channel->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = false;
            return SOFTBUS_OK;
        });
    ret = channel->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = true;
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, TransProxyPipelineRegisterListener(_, _))
        .WillRepeatedly([testData](TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener) {
            listener->onDataReceived(CID, testData, strlen(testData));
            return SOFTBUS_OK;
        });
    ret = channel->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: SendMessage
* @tc.desc: json/tlv branch test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProxyNegotiateChannelTest, SendMessage, TestSize.Level1)
{
    NiceMock<WifiDirectInterfaceMock> mock;
    NegotiateMessage msg;
    int ret = SOFTBUS_INVALID_PARAM;
    auto channel = NewCoCProxyNegotiateChannel(mock);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = true;
            return SOFTBUS_OK;
        });
    ret = channel->SendMessage(msg);
    SoftBusSleepMs(DELAY_TIME);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = false;
            return SOFTBUS_OK;
        });
    ret = channel->SendMessage(msg);
    SoftBusSleepMs(DELAY_TIME);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, bool *info) {
            *info = true;
            return SOFTBUS_OK;
        });
    ret = channel->SendMessage(msg);
    SoftBusSleepMs(DELAY_TIME);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
}
