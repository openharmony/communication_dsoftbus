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

#include "auth_interface.h"
#include "conn_log.h"
#include "data/negotiate_message.h"
#include "dfx/duration_statistic.h"
#include "dfx/wifi_direct_dfx.h"
#include "wifi_direct_mock.h"
#include "wifi_direct_types.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS::SoftBus {
class WifiDirectDfxTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: ReportConnEventExtraTest
 * @tc.desc: check BytesToInt method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectDfxTest, ReportConnEventExtraTest, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ReportConnEventExtraTest in");
    WifiDirectInterfaceMock wifiDirectInterfaceMock;
    EXPECT_CALL(wifiDirectInterfaceMock, LnnSetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    bool result = false;
    int32_t reason = SOFTBUS_CONN_FAIL;
    int32_t requestId = 0;
    uint16_t challengeCode = 0;
    WifiDirectConnectInfo wifiDirectConnectInfo = { 0 };
    wifiDirectConnectInfo.dfxInfo.linkType = STATISTIC_HML;
    DurationStatistic::GetInstance().Record(requestId, TOTAL_START);
    WifiDirectDfx::GetInstance().Record(requestId, challengeCode);
    sleep(1);
    DurationStatistic::GetInstance().Record(requestId, TOTAL_END);
    WifiDirectDfx::GetInstance().SetVirtualLinkType(requestId, STATISTIC_LINK_VIRTUAL_TO_REAL);
    WifiDirectDfx::GetInstance().SetVirtualLinkType(requestId, STATISTIC_LINK_VIRTUAL);
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_SPARKLINK_TRIGGER_HML;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = static_cast<WifiDirectConnectType>(-1);
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    CONN_LOGI(CONN_WIFI_DIRECT, "ReportConnEventExtraTest out");
}

/*
 * @tc.name: SetBootLinkTypeTest
 * @tc.desc: test set boot link type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectDfxTest, SetBootLinkTypeTest, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "SetBootLinkTypeTest in");
    WifiDirectInterfaceMock wifiDirectInterfaceMock;
    EXPECT_CALL(wifiDirectInterfaceMock, LnnSetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    bool result = false;
    int32_t reason = SOFTBUS_CONN_FAIL;
    WifiDirectConnectInfo wifiDirectConnectInfo = { 0 };
    wifiDirectConnectInfo.negoChannel.type = NEGO_CHANNEL_NULL;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_SPARKLINK_TRIGGER_HML;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.negoChannel.type = NEGO_CHANNEL_AUTH;
    wifiDirectConnectInfo.negoChannel.handle.authHandle.type = 1;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.negoChannel.type = NEGO_CHANNEL_AUTH;
    wifiDirectConnectInfo.negoChannel.handle.authHandle.type = 2;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.negoChannel.type = NEGO_CHANNEL_AUTH;
    wifiDirectConnectInfo.negoChannel.handle.authHandle.type = 3;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.negoChannel.type = NEGO_CHANNEL_AUTH;
    wifiDirectConnectInfo.negoChannel.handle.authHandle.type = 4;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.negoChannel.type = NEGO_CHANNEL_COC;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.negoChannel.type = NEGO_CHANNEL_ACTION;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.dfxInfo.bootLinkType = STATISTIC_BLE_AND_ACTION;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    CONN_LOGI(CONN_WIFI_DIRECT, "SetBootLinkTypeTest out");
}

/*
 * @tc.name: ReportReceiveAuthLinkMsgTest
 * @tc.desc: check BytesToInt method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectDfxTest, ReportReceiveAuthLinkMsgTest, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ReportReceiveAuthLinkMsgTest in");
    WifiDirectInterfaceMock wifiDirectInterfaceMock;
    EXPECT_CALL(wifiDirectInterfaceMock, LnnSetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    std::string remoteDeviceId = "test";
    NegotiateMessage negotiateMessage;
    negotiateMessage.SetChallengeCode(0);
    negotiateMessage.SetSessionId(0);
    negotiateMessage.SetMessageType(NegotiateMessageType::CMD_TRIGGER_REQ);
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::ReportReceiveAuthLinkMsg(negotiateMessage, remoteDeviceId));
    negotiateMessage.SetMessageType(NegotiateMessageType::CMD_CONN_V2_REQ_3);
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::ReportReceiveAuthLinkMsg(negotiateMessage, remoteDeviceId));
    negotiateMessage.SetMessageType(NegotiateMessageType::CMD_CONN_V2_REQ_1);
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::ReportReceiveAuthLinkMsg(negotiateMessage, remoteDeviceId));
    CONN_LOGI(CONN_WIFI_DIRECT, "ReportReceiveAuthLinkMsgTest out");
}
} // namespace OHOS::SoftBus