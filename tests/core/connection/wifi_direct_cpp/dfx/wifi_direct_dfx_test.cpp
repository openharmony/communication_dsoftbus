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
    CONN_LOGI(CONN_WIFI_DIRECT, "ReportConnEventExtraTest start");
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
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    wifiDirectConnectInfo.dfxInfo.linkType = STATISTIC_TRIGGER_HML;
    EXPECT_NO_FATAL_FAILURE(WifiDirectDfx::GetInstance().DfxRecord(result, reason, wifiDirectConnectInfo));
    CONN_LOGI(CONN_WIFI_DIRECT, "ReportConnEventExtraTest end");
}

/*
 * @tc.name: ReportReceiveAuthLinkMsgTest
 * @tc.desc: check BytesToInt method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectDfxTest, ReportReceiveAuthLinkMsgTest, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ReportReceiveAuthLinkMsgTest start");
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
    CONN_LOGI(CONN_WIFI_DIRECT, "ReportReceiveAuthLinkMsgTest end");
}
} // namespace OHOS::SoftBus