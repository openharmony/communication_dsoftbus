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

#include "gtest/gtest.h"
#include <securec.h>
#include "lnn_wifiservice_monitor.cpp"
#include "lnn_wifiservice_monitor_mock.cpp"
#include "common_event_data.h"
#include "softbus_wifi_api_adapter.h"
#include "softbus_errcode.h"
#include "bus_center_client_proxy.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
bool g_subscribeCommonEventRet = false;
namespace EventFwk {
    bool CommonEventManager::SubscribeCommonEvent(const std::shared_ptr<EventFwk::CommonEventSubscriber> &subscriber)
    {
        return g_subscribeCommonEventRet;
    }
}

class LnnWifiServiceMonitorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnWifiServiceMonitorTest::SetUpTestCase()
{
}

void LnnWifiServiceMonitorTest::TearDownTestCase()
{
}

void LnnWifiServiceMonitorTest::SetUp()
{
}

void LnnWifiServiceMonitorTest::TearDown()
{
}

HWTEST_F(LnnWifiServiceMonitorTest, LNN_WIFISERVICE_MONITOR_SetSoftBusWifiConnState_001, TestSize.Level1)
{
    SoftBusWifiState state = SOFTBUS_WIFI_UNKNOWN;

    EventFwk::SetSoftBusWifiConnState((int)OHOS::Wifi::ConnState::OBTAINING_IPADDR, &state);
    EXPECT_EQ(state, SOFTBUS_WIFI_OBTAINING_IPADDR);

    EventFwk::SetSoftBusWifiConnState((int)OHOS::Wifi::ConnState::CONNECTED, &state);
    EXPECT_EQ(state, SOFTBUS_WIFI_CONNECTED);

    EventFwk::SetSoftBusWifiConnState((int)OHOS::Wifi::ConnState::DISCONNECTED, &state);
    EXPECT_EQ(state, SOFTBUS_WIFI_DISCONNECTED);

    state = SOFTBUS_WIFI_UNKNOWN;
    EventFwk::SetSoftBusWifiConnState((int)OHOS::Wifi::ConnState::UNKNOWN, &state);
    EXPECT_EQ(state, SOFTBUS_WIFI_UNKNOWN);
}

HWTEST_F(LnnWifiServiceMonitorTest, LNN_WIFISERVICE_MONITOR_SetSoftBusWifiUseState_001, TestSize.Level1)
{
    SoftBusWifiState state = SOFTBUS_WIFI_UNKNOWN;

    EventFwk::SetSoftBusWifiUseState((int)OHOS::Wifi::WifiState::DISABLED, &state);
    EXPECT_EQ(state, SOFTBUS_WIFI_DISABLED);

    EventFwk::SetSoftBusWifiUseState((int)OHOS::Wifi::WifiState::ENABLED, &state);
    EXPECT_EQ(state, SOFTBUS_WIFI_ENABLED);

    state = SOFTBUS_WIFI_UNKNOWN;
    EventFwk::SetSoftBusWifiUseState((int)OHOS::Wifi::WifiState::UNKNOWN, &state);
    EXPECT_EQ(state, SOFTBUS_WIFI_UNKNOWN);
}

HWTEST_F(LnnWifiServiceMonitorTest, LNN_WIFISERVICE_MONITOR_SetSoftBusWifiHotSpotState_001, TestSize.Level1)
{
    SoftBusWifiState state = SOFTBUS_WIFI_UNKNOWN;

    EventFwk::SetSoftBusWifiHotSpotState((int)OHOS::Wifi::ApState::AP_STATE_STARTED, &state);
    EXPECT_EQ(state, SOFTBUS_AP_ENABLED);

    EventFwk::SetSoftBusWifiHotSpotState((int)OHOS::Wifi::ApState::AP_STATE_CLOSED, &state);
    EXPECT_EQ(state, SOFTBUS_AP_DISABLED);

    state = SOFTBUS_WIFI_UNKNOWN;
    EventFwk::SetSoftBusWifiHotSpotState((int)OHOS::Wifi::ApState::AP_STATE_NONE, &state);
    EXPECT_EQ(state, SOFTBUS_WIFI_UNKNOWN);
}

}