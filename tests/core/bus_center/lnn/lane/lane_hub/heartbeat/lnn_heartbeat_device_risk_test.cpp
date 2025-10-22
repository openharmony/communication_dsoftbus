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
#include <gmock/gmock.h>
#include <securec.h>
#include <thread>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_connection_fsm.h"
#include "lnn_device_info.h"
#include "lnn_heartbeat_ctrl.c"
#include "lnn_heartbeat_device_risk_mock.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_node_info.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common_struct.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

NodeInfo nodeinfo1;

class LnnHeartBeatDeviceRiskTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void LnnHeartBeatDeviceRiskTest::SetUpTestCase()
{
}

void LnnHeartBeatDeviceRiskTest::TearDownTestCase()
{
}

void LnnHeartBeatDeviceRiskTest::SetUp()
{}

void LnnHeartBeatDeviceRiskTest::TearDown()
{}

/*
 * @tc.name: RiskDeviceLeaveLnnTest01
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatDeviceRiskTest, RiskDeviceLeaveLnnTest001, TestSize.Level1)
{
    int ret = 0;
    NiceMock<LnnHeatbeatDeviceRiskInterfaceMock> LnnMock;

    EXPECT_CALL(LnnMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = RiskDeviceLeaveLnn();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR);

    EXPECT_CALL(LnnMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = RiskDeviceLeaveLnn();
    EXPECT_EQ(ret, SOFTBUS_NO_ONLINE_DEVICE);
}

/*
 * @tc.name: HbDeviceRiskStateEventHandlerTest01
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatDeviceRiskTest, HbDeviceRiskStateEventHandlerTest001, TestSize.Level1)
{
    LnnDeviceRiskStateChangeEvent *event =
        reinterpret_cast<LnnDeviceRiskStateChangeEvent*>(SoftBusCalloc(sizeof(LnnDeviceRiskStateChangeEvent)));
    event->basic.event = LNN_EVENT_TYPE_MAX;
    event->status = SOFTBUS_DEVICE_IS_RISK;
    g_hbConditionState.deviceRiskState = SOFTBUS_DEVICE_IS_RISK;
    HbDeviceRiskStateEventHandler(NULL);

    HbDeviceRiskStateEventHandler(&event->basic);

    event->basic.event = LNN_EVENT_DEVICE_RISK_STATE_CHANGED;
    HbDeviceRiskStateEventHandler(&event->basic);

    g_hbConditionState.deviceRiskState = SOFTBUS_DEVICE_NOT_RISK;
    event->status = SOFTBUS_DEVICE_NOT_RISK;
    HbDeviceRiskStateEventHandler(&event->basic);

    EXPECT_EQ(event->status, 0);
}
}  // namespace OHOS