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
#include "bus_center_manager.h"

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_decision_center.h"
#include "bus_center_event.h"
#include "lnn_async_callback_utils.h"
#include "lnn_coap_discovery_impl.h"
#include "lnn_decision_center.h"
#include "lnn_discovery_manager.h"
#include "lnn_event_monitor.h"
#include "lnn_lane_hub.h"
#include "lnn_log.h"
#include "lnn_meta_node_interface.h"
#include "lnn_net_builder.h"
#include "lnn_net_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_ohos_account_adapter.h"
#include "legacy/softbus_adapter_xcollie.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

#include "bus_center_manager_deps_mock.h"

using namespace testing;
using namespace testing::ext;


namespace OHOS {

class BusCenterManagerTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BusCenterManagerTest::SetUpTestCase(void)
{
}

void BusCenterManagerTest::TearDownTestCase(void)
{
}

void BusCenterManagerTest::SetUp(void)
{
}

void BusCenterManagerTest::TearDown(void)
{
}

/*
* @tc.name: BusCenterManagerTest001
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterManagerTest, BusCenterManagerTest001, TestSize.Level1)
{
    NiceMock<BusCenterManagerDepsInterfaceMock> BusCenterManagerMock;
    EXPECT_CALL(BusCenterManagerMock, GetLooper(_)).WillOnce(Return(NULL));
    LnnDeinitLnnLooper();
}

/*
* @tc.name: BusCenterManagerTest002
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterManagerTest, BusCenterManagerTest002, TestSize.Level1)
{
    NiceMock<BusCenterManagerDepsInterfaceMock> BusCenterManagerMock;
    EXPECT_CALL(BusCenterManagerMock, CreateNewLooper(_)).WillOnce(Return(NULL));
    int32_t ret = LnnInitLnnLooper();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterManagerTest003
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterManagerTest, BusCenterManagerTest003, TestSize.Level1)
{
    NiceMock<BusCenterManagerDepsInterfaceMock> BusCenterManagerMock;
    EXPECT_CALL(BusCenterManagerMock, CreateNewLooper(_)).WillOnce(Return(NULL));
    int32_t ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterManagerTest004
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterManagerTest, BusCenterManagerTest004, TestSize.Level1)
{
    NiceMock<BusCenterManagerDepsInterfaceMock> BusCenterManagerMock;
    SoftBusLooper loop;
    EXPECT_CALL(BusCenterManagerMock, CreateNewLooper(_)).WillOnce(Return(&loop));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetLedger()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitBusCenterEvent()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitEventMonitor()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitDiscoveryManager()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetworkManager()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetBuilder()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitMetaNode()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, IsActiveOsAccountUnlocked()).WillOnce(Return(false));
    EXPECT_CALL(BusCenterManagerMock,  SoftBusRunPeriodicalTask(_, _, _, _)).WillOnce(Return());
    EXPECT_CALL(BusCenterManagerMock, LnnInitLaneHub()).WillOnce(Return(SOFTBUS_NO_INIT));
    int32_t ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterManagerTest005
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterManagerTest, BusCenterManagerTest005, TestSize.Level1)
{
    NiceMock<BusCenterManagerDepsInterfaceMock> BusCenterManagerMock;
    SoftBusLooper loop;
    EXPECT_CALL(BusCenterManagerMock, CreateNewLooper(_)).WillRepeatedly(Return(&loop));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetLedger()).WillOnce(Return(SOFTBUS_HUKS_INIT_FAILED));
    int32_t ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetLedger()).WillRepeatedly(Return(SOFTBUS_OK));
    ret = BusCenterServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnInitDecisionCenter(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitBusCenterEvent()).WillOnce(Return(SOFTBUS_LOOPER_ERR));
    ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnInitBusCenterEvent()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitEventMonitor()).WillOnce(Return(SOFTBUS_EVENT_MONITER_INIT_FAILED));
    ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnInitEventMonitor()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitDiscoveryManager()).WillOnce(Return(SOFTBUS_DISCOVER_MANAGER_INIT_FAIL));
    ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnInitDiscoveryManager()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetworkManager()).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetworkManager()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetBuilder()).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetBuilder()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitMetaNode()).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnInitMetaNode()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, IsActiveOsAccountUnlocked()).WillOnce(Return(true));
    ret = BusCenterServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterManagerTest006
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterManagerTest, BusCenterManagerTest006, TestSize.Level1)
{
    NiceMock<BusCenterManagerDepsInterfaceMock> BusCenterManagerMock;
    SoftBusLooper loop;
    EXPECT_CALL(BusCenterManagerMock, CreateNewLooper(_)).WillRepeatedly(Return(&loop));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetLedger()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitBusCenterEvent()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitEventMonitor()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitDiscoveryManager()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetworkManager()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitNetBuilder()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnInitMetaNode()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, IsActiveOsAccountUnlocked()).WillRepeatedly(Return(false));
    EXPECT_CALL(BusCenterManagerMock,  SoftBusRunPeriodicalTask(_, _, _, _))
        .WillRepeatedly(Return());
    EXPECT_CALL(BusCenterManagerMock, LnnInitLaneHub()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterManagerMock, InitDecisionCenter()).WillOnce(Return(SOFTBUS_CREATE_LIST_ERR));
    ret = BusCenterServerInit();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(BusCenterManagerMock, InitDecisionCenter()).WillRepeatedly(Return(SOFTBUS_OK));
    ret = BusCenterServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}
}
