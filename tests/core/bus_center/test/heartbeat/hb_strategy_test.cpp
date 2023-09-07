/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <securec.h>

#include "bus_center_event.h"
#include "lnn_heartbeat_fsm.h"
#include "lnn_heartbeat_strategy.h"
#include "softbus_error_code.h"

namespace OHOS {

using namespace testing::ext;
using namespace testing;

constexpr uint32_t LNN_HB_TYPE = 1;
constexpr char NETWORKID[NETWORK_ID_BUF_LEN] = "123456ABD";

class HeartBeatStrategyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HeartBeatStrategyTest::SetUpTestCase()
{
    LooperInit();
}

void HeartBeatStrategyTest::TearDownTestCase()
{
    LooperDeinit();
}

void HeartBeatStrategyTest::SetUp() { }

void HeartBeatStrategyTest::TearDown() { }

/*
 * @tc.name: GET_STRATEGY_TYPE_BY_POLICY_TEST_01
 * @tc.desc: get strategy type by policy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, GET_STRATEGY_TYPE_BY_POLICY_TEST_01, TestSize.Level1)
{
    LnnHeartbeatStrategyType ret = GetStrategyTypeByPolicy(ONCE_STRATEGY);
    EXPECT_TRUE(ret == STRATEGY_HB_SEND_SINGLE);
    ret = GetStrategyTypeByPolicy(HIGH_PERFORMANCE_STRATEGY);
    EXPECT_TRUE(ret == STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
}

/*
 * @tc.name: LNN_STOP_HEARTBEAT_ADV_BY_TYPE_NOW_TEST_01
 * @tc.desc: lnn stop heartbeat adv by type now test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_STOP_HEARTBEAT_ADV_BY_TYPE_NOW_TEST_01, TestSize.Level1)
{
    int32_t ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MIN);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MAX);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MAX - 1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnStartNewHbStrategyFsm();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MAX - 1);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_START_SCREEN_CHANGE_OFFLINE_TIMING_TEST_01
 * @tc.desc: lnn start screen change offline timing test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_START_SCREEN_CHANGE_OFFLINE_TIMING_TEST_01, TestSize.Level1)
{
    int32_t ret = LnnStartScreenChangeOfflineTiming(nullptr, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStartScreenChangeOfflineTiming(NETWORKID, CONNECTION_ADDR_MAX);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStartScreenChangeOfflineTiming(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_STOP_SCREEN_CHANGE_OFFLINE_TIMING_TEST_01
 * @tc.desc: lnn stop screen change offline timing test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_STOP_SCREEN_CHANGE_OFFLINE_TIMING_TEST_01, TestSize.Level1)
{
    int32_t ret = LnnStopScreenChangeOfflineTiming(nullptr, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStopScreenChangeOfflineTiming(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_START_OFFLINE_TIMING_STRATEGY_TEST_01
 * @tc.desc: lnn start offline timing strategy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_START_OFFLINE_TIMING_STRATEGY_TEST_01, TestSize.Level1)
{
    int32_t ret = LnnStartOfflineTimingStrategy(nullptr, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStartOfflineTimingStrategy(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: LNN_STOP_OFFLINE_TIMING_STRATEGY_TEST_01
 * @tc.desc: lnn stop offline timing strategy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_STOP_OFFLINE_TIMING_STRATEGY_TEST_01, TestSize.Level1)
{
    int32_t ret = LnnStopOfflineTimingStrategy(nullptr, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStopOfflineTimingStrategy(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_STOP_HEARTBEAT_BY_TYPE_TEST_01
 * @tc.desc: lnn stop heartbeat by type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_STOP_HEARTBEAT_BY_TYPE_TEST_01, TestSize.Level1)
{
    int32_t ret = LnnStopHeartbeatByType(LNN_HB_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_STOPV0_HEARTBEAT_AND_NOT_TRANS_STATE_TEST_01
 * @tc.desc: lnn stopv0 heartbeat and not trans state test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_STOPV0_HEARTBEAT_AND_NOT_TRANS_STATE_TEST_01, TestSize.Level1)
{
    int32_t ret = LnnStopV0HeartbeatAndNotTransState();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_MEDIUM_PARAM_BY_SPECIFIC_TYPE_TEST_01
 * @tc.desc: lnn get medium param by specific type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_GET_MEDIUM_PARAM_BY_SPECIFIC_TYPE_TEST_01, TestSize.Level1)
{
    LnnHeartbeatMediumParam param;
    int32_t ret = LnnHbStrategyInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetMediumParamBySpecificType(nullptr, LNN_HB_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetMediumParamBySpecificType(&param, LNN_HB_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    LnnHbStrategyDeinit();
}

/*
 * @tc.name: LNN_GET_HB_STRATEGY_MANAGER_TEST_01
 * @tc.desc: lnn get hb strategy manager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_GET_HB_STRATEGY_MANAGER_TEST_01, TestSize.Level1)
{
    LnnHeartbeatStrategyManager mgr;
    LnnProcessSendOnceMsgPara msgPara;
    LnnHeartbeatFsm hbFsm;
    int32_t ret = LnnGetHbStrategyManager(&mgr, HEARTBEAT_TYPE_MAX, STRATEGY_HB_SEND_SINGLE);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnGetHbStrategyManager(&mgr, HEARTBEAT_TYPE_UDP, STRATEGY_HB_SEND_SINGLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    msgPara.strategyType = STRATEGY_HB_SEND_SINGLE;
    ret = mgr.onProcess(&hbFsm, reinterpret_cast<void *>(&msgPara));
    EXPECT_TRUE(ret == SOFTBUS_OK);
    msgPara.strategyType = STRATEGY_HB_SEND_FIXED_PERIOD;
    ret = mgr.onProcess(&hbFsm, reinterpret_cast<void *>(&msgPara));
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = LnnGetHbStrategyManager(&mgr, HEARTBEAT_TYPE_UDP, STRATEGY_HB_SEND_FIXED_PERIOD);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = mgr.onProcess(&hbFsm, reinterpret_cast<void *>(&msgPara));
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    msgPara.strategyType = STRATEGY_HB_SEND_ADJUSTABLE_PERIOD;
    ret = mgr.onProcess(&hbFsm, reinterpret_cast<void *>(&msgPara));
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = LnnGetHbStrategyManager(&mgr, HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = mgr.onProcess(&hbFsm, reinterpret_cast<void *>(&msgPara));
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    msgPara.hbType = HEARTBEAT_TYPE_BLE_V0;
    ret = mgr.onProcess(&hbFsm, reinterpret_cast<void *>(&msgPara));
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    msgPara.strategyType = STRATEGY_HB_RECV_SINGLE;
    ret = mgr.onProcess(&hbFsm, reinterpret_cast<void *>(&msgPara));
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
