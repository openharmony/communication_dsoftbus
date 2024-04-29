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
#include "hb_fsm_strategy_mock.h"
#include "lnn_ble_heartbeat_virtual.c"
#include "lnn_heartbeat_strategy.h"
#include "lnn_heartbeat_strategy.c"
#include "softbus_error_code.h"

namespace OHOS {

using namespace testing::ext;
using namespace testing;

constexpr uint32_t LNN_HB_TYPE = 1;
constexpr char NETWORKID[NETWORK_ID_BUF_LEN] = "123456ABD";
constexpr int32_t LISTENER_ID = 3;
constexpr uint64_t DELAY_MILLIS = 6000;

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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MIN);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MAX);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MAX - 1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnStartNewHbStrategyFsm();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnConvertConnAddrTypeToHbType).WillByDefault(Return(CONNECTION_ADDR_WLAN));
    ON_CALL(hbMock, LnnPostScreenOffCheckDevMsgToHbFsm).WillByDefault(Return(SOFTBUS_OK));
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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnConvertConnAddrTypeToHbType).WillByDefault(Return(CONNECTION_ADDR_WLAN));
    ON_CALL(hbMock, LnnRemoveScreenOffCheckStatusMsg).WillByDefault(Return());
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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnConvertConnAddrTypeToHbType).WillByDefault(Return(CONNECTION_ADDR_WLAN));
    ON_CALL(hbMock, LnnGetLocalNumU64Info).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbMock, LnnGetRemoteNumU64Info).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbMock, IsFeatureSupport).WillByDefault(Return(false));
    ON_CALL(hbMock, LnnConvertHbTypeToId).WillByDefault(Return(1));
    ON_CALL(hbMock, LnnPostCheckDevStatusMsgToHbFsm).WillByDefault(Return(SOFTBUS_ERR));
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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnConvertConnAddrTypeToHbType).WillByDefault(Return(CONNECTION_ADDR_WLAN));
    ON_CALL(hbMock, LnnRemoveCheckDevStatusMsg).WillByDefault(Return());
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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnPostStopMsgToHbFsm).WillByDefault(Return(SOFTBUS_OK));
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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnPostStopMsgToHbFsm).WillByDefault(Return(SOFTBUS_OK));
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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnVisitHbTypeSet).WillByDefault(Return(true));
    ON_CALL(hbMock, LnnConvertHbTypeToId).WillByDefault(Return(1));
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
 * @tc.name: LNN_SET_MEDIUM_PARAM_BY_SPECIFIC_TYPE_TEST_01
 * @tc.desc: lnn set medium param by specific type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_SET_MEDIUM_PARAM_BY_SPECIFIC_TYPE_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnVisitHbTypeSet).WillByDefault(Return(true));
    ON_CALL(hbMock, LnnConvertHbTypeToId).WillByDefault(Return(1));
    ON_CALL(hbMock, LnnPostSetMediumParamMsgToHbFsm).WillByDefault(Return(SOFTBUS_OK));
    LnnHeartbeatMediumParam param;
    int32_t ret = LnnHbStrategyInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetMediumParamBySpecificType(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnSetMediumParamBySpecificType(&param);
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
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnCheckSupportedHbType).WillByDefault(Return(true));
    ON_CALL(hbMock, GetScreenState).WillByDefault(Return(SOFTBUS_SCREEN_ON));
    ON_CALL(hbMock, LnnVisitHbTypeSet).WillByDefault(Return(true));
    ON_CALL(hbMock, LnnRemoveSendEndMsg).WillByDefault(Return());
    ON_CALL(hbMock, LnnFsmRemoveMessage).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillByDefault(Return(SOFTBUS_ERR));
    ON_CALL(hbMock, LnnRemoveCheckDevStatusMsg).WillByDefault(Return());
    ON_CALL(hbMock, LnnPostCheckDevStatusMsgToHbFsm).WillByDefault(Return(SOFTBUS_ERR));

    int32_t ret = LnnGetHbStrategyManager(&mgr, HEARTBEAT_TYPE_MAX, STRATEGY_HB_SEND_SINGLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
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
    EXPECT_TRUE(ret == SOFTBUS_OK);
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

/*
 * @tc.name: LNN_GET_GEAR_MODE_BY_SPECIFIC_TYPE_TEST_01
 * @tc.desc: lnn get gear mode by specific type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_GET_GEAR_MODE_BY_SPECIFIC_TYPE_TEST_01, TestSize.Level1)
{
    GearMode mode = {
        .cycle = MID_FREQ_CYCLE,
        .duration = NORMAL_DURATION,
        .wakeupFlag = false,
    };
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnVisitHbTypeSet).WillByDefault(Return(true));
    ON_CALL(hbMock, LnnConvertHbTypeToId).WillByDefault(Return(1));
    int32_t ret = LnnHbStrategyInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetGearModeBySpecificType(nullptr, LNN_HB_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetGearModeBySpecificType(&mode, LNN_HB_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    LnnHbStrategyDeinit();
}

/*
 * @tc.name: VISIT_CLEAR_NONE_SPLIT_HB_TYPE_TEST_01
 * @tc.desc: visit clear none split hb type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, VISIT_CLEAR_NONE_SPLIT_HB_TYPE_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnConvertHbTypeToId).WillByDefault(Return(1));
    LnnHeartbeatType typeSet;
    bool ret = VisitClearNoneSplitHbType(&typeSet, HEARTBEAT_TYPE_BLE_V3, nullptr);
    EXPECT_TRUE(ret == true);
}

/*
 * @tc.name: SEND_EACH_SEPARATELY_TEST_01
 * @tc.desc: send each separately test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, SEND_EACH_SEPARATELY_TEST_01, TestSize.Level1)
{
    GearMode mode = {
        .cycle = MID_FREQ_CYCLE,
        .duration = NORMAL_DURATION,
        .wakeupFlag = true,
    };
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara msgPara;
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnVisitHbTypeSet).WillByDefault(Return(true));
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = SendEachSeparately(&hbFsm, &msgPara, &mode, HEARTBEAT_TYPE_BLE_V3, false);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = SendEachSeparately(&hbFsm, &msgPara, &mode, HEARTBEAT_TYPE_BLE_V3, false);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = SendEachSeparately(&hbFsm, &msgPara, &mode, HEARTBEAT_TYPE_BLE_V3, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: VISIT_CLEAR_UN_REGISTED_HB_TYPE_TEST_01
 * @tc.desc: visit clear un registed hb type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, VISIT_CLEAR_UN_REGISTED_HB_TYPE_TEST_01, TestSize.Level1)
{
    LnnHeartbeatType typeSet;
    bool ret = VisitClearUnRegistedHbType(&typeSet, HEARTBEAT_TYPE_BLE_V3, nullptr);
    EXPECT_TRUE(ret == true);
}

/*
 * @tc.name: PROCESS_SEND_ONCE_STRATEGY_TEST_01
 * @tc.desc: process send once strategy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, PROCESS_SEND_ONCE_STRATEGY_TEST_01, TestSize.Level1)
{
    GearMode mode = {
        .cycle = MID_FREQ_CYCLE,
        .duration = NORMAL_DURATION,
        .wakeupFlag = true,
    };
    LnnProcessSendOnceMsgPara msgPara = {
        .isRelay = true,
    };
    LnnHeartbeatFsm hbFsm;
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    EXPECT_CALL(hbMock, LnnRemoveSendEndMsg);
    EXPECT_CALL(hbMock, LnnFsmRemoveMessage).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnRemoveCheckDevStatusMsg);
    EXPECT_CALL(hbMock, LnnPostCheckDevStatusMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = ProcessSendOnceStrategy(&hbFsm, &msgPara, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = ProcessSendOnceStrategy(&hbFsm, &msgPara, &mode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = ProcessSendOnceStrategy(&hbFsm, &msgPara, &mode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    msgPara.isRelay = false;
    msgPara.hbType = HEARTBEAT_TYPE_MIN;
    ret = ProcessSendOnceStrategy(&hbFsm, &msgPara, &mode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_START_HEARTBEAT_TEST_01
 * @tc.desc: lnn start heartbeat test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_START_HEARTBEAT_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnPostStartMsgToHbFsm)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnStartHeartbeat(DELAY_MILLIS);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnStartHeartbeat(DELAY_MILLIS);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_BLE_HEARTBEAT_VIRTUAL_TEST_01
 * @tc.desc: lnn_ble_heartbeat_virtual.c
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_BLE_HEARTBEAT_VIRTUAL_TEST_01, TestSize.Level1)
{
    int32_t ret = InitBleHeartbeat(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = BleHeartbeatOnceBegin(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_NOT_IMPLEMENT);
    ret = BleHeartbeatOnceEnd(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_NOT_IMPLEMENT);
    ret = SetBleMediumParam(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_NOT_IMPLEMENT);
    ret = UpdateBleSendInfo(UPDATE_HB_ACCOUNT_INFO);
    EXPECT_TRUE(ret == SOFTBUS_NOT_IMPLEMENT);
    ret = StopBleHeartbeat();
    EXPECT_TRUE(ret == SOFTBUS_NOT_IMPLEMENT);
    DeinitBleHeartbeat();
    ret = HbUpdateBleScanFilter(LISTENER_ID, LNN_HB_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS
