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
#include "lnn_heartbeat_strategy.c"
#include "lnn_heartbeat_strategy.h"
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
        .WillOnce(Return(SOFTBUS_NETWORK_POST_MSG_DELAY_FAIL))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MIN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_MAX - 1);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_FAIL);
    ret = LnnStartNewHbStrategyFsm();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_FSM_CREATE_FAIL);
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
    ON_CALL(hbMock, LnnPostCheckDevStatusMsgToHbFsm).WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnStartOfflineTimingStrategy(nullptr, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStartOfflineTimingStrategy(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_GET_GEAR_MODE_FAIL);
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
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_INVALID_MGR);
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
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_INVALID_MGR);
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
    ON_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    ON_CALL(hbMock, LnnRemoveCheckDevStatusMsg).WillByDefault(Return());
    ON_CALL(hbMock, LnnPostCheckDevStatusMsgToHbFsm).WillByDefault(Return(SOFTBUS_INVALID_PARAM));

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
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_GET_GEAR_MODE_FAIL);
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
    ret = LnnGetGearModeBySpecificType(nullptr, nullptr, LNN_HB_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetGearModeBySpecificType(&mode, nullptr, LNN_HB_TYPE);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_INVALID_MGR);
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
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = SendEachSeparately(&hbFsm, &msgPara, &mode, HEARTBEAT_TYPE_BLE_V3, false);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_FAIL);
    ret = SendEachSeparately(&hbFsm, &msgPara, &mode, HEARTBEAT_TYPE_BLE_V3, false);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_FAIL);
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
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnStartHeartbeat(DELAY_MILLIS);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
/*
 * @tc.name: LNN_START_STRATEGY_DIRECTLY_TEST_01
 * @tc.desc: LnnStartHbByTypeAndStrategyDirectly test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_START_STRATEGY_DIRECTLY_TEST_01, TestSize.Level1)
{
    uint64_t timeout = 100;
    int32_t ret =
        LnnStartHbByTypeAndStrategyDirectly(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false, NULL, timeout);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_DIRECT_SEND_STRATEGY_TEST_01
 * @tc.desc: DirectAdvSendStrategy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_DIRECT_SEND_STRATEGY_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.strategyType = STRATEGY_HB_SEND_SINGLE;
    int32_t ret = DirectAdvSendStrategy(&hbFsm, (void *)&obj);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    obj.strategyType = STRATEGY_HB_SEND_DIRECT;
    obj.hbType = HEARTBEAT_TYPE_BLE_V0;
    obj.isDirectBoardcast = true;
    ret = DirectAdvSendStrategy(&hbFsm, (void *)&obj);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = DirectAdvSendStrategy(&hbFsm, (void *)&obj);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_HEARTBEAT_SEND_ERR);
}

/*
 * @tc.name: LNN_GET_STRATEGY_MANAGER_TEST_01
 * @tc.desc: LnnGetHbStrategyManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_GET_STRATEGY_MANAGER_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    ON_CALL(hbMock, LnnVisitHbTypeSet).WillByDefault(Return(false));
    LnnHeartbeatStrategyManager strategyMgr;
    int32_t ret = LnnGetHbStrategyManager(NULL, HEARTBEAT_TYPE_MAX, STRATEGY_HB_SEND_SINGLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetHbStrategyManager(&strategyMgr, HEARTBEAT_TYPE_MAX, STRATEGY_HB_SEND_SINGLE);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_FIXED_PERIOD_SEND_STRATEGY_TEST_01
 * @tc.desc: FixedPeriodSendStrategy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_FIXED_PERIOD_SEND_STRATEGY_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.strategyType = STRATEGY_HB_SEND_FIXED_PERIOD;
    obj.hbType = HEARTBEAT_TYPE_BLE_V1;
    obj.isDirectBoardcast = false;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = FixedPeriodSendStrategy(&hbFsm, (void *)&obj);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostNextSendOnceMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = FixedPeriodSendStrategy(&hbFsm, (void *)&obj);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SINGLE_SEND_STRATEGY_TEST_01
 * @tc.desc: SingleSendStrategy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_SINGLE_SEND_STRATEGY_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.strategyType = STRATEGY_HB_SEND_SINGLE;
    obj.hbType = HEARTBEAT_TYPE_BLE_V1;
    obj.isDirectBoardcast = false;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = SingleSendStrategy(&hbFsm, (void *)&obj);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_PROCESS_BEAT_STRATEGY_TEST_01
 * @tc.desc: ProcessSendOnceStrategy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_PROCESS_BEAT_STRATEGY_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.hbType = HEARTBEAT_TYPE_BLE_V0;
    obj.isDirectBoardcast = true;
    obj.strategyType = STRATEGY_HB_SEND_DIRECT;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ProcessSendOnceStrategy(&hbFsm, &obj, NULL);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_HEARTBEAT_SEND_ERR);
    obj.isDirectBoardcast = false;
    obj.strategyType = STRATEGY_HB_SEND_SINGLE;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ProcessSendOnceStrategy(&hbFsm, &obj, NULL);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_HEARTBEAT_SEND_ERR);
    obj.isRelay = true;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ProcessSendOnceStrategy(&hbFsm, &obj, NULL);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_PROCESSCHECK_DEVSTATUSMSG_TEST_01
 * @tc.desc: ProcessCheckDevStatusMsg test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_PROCESSCHECK_DEVSTATUSMSG_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.strategyType = STRATEGY_HB_SEND_SINGLE;
    obj.hbType = HEARTBEAT_TYPE_BLE_V0;
    obj.isDirectBoardcast = true;
    EXPECT_CALL(hbMock, LnnPostCheckDevStatusMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ProcessCheckDevStatusMsg(&hbFsm, &obj, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SEND_DIRECTBOARD_CAST_TEST_01
 * @tc.desc: SendDirectBoardcast test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_SEND_DIRECTBOARD_CAST_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.strategyType = STRATEGY_HB_SEND_DIRECT;
    obj.hbType = HEARTBEAT_TYPE_BLE_V0;
    obj.isDirectBoardcast = true;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = SendDirectBoardcast(&hbFsm, &obj, NULL, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_TRUE(ret == SOFTBUS_MEM_ERR);
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = SendDirectBoardcast(&hbFsm, &obj, NULL, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    ret = SendDirectBoardcast(&hbFsm, &obj, NULL, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_EACH_SEPARATELY_TEST_01
 * @tc.desc: SendEachSeparately test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_SEND_EACH_SEPARATELY_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.strategyType = STRATEGY_HB_SEND_SINGLE;
    obj.hbType = HEARTBEAT_TYPE_BLE_V0;
    obj.isDirectBoardcast = false;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnIsMultiDeviceOnline).WillOnce(Return(true));
    int32_t ret = SendEachSeparately(&hbFsm, &obj, NULL, HEARTBEAT_TYPE_BLE_V0, true);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(hbMock, LnnIsMultiDeviceOnline).WillOnce(Return(false));
    ret = SendEachSeparately(&hbFsm, &obj, NULL, HEARTBEAT_TYPE_BLE_V0, true);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = SendEachSeparately(&hbFsm, &obj, NULL, HEARTBEAT_TYPE_BLE_V1, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_RELAY_HEARTBEAT_V1_SPLIT_TEST_01
 * @tc.desc: RelayHeartbeatV1Split test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_RELAY_HEARTBEAT_V1_SPLIT_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.strategyType = STRATEGY_HB_SEND_SINGLE;
    obj.hbType = HEARTBEAT_TYPE_BLE_V0;
    obj.isDirectBoardcast = false;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = RelayHeartbeatV1Split(&hbFsm, &obj, false, HEARTBEAT_TYPE_BLE_V0);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = RelayHeartbeatV1Split(&hbFsm, &obj, false, HEARTBEAT_TYPE_BLE_V0);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    ret = RelayHeartbeatV1Split(&hbFsm, &obj, false, HEARTBEAT_TYPE_BLE_V0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_RELAY_HEARTBEAT_V0_SPLIT_OLD_TEST_01
 * @tc.desc: RelayHeartbeatV0SplitOld test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_RELAY_HEARTBEAT_V0_SPLIT_OLD_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    LnnHeartbeatFsm hbFsm;
    LnnProcessSendOnceMsgPara obj;
    obj.strategyType = STRATEGY_HB_SEND_SINGLE;
    obj.hbType = HEARTBEAT_TYPE_BLE_V0;
    obj.isDirectBoardcast = false;
    LnnHeartbeatSendEndData endData;
    uint32_t delayTime = 11;
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    SendEachOnce(&hbFsm, &obj, &endData, &delayTime, 11);
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = RelayHeartbeatV0SplitOld(&hbFsm, &obj, false, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    EXPECT_CALL(hbMock, LnnPostSendBeginMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    SendEachOnce(&hbFsm, &obj, &endData, &delayTime, 11);
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = RelayHeartbeatV0SplitOld(&hbFsm, &obj, false, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    EXPECT_CALL(hbMock, LnnPostSendEndMsgToHbFsm).WillRepeatedly(Return(SOFTBUS_OK));
    ret = RelayHeartbeatV0SplitOld(&hbFsm, &obj, false, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_GEARMODE_BY_SPECIFICTYPE_TEST_01
 * @tc.desc: LnnSetGearModeBySpecificType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatStrategyTest, LNN_SET_GEARMODE_BY_SPECIFICTYPE_TEST_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMStrategyInterfaceMock> hbMock;
    EXPECT_CALL(hbMock, LnnVisitHbTypeSet).WillRepeatedly(Return(true));
    EXPECT_CALL(hbMock, LnnConvertHbTypeToId).WillRepeatedly(Return(1));
    LnnHbStrategyInit();
    GearMode mode;
    int32_t ret = LnnSetGearModeBySpecificType(NULL, &mode, HEARTBEAT_TYPE_BLE_V0);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}
} // namespace OHOS
