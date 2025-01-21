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
#include <securec.h>

#include "ble_mock.h"
#include "bus_center_manager.h"
#include "hb_ctrl_static_mock.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_decision_center.h"
#include "lnn_heartbeat_ctrl.c"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_ledger_mock.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class HeartBeatCtrlStaticTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HeartBeatCtrlStaticTest::SetUpTestCase()
{
    int32_t ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void HeartBeatCtrlStaticTest::TearDownTestCase() { }

void HeartBeatCtrlStaticTest::SetUp() { }

void HeartBeatCtrlStaticTest::TearDown() { }

/*
 * @tc.name: HB_HANDLE_LEAVE_LNN_TEST_001
 * @tc.desc: handle leave lnn base remote info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, HB_HANDLE_LEAVE_LNN_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(info), SetArgPointee<1>(infoNum), Return(SOFTBUS_INVALID_PARAM)));
    int32_t ret = HbHandleLeaveLnn();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR);

    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(info), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    ret = HbHandleLeaveLnn();
    EXPECT_EQ(ret, SOFTBUS_NO_ONLINE_DEVICE);

    NodeBasicInfo *info1 = nullptr;
    int32_t infoNum1 = 1;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(info1), SetArgPointee<1>(infoNum1), Return(SOFTBUS_INVALID_PARAM)));
    ret = HbHandleLeaveLnn();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR);

    NodeBasicInfo *info2 = nullptr;
    int32_t infoNum2 = 0;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(info2), SetArgPointee<1>(infoNum2), Return(SOFTBUS_OK)));
    ret = HbHandleLeaveLnn();
    EXPECT_EQ(ret, SOFTBUS_NO_ONLINE_DEVICE);
}

/*
 * @tc.name: HB_HANDLE_LEAVE_LNN_TEST_002
 * @tc.desc: handle leave lnn base remote info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, HB_HANDLE_LEAVE_LNN_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo1);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    NiceMock<BleMock> bleMock;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<2>(nodeInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(bleMock, SoftBusGetBrState()).WillRepeatedly(Return(BR_ENABLE));
    ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<2>(nodeInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(bleMock, SoftBusGetBrState()).WillRepeatedly(Return(BR_DISABLE));
    ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    nodeInfo.feature = 0x1FFFF;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<2>(nodeInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(bleMock, SoftBusGetBrState()).WillRepeatedly(Return(BR_ENABLE));
    ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(bleMock, SoftBusGetBrState()).WillRepeatedly(Return(BR_DISABLE));
    ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: GET_DISENABLE_BLE_DISCOVERY_TIME_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, GET_DISENABLE_BLE_DISCOVERY_TIME_TEST_001, TestSize.Level1)
{
    uint64_t modeDuration = 0ULL;
    uint64_t ret = GetDisEnableBleDiscoveryTime(modeDuration);
    EXPECT_EQ(ret, MIN_DISABLE_BLE_DISCOVERY_TIME);

    modeDuration = 20000LL;
    ret = GetDisEnableBleDiscoveryTime(modeDuration);
    EXPECT_EQ(ret, MAX_DISABLE_BLE_DISCOVERY_TIME);
}

/*
 * @tc.name: LNN_REGISTER_HEART_BEAT_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_REGISTER_HEART_BEAT_TEST_001, TestSize.Level1)
{
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_NODE_MASTER_STATE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_HOME_GROUP_CHANGED), _))
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_ACCOUNT_CHANGED), _))
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED), _))
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_USER_STATE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_LP_EVENT_REPORT), _))
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: HB_SEND_CHECK_OFFLINE_MESSAGE_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, HB_SEND_CHECK_OFFLINE_MESSAGE_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnHeartbeatType hbType;
    (void)memset_s(&hbType, sizeof(LnnHeartbeatType), 0, sizeof(LnnHeartbeatType));
    HbSendCheckOffLineMessage(hbType);

    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    InitHbSpecificConditionState();
    InitHbSpecificConditionState();

    LnnEventBasicInfo info;
    (void)memset_s(&info, sizeof(LnnEventBasicInfo), 0, sizeof(LnnEventBasicInfo));
    info.event = LNN_EVENT_IP_ADDR_CHANGED;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnEnableHeartbeatByType(Eq(HEARTBEAT_TYPE_TCP_FLUSH), false))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnEnableHeartbeatByType(Eq(HEARTBEAT_TYPE_TCP_FLUSH), true))
        .WillOnce(Return(SOFTBUS_LOCK_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    HbIpAddrChangeEventHandler(&info);
    HbIpAddrChangeEventHandler(&info);
}

/*
 * @tc.name: HB_TRY_CLOUD_SYNC_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, HB_TRY_CLOUD_SYNC_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnIsDefaultOhosAccount).WillOnce(Return(true)).WillRepeatedly(Return(false));
    int32_t ret = HbTryCloudSync();
    EXPECT_EQ(ret, SOFTBUS_NOT_LOGIN);

    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    EXPECT_CALL(hbStaticMock, LnnGetLocalNodeInfoSafe)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = HbTryCloudSync();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);

    EXPECT_CALL(hbStaticMock, LnnLedgerAllDataSyncToDB)
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = HbTryCloudSync();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = HbTryCloudSync();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_REGISTER_COMMON_EVENT_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_REGISTER_COMMON_EVENT_TEST_001, TestSize.Level1)
{
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    EXPECT_CALL(hbStaticMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_SCREEN_STATE_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_SCREEN_LOCK_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_NIGHT_MODE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnRegisterCommonEvent();
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_OOBE_STATE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterCommonEvent();
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_USER_SWITCHED), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterCommonEvent();
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = LnnRegisterCommonEvent();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_REGISTER_NETWORK_EVENT_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_REGISTER_NETWORK_EVENT_TEST_001, TestSize.Level1)
{
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_IP_ADDR_CHANGED), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnRegisterNetworkEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_BT_STATE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterNetworkEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_LANE_VAP_CHANGE), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterNetworkEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);

    ret = LnnRegisterNetworkEvent();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_IS_HEARTBEAT_ENABLE_TEST_001
 * @tc.desc: IsHeartbeatEnable test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_IS_HEARTBEAT_ENABLE_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    SetScreenState(SOFTBUS_SCREEN_ON);
    EXPECT_CALL(ledgerMock, LnnIsDefaultOhosAccount).WillRepeatedly(Return(false));
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(hbStaticMock, AuthHasTrustedRelation).WillRepeatedly(Return(TRUSTED_RELATION_YES));
    EXPECT_CALL(hbStaticMock, IsEnableSoftBusHeartbeat).WillRepeatedly(Return(true));
    EXPECT_CALL(bleMock, SoftBusGetBtState).WillRepeatedly(Return(BLE_ENABLE));
    int32_t infoNum = 1;
    NodeBasicInfo *nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo));
    ASSERT_TRUE(nodeBasicInfo != NULL);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnIsLSANode).WillRepeatedly(Return(false));
    EXPECT_CALL(hbStaticMock, LnnStopScreenChangeOfflineTiming).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(hbStaticMock, LnnStartScreenChangeOfflineTiming).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    HbSendCheckOffLineMessage(HEARTBEAT_TYPE_BLE_V1);
    InitHbConditionState();
    bool ret = IsHeartbeatEnable();
    EXPECT_EQ(ret, false);
    g_hbConditionState.lockState = SOFTBUS_SCREEN_UNLOCK;
    g_hbConditionState.btState = SOFTBUS_BLE_TURN_ON;
    g_hbConditionState.lockState = SOFTBUS_SCREEN_UNLOCK;
    g_hbConditionState.accountState = SOFTBUS_ACCOUNT_LOG_IN;
    g_hbConditionState.OOBEState = SOFTBUS_OOBE_END;
    g_hbConditionState.heartbeatEnable = true;
    g_isScreenOnOnce = false;
    HbScreenOnOnceTryCloudSync();
    ret = IsHeartbeatEnable();
    EXPECT_EQ(ret, true);
    EXPECT_CALL(hbStaticMock, LnnEnableHeartbeatByType).WillOnce(Return(SOFTBUS_LOCK_ERR));
    HbConditionChanged(true);
    EXPECT_CALL(hbStaticMock, LnnEnableHeartbeatByType).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    EXPECT_CALL(hbStaticMock, LnnStopHeartbeatByType).WillRepeatedly(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    ret = IsHeartbeatEnable();
    EXPECT_EQ(ret, true);
    HbConditionChanged(true);
    g_hbConditionState.OOBEState = SOFTBUS_OOBE_RUNNING;
    ret = IsHeartbeatEnable();
    EXPECT_EQ(ret, false);
    HbConditionChanged(false);
    g_hbConditionState.OOBEState = SOFTBUS_OOBE_END;
    ret = IsHeartbeatEnable();
    EXPECT_EQ(ret, true);
    HbConditionChanged(false);
}

/*
 * @tc.name: LNN_START_HEARTBEAT_FRAME_DELAY_TEST_001
 * @tc.desc: LnnStartHeartbeatFrameDelay Abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_START_HEARTBEAT_FRAME_DELAY_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    RequestEnableDiscovery(NULL);
    g_hbConditionState.isRequestDisable = true;
    RequestEnableDiscovery(NULL);
    EXPECT_CALL(hbStaticMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    LnnHbOnTrustedRelationReduced();
    HbHandleBleStateChange(SOFTBUS_BR_TURN_ON);
    LnnRequestBleDiscoveryProcess(REQUEST_DISABLE_BLE_DISCOVERY, 0);
    EXPECT_CALL(hbStaticMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    LnnRequestBleDiscoveryProcess(REQUEST_DISABLE_BLE_DISCOVERY, 0);
    EXPECT_CALL(hbStaticMock, LnnHbMediumMgrInit).WillOnce(Return(SOFTBUS_NETWORK_HB_MGR_REG_FAIL))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnStartHeartbeatFrameDelay();
    EXPECT_NE(ret, SOFTBUS_OK);
    g_hbConditionState.isRequestDisable = true;
    LnnRequestBleDiscoveryProcess(REQUEST_DISABLE_BLE_DISCOVERY, 0);
    LnnRequestBleDiscoveryProcess(REQUEST_ENABLE_BLE_DISCOVERY, 0);
    LnnRequestBleDiscoveryProcess(MIN_DISABLE_BLE_DISCOVERY_TIME, 0);
    g_hbConditionState.screenState = SOFTBUS_SCREEN_OFF;
    EXPECT_CALL(hbStaticMock, LnnIsLocalSupportBurstFeature).WillRepeatedly(Return(false));
    EXPECT_CALL(hbStaticMock, LnnSetMediumParamBySpecificType).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    HbDelaySetNormalScanParam(NULL);
    HbDelaySetHighScanParam(NULL);
    g_hbConditionState.screenState = SOFTBUS_SCREEN_ON;
    HbDelaySetHighScanParam(NULL);
    EXPECT_CALL(hbStaticMock, LnnStartNewHbStrategyFsm).WillRepeatedly(Return(SOFTBUS_NETWORK_FSM_CREATE_FAIL));
    ret = LnnStartHeartbeatFrameDelay();
    EXPECT_NE(ret, SOFTBUS_OK);
    LnnMonitorHbStateChangedEvent event = { .basic.event = LNN_EVENT_BT_STATE_CHANGED,
        .status = (uint8_t)(SOFTBUS_BR_TURN_OFF) };
    HbBtStateChangeEventHandler((const LnnEventBasicInfo *)&event);
    EXPECT_CALL(bleMock, SoftBusGetBtState).WillRepeatedly(Return(BLE_DISABLE));
    HbBtStateChangeEventHandler((const LnnEventBasicInfo *)&event);
}

/*
 * @tc.name: LNN_SHIFT_LNN_GEAR_TEST_001
 * @tc.desc: LnnShiftLNNGear Abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_SHIFT_LNN_GEAR_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    GearMode mode;
    mode.action = CHANGE_TCP_KEEPALIVE;
    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    int32_t ret = LnnShiftLNNGear("test_ctrl", "test_ctrl", "12345678", &mode);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    EXPECT_CALL(hbStaticMock, AuthSendKeepaliveOption).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnShiftLNNGear("test_ctrl", "test_ctrl", "12345678", &mode);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(hbStaticMock, AuthSendKeepaliveOption).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnShiftLNNGear("test_ctrl", "test_ctrl", "12345678", &mode);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnLaneVapChangeEvent vapChangeEvent = { .basic.event = LNN_EVENT_LANE_VAP_CHANGE };
    HbLaneVapChangeEventHandler(NULL);
    EXPECT_CALL(bleMock, SoftBusGetBtState).WillOnce(Return(BLE_DISABLE));
    HbLaneVapChangeEventHandler((const LnnEventBasicInfo *)&vapChangeEvent);
    EXPECT_CALL(bleMock, SoftBusGetBtState).WillRepeatedly(Return(BLE_ENABLE));
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    HbLaneVapChangeEventHandler((const LnnEventBasicInfo *)&vapChangeEvent);
    LnnMasterNodeChangedEvent masterNodeEvent = { .basic.event = LNN_EVENT_NODE_MASTER_STATE_CHANGED };
    EXPECT_CALL(hbStaticMock, LnnSetHbAsMasterNodeState).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    HbMasterNodeChangeEventHandler((const LnnEventBasicInfo *)&masterNodeEvent);
    LnnHeartbeatType hbType = HEARTBEAT_TYPE_MAX;
    HbRemoveCheckOffLineMessage(hbType);
    hbType = HEARTBEAT_TYPE_BLE_V0;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return((SOFTBUS_INVALID_PARAM)));
    HbRemoveCheckOffLineMessage(hbType);
    int32_t infoNum = 1;
    NodeBasicInfo *nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo));
    ASSERT_TRUE(nodeBasicInfo != NULL);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    EXPECT_CALL(hbStaticMock, LnnStopScreenChangeOfflineTiming).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnIsLSANode).WillRepeatedly(Return(false));
    HbRemoveCheckOffLineMessage(hbType);
    SoftBusScreenState state = SOFTBUS_SCREEN_UNKNOWN;
    HbChangeMediumParamByState(state);
    state = SOFTBUS_SCREEN_ON;
    EXPECT_CALL(hbStaticMock, LnnIsLocalSupportBurstFeature).WillRepeatedly(Return(false));
    EXPECT_CALL(hbStaticMock, LnnSetMediumParamBySpecificType).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    HbChangeMediumParamByState(state);
}

/*
 * @tc.name: LNN_SHIFT_LNN_GEAR_TEST_002
 * @tc.desc: LnnShiftLNNGear Abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_SHIFT_LNN_GEAR_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    GearMode mode;
    mode.action = FLUSH_DEVICE_LIST;
    EXPECT_CALL(hbStaticMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnSetGearModeBySpecificType).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    int32_t ret = LnnShiftLNNGear("test_ctrl", "test_ctrl", "12345678", &mode);
    EXPECT_NE(ret, SOFTBUS_OK);
    HbDelayConditionChanged(NULL);
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    HbScreenOnChangeEventHandler(100000);
    LnnMonitorHbStateChangedEvent hbStateChangedEvent = { .basic.event = LNN_EVENT_SCREEN_STATE_CHANGED,
        .status = SOFTBUS_SCREEN_OFF };
    g_hbConditionState.screenState = SOFTBUS_SCREEN_ON;
    EXPECT_CALL(hbStaticMock, LnnIsLocalSupportBurstFeature).WillOnce(Return(false));
    HbScreenStateChangeEventHandler((const LnnEventBasicInfo *)&hbStateChangedEvent);
    EXPECT_CALL(hbStaticMock, LnnIsLocalSupportBurstFeature).WillRepeatedly(Return(true));
    EXPECT_CALL(hbStaticMock, LnnStopHeartBeatAdvByTypeNow).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    g_hbConditionState.screenState = SOFTBUS_SCREEN_ON;
    HbScreenStateChangeEventHandler((const LnnEventBasicInfo *)&hbStateChangedEvent);
    LnnMonitorHbStateChangedEvent lockEvent = { .basic.event = LNN_EVENT_SCREEN_LOCK_CHANGED,
        .status = SOFTBUS_SCREEN_UNLOCK };
    HbScreenLockChangeEventHandler(NULL);
    lockEvent.status = SOFTBUS_SCREEN_UNLOCK;
    g_hbConditionState.screenState = SOFTBUS_SCREEN_ON;
    g_hbConditionState.accountState = SOFTBUS_ACCOUNT_LOG_IN;
    EXPECT_CALL(ledgerMock, LnnIsDefaultOhosAccount).WillRepeatedly(Return(false));
    g_hbConditionState.lockState = SOFTBUS_SCREEN_LOCK_UNKNOWN;
    HbScreenLockChangeEventHandler((const LnnEventBasicInfo *)&lockEvent);
    g_hbConditionState.accountState = SOFTBUS_ACCOUNT_LOG_OUT;
    g_hbConditionState.lockState = SOFTBUS_SCREEN_LOCK_UNKNOWN;
    HbScreenLockChangeEventHandler((const LnnEventBasicInfo *)&lockEvent);
    lockEvent.status = SOFTBUS_USER_UNLOCK;
    g_hbConditionState.lockState = SOFTBUS_SCREEN_LOCK_UNKNOWN;
    HbScreenLockChangeEventHandler((const LnnEventBasicInfo *)&lockEvent);
    g_hbConditionState.lockState = SOFTBUS_SCREEN_LOCK_UNKNOWN;
    lockEvent.status = SOFTBUS_SCREEN_LOCK_UNKNOWN;
    HbScreenLockChangeEventHandler((const LnnEventBasicInfo *)&lockEvent);
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, AuthFlushDevice).WillRepeatedly(Return(SOFTBUS_AUTH_POST_MSG_FAIL));
    ret = LnnShiftLNNGear("test_ctrl", "test_ctrl", "12345678", &mode);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: LNN_INIT_HEARTBEAT_TEST_001
 * @tc.desc: LnnInitHeartbeat Abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_INIT_HEARTBEAT_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    LnnMonitorHbStateChangedEvent OOBEEvent = { .basic.event = LNN_EVENT_NIGHT_MODE_CHANGED,
        .status = SOFTBUS_FACK_OOBE_END };
    HbOOBEStateEventHandler((const LnnEventBasicInfo *)&OOBEEvent);
    OOBEEvent.basic.event = LNN_EVENT_OOBE_STATE_CHANGED;
    HbOOBEStateEventHandler((const LnnEventBasicInfo *)&OOBEEvent);
    OOBEEvent.status = SOFTBUS_OOBE_END;
    HbOOBEStateEventHandler((const LnnEventBasicInfo *)&OOBEEvent);
    OOBEEvent.status = SOFTBUS_OOBE_UNKNOWN;
    HbOOBEStateEventHandler((const LnnEventBasicInfo *)&OOBEEvent);
    EXPECT_CALL(hbStaticMock, LnnHbStrategyInit).WillOnce(Return(SOFTBUS_LOCK_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitHeartbeat();
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_SCREEN_STATE_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_SCREEN_LOCK_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_NIGHT_MODE_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_OOBE_STATE_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_USER_SWITCHED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_IP_ADDR_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_BT_STATE_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_LANE_VAP_CHANGE), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnInitHeartbeat();
    EXPECT_NE(ret, SOFTBUS_OK);
    LnnMonitorHbStateChangedEvent userSwitchEvent = { .basic.event = LNN_EVENT_NIGHT_MODE_CHANGED,
        .status = (uint8_t)SOFTBUS_USER_SWITCHED };
    HbUserSwitchedHandler((const LnnEventBasicInfo *)&userSwitchEvent);
    userSwitchEvent.basic.event = LNN_EVENT_USER_SWITCHED;
    HbUserSwitchedHandler((const LnnEventBasicInfo *)&userSwitchEvent);
    userSwitchEvent.status = SOFTBUS_USER_SWITCH_UNKNOWN;
    HbUserSwitchedHandler((const LnnEventBasicInfo *)&userSwitchEvent);
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_NODE_MASTER_STATE_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitHeartbeat();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_TRIGGER_DATA_LEVEL_HEARTBEAT_TEST_001
 * @tc.desc: LnnTriggerDataLevelHeartbeat Abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_TRIGGER_DATA_LEVEL_HEARTBEAT_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    LnnMonitorHbStateChangedEvent nightModeEvent = { .basic.event = LNN_EVENT_HOME_GROUP_CHANGED,
        .status = (uint8_t)SOFTBUS_NIGHT_MODE_ON };
    HbNightModeStateEventHandler((const LnnEventBasicInfo *)&nightModeEvent);
    nightModeEvent.basic.event = LNN_EVENT_NIGHT_MODE_CHANGED;
    HbNightModeStateEventHandler((const LnnEventBasicInfo *)&nightModeEvent);
    nightModeEvent.status = SOFTBUS_NIGHT_MODE_ON;
    HbNightModeStateEventHandler((const LnnEventBasicInfo *)&nightModeEvent);
    nightModeEvent.status = SOFTBUS_NIGHT_MODE_UNKNOWN;
    HbNightModeStateEventHandler((const LnnEventBasicInfo *)&nightModeEvent);
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnTriggerDataLevelHeartbeat();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(hbStaticMock, AuthHasTrustedRelation).WillRepeatedly(Return(TRUSTED_RELATION_YES));
    EXPECT_CALL(ledgerMock, LnnIsDefaultOhosAccount).WillRepeatedly(Return(true));
    HbDelayCheckTrustedRelation(NULL);
    EXPECT_CALL(hbStaticMock, AuthHasTrustedRelation).WillRepeatedly(Return(TRUSTED_RELATION_NO));
    HbDelayCheckTrustedRelation(NULL);
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    LnnLpReportEvent LPEvent = { .basic.event = LNN_EVENT_USER_SWITCHED,
        .type = SOFTBUS_MSDP_MOVEMENT_AND_STATIONARY };
    HbLpEventHandler((const LnnEventBasicInfo *)&LPEvent);
    LPEvent.basic.event = LNN_EVENT_LP_EVENT_REPORT;
    HbLpEventHandler((const LnnEventBasicInfo *)&LPEvent);
    LPEvent.type = SOFTBUS_LP_EVENT_UNKNOWN;
    HbLpEventHandler((const LnnEventBasicInfo *)&LPEvent);
    ret = LnnTriggerDataLevelHeartbeat();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_TRIGGER_DIRECT_HEARTBEAT_TEST_001
 * @tc.desc: LnnTriggerDirectHeartbeat Abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_TRIGGER_DIRECT_HEARTBEAT_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    char networkId[] = "12222";
    LnnStopOfflineTimingByHeartbeat(NULL, CONNECTION_ADDR_BR);
    LnnStopOfflineTimingByHeartbeat(networkId, CONNECTION_ADDR_BR);
    LnnStopOfflineTimingByHeartbeat(networkId, CONNECTION_ADDR_BLE);
    LnnMonitorHbStateChangedEvent userBackEvent = { .basic.event = LNN_EVENT_HOME_GROUP_CHANGED,
        .status = SOFTBUS_USER_FOREGROUND };
    HbUserBackgroundEventHandler((const LnnEventBasicInfo *)&userBackEvent);
    userBackEvent.basic.event = LNN_EVENT_USER_STATE_CHANGED;
    HbUserBackgroundEventHandler((const LnnEventBasicInfo *)&userBackEvent);
    userBackEvent.status = SOFTBUS_USER_BACKGROUND;
    HbUserBackgroundEventHandler((const LnnEventBasicInfo *)&userBackEvent);
    userBackEvent.status = SOFTBUS_USER_UNKNOWN;
    HbUserBackgroundEventHandler((const LnnEventBasicInfo *)&userBackEvent);
    int32_t ret = LnnTriggerDirectHeartbeat(NULL, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_TRIGGER_CLOUD_SYNC_HEARTBEAT_TEST_001
 * @tc.desc: LnnTriggerCloudSyncHeartbeat Abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_TRIGGER_CLOUD_SYNC_HEARTBEAT_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    LnnMonitorHbStateChangedEvent differentEvent = { .basic.event = LNN_EVENT_HOME_GROUP_CHANGED,
        .status = (uint8_t)LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED };
    HbDifferentAccountEventHandler((const LnnEventBasicInfo *)&differentEvent);
    differentEvent.basic.event = LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED;
    HbDifferentAccountEventHandler((const LnnEventBasicInfo *)&differentEvent);
    LnnMonitorHbStateChangedEvent accountEvent = { .basic.event = LNN_EVENT_SCREEN_LOCK_CHANGED,
        .status = (uint8_t)SOFTBUS_ACCOUNT_UNKNOWN };
    HbAccountStateChangeEventHandler((const LnnEventBasicInfo *)&accountEvent);
    accountEvent.basic.event = LNN_EVENT_ACCOUNT_CHANGED;
    HbAccountStateChangeEventHandler((const LnnEventBasicInfo *)&accountEvent);
    LnnUnregDataLevelChangeCb();
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillOnce(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    int32_t ret = LnnTriggerCloudSyncHeartbeat();
    EXPECT_NE(ret, SOFTBUS_OK);
    accountEvent.status = (uint8_t)SOFTBUS_ACCOUNT_LOG_IN;
    HbAccountStateChangeEventHandler((const LnnEventBasicInfo *)&accountEvent);
    EXPECT_CALL(hbStaticMock, LnnDeleteSyncToDB).WillRepeatedly(Return(SOFTBUS_NOT_IMPLEMENT));
    accountEvent.status = (uint8_t)SOFTBUS_ACCOUNT_LOG_OUT;
    HbAccountStateChangeEventHandler((const LnnEventBasicInfo *)&accountEvent);
    LnnMonitorHbStateChangedEvent homeGroupEvent = { .basic.event = LNN_EVENT_HOME_GROUP_CHANGED,
        .status = (uint8_t)SOFTBUS_HOME_GROUP_CHANGE };
    HbHomeGroupStateChangeEventHandler((const LnnEventBasicInfo *)&homeGroupEvent);
    homeGroupEvent.status = (uint8_t)SOFTBUS_HOME_GROUP_LEAVE;
    HbHomeGroupStateChangeEventHandler((const LnnEventBasicInfo *)&homeGroupEvent);
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnTriggerCloudSyncHeartbeat();
    EXPECT_EQ(ret, SOFTBUS_OK);
    homeGroupEvent.status = (uint8_t)SOFTBUS_HOME_GROUP_JOIN;
    HbHomeGroupStateChangeEventHandler((const LnnEventBasicInfo *)&homeGroupEvent);
    EXPECT_CALL(hbStaticMock, LnnStartHeartbeat).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnHbOnTrustedRelationIncreased(AUTH_PEER_TO_PEER_GROUP);
    EXPECT_CALL(hbStaticMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    LnnHbOnTrustedRelationIncreased(AUTH_PEER_TO_PEER_GROUP);
}

/*
 * @tc.name: LNN_REQUEST_BLE_DISCOVERY_PROCESS_TEST_001
 * @tc.desc: LnnRequestBleDiscoveryProcess test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, LNN_REQUEST_BLE_DISCOVERY_PROCESS_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    NiceMock<BleMock> bleMock;
    EXPECT_CALL(ledgerMock, LnnIsDefaultOhosAccount).WillOnce(Return(true)).WillRepeatedly(Return(false));
    EXPECT_CALL(hbStaticMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(hbStaticMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(LnnRequestBleDiscoveryProcess(SAME_ACCOUNT_REQUEST_DISABLE_BLE_DISCOVERY, 0));
    EXPECT_CALL(hbStaticMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnRequestBleDiscoveryProcess(SAME_ACCOUNT_REQUEST_DISABLE_BLE_DISCOVERY, 0));
    EXPECT_CALL(hbStaticMock, LnnHbMediumMgrInit).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnStartHeartbeatFrameDelay();
    EXPECT_NE(ret, SOFTBUS_OK);
    g_hbConditionState.isRequestDisable = true;
    EXPECT_NO_FATAL_FAILURE(LnnRequestBleDiscoveryProcess(SAME_ACCOUNT_REQUEST_DISABLE_BLE_DISCOVERY, 0));
    EXPECT_NO_FATAL_FAILURE(LnnRequestBleDiscoveryProcess(SAME_ACCOUNT_REQUEST_ENABLE_BLE_DISCOVERY, 0));
}

/*
 * @tc.name: SAME_ACCOUNT_DEV_DISABLE_DISCOVERY_PROCESS_TEST_001
 * @tc.desc: SameAccountDevDisableDiscoveryProcess test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, SAME_ACCOUNT_DEV_DISABLE_DISCOVERY_PROCESS_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo1);
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    EXPECT_CALL(hbStaticMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<2>(nodeInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = SameAccountDevDisableDiscoveryProcess();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SAME_ACCOUNT_DEV_DISABLE_DISCOVERY_PROCESS_TEST_002
 * @tc.desc: SameAccountDevDisableDiscoveryProcess test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, SAME_ACCOUNT_DEV_DISABLE_DISCOVERY_PROCESS_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(DoAll(SetArgPointee<0>(info),
        SetArgPointee<1>(infoNum), Return(SOFTBUS_INVALID_PARAM)));
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    EXPECT_CALL(hbStaticMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = SameAccountDevDisableDiscoveryProcess();
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(DoAll(SetArgPointee<0>(info),
        SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    ret = SameAccountDevDisableDiscoveryProcess();
    EXPECT_EQ(ret, SOFTBUS_NO_ONLINE_DEVICE);
}

/*
 * @tc.name: REQUEST_DISABLE_DISCOVERY_TEST_001
 * @tc.desc: RequestDisableDiscovery test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlStaticTest, REQUEST_DISABLE_DISCOVERY_TEST_001, TestSize.Level1)
{
    NiceMock<BleMock> bleMock;
    EXPECT_CALL(bleMock, SoftBusGetBtState).WillRepeatedly(Return(BLE_DISABLE));
    NiceMock<HeartBeatCtrlStaticInterfaceMock> hbStaticMock;
    EXPECT_CALL(hbStaticMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnUpdateOhosAccount).WillRepeatedly(Return());
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnIsDefaultOhosAccount).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(hbStaticMock, AuthHasTrustedRelation).WillRepeatedly(Return(TRUSTED_RELATION_YES));
    EXPECT_CALL(hbStaticMock, IsEnableSoftBusHeartbeat).WillRepeatedly(Return(true));
    g_hbConditionState.isRequestDisable = false;
    int64_t modeDuration = -1;
    EXPECT_NO_FATAL_FAILURE(RequestDisableDiscovery(modeDuration));
    g_hbConditionState.isRequestDisable = true;
    EXPECT_NO_FATAL_FAILURE(RequestDisableDiscovery(modeDuration));
}
} // namespace OHOS
