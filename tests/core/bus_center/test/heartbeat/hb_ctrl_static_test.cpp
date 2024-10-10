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
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_ctrl.c"
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
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(DoAll(SetArgPointee<0>(info),
        SetArgPointee<1>(infoNum), Return(SOFTBUS_ERR)));
    int32_t ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(DoAll(SetArgPointee<0>(info),
        SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    NodeBasicInfo *info1 = nullptr;
    int32_t infoNum1 = 1;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(DoAll(SetArgPointee<0>(info1),
        SetArgPointee<1>(infoNum1), Return(SOFTBUS_ERR)));
    ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    NodeBasicInfo *info2 = nullptr;
    int32_t infoNum2 = 0;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(DoAll(SetArgPointee<0>(info2),
        SetArgPointee<1>(infoNum2), Return(SOFTBUS_OK)));
    ret = HbHandleLeaveLnn();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
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
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_ERR));
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
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_HOME_GROUP_CHANGED), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_ACCOUNT_CHANGED), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_USER_STATE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_LP_EVENT_REPORT), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterHeartbeatEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

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
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    LnnHeartbeatType hbType;
    (void)memset_s(&hbType, sizeof(LnnHeartbeatType), 0, sizeof(LnnHeartbeatType));
    HbSendCheckOffLineMessage(hbType);

    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    InitHbSpecificConditionState();
    InitHbSpecificConditionState();

    LnnEventBasicInfo info;
    (void)memset_s(&info, sizeof(LnnEventBasicInfo), 0, sizeof(LnnEventBasicInfo));
    info.event = LNN_EVENT_IP_ADDR_CHANGED;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnEnableHeartbeatByType(Eq(HEARTBEAT_TYPE_TCP_FLUSH), false))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnEnableHeartbeatByType(Eq(HEARTBEAT_TYPE_TCP_FLUSH), true))
        .WillOnce(Return(SOFTBUS_ERR))
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
        .WillRepeatedly(Return(SOFTBUS_ERR));
    ret = HbTryCloudSync();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = HbTryCloudSync();
    EXPECT_EQ(ret, SOFTBUS_ERR);
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
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_SCREEN_STATE_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_SCREEN_LOCK_CHANGED), _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_NIGHT_MODE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnRegisterCommonEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_OOBE_STATE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterCommonEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_USER_SWITCHED), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterCommonEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

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
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnRegisterNetworkEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_BT_STATE_CHANGED), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterNetworkEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(hbStaticMock, LnnRegisterEventHandler(Eq(LNN_EVENT_LANE_VAP_CHANGE), _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterNetworkEvent();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = LnnRegisterNetworkEvent();
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
