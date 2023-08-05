/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "bus_center_manager.h"
#include "distribute_net_ledger_mock.h"
#include "hb_fsm_mock.h"
#include "hb_strategy_mock.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_connection_mock.h"
#include "lnn_heartbeat_fsm.c"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_state_machine.h"
#include "message_handler.h"
#include "softbus_common.h"

namespace OHOS {
#define TEST_NETWORK_ID  "6542316a57d"
#define TEST_NETWORK_ID2 "654231655557d"
#define TEST_UDID        "1111222233334444"
#define TEST_DISC_TYPE   5321
#define TEST_ARGS        22
#define TEST_TIME1       450
#define TEST_TIME2       500
#define TEST_TIME3       2000000
constexpr int32_t MSGTYPE = 2;
using namespace testing::ext;
using namespace testing;

class HeartBeatFSMTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HeartBeatFSMTest::SetUpTestCase()
{
    int32_t ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void HeartBeatFSMTest::TearDownTestCase() { }

void HeartBeatFSMTest::SetUp() { }

void HeartBeatFSMTest::TearDown() { }

/*
 * @tc.name: CheckHbFsmStateMsgArgs
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, CheckHbFsmStateMsgArgsTest_01, TestSize.Level1)
{
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    bool ret = CheckHbFsmStateMsgArgs(nullptr);
    EXPECT_FALSE(ret);
    ret = CheckHbFsmStateMsgArgs(const_cast<const FsmStateMachine *>(&hbFsm->fsm));
    EXPECT_TRUE(ret);
    hbFsm->state = STATE_HB_INDEX_MAX;
    ret = CheckHbFsmStateMsgArgs(const_cast<const FsmStateMachine *>(&hbFsm->fsm));
    EXPECT_FALSE(ret);
    SoftBusSleepMs(20);
    LnnDestroyHeartbeatFsm(hbFsm);
}

/*
 * @tc.name: CheckRemoveHbMsgParams
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, CheckRemoveHbMsgParamsTest_01, TestSize.Level1)
{
    SoftBusMessage ctrlMsgObj = {
        .what = TEST_ARGS,
    };
    SoftBusMessage delMsg = {
        .what = TEST_ARGS,
    };
    bool ret = CheckRemoveHbMsgParams(const_cast<const SoftBusMessage *>(&ctrlMsgObj), nullptr);
    EXPECT_FALSE(ret);
    ret = CheckRemoveHbMsgParams(const_cast<const SoftBusMessage *>(&ctrlMsgObj), reinterpret_cast<void *>(&delMsg));
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LnnRemoveSendEndMsg
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, LnnRemoveSendEndMsgTest_01, TestSize.Level1)
{
    bool isRemoved = true;
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    LnnRemoveSendEndMsg(nullptr, HEARTBEAT_TYPE_BLE_V1, true, true, &isRemoved);
    LnnRemoveCheckDevStatusMsg(nullptr, nullptr);
    LnnRemoveProcessSendOnceMsg(nullptr, HEARTBEAT_TYPE_BLE_V1, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
    HbMasterNodeStateEnter(nullptr);
    HbMasterNodeStateExit(nullptr);
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    EXPECT_TRUE(hbFsm != nullptr);
    HbMasterNodeStateExit(&hbFsm->fsm);
    HbNormalNodeStateEnter(nullptr);
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrStop).WillRepeatedly(Return(SOFTBUS_ERR));
    HbNoneStateEnter(&hbFsm->fsm);
    HbNoneStateEnter(nullptr);
    EXPECT_TRUE(hbFsm != nullptr);
    SoftBusSleepMs(50);
    LnnDestroyHeartbeatFsm(hbFsm);
}

/*
 * @tc.name: OnProcessSendOnce
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, OnProcessSendOnceTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    EXPECT_CALL(heartbeatFsmMock, LnnGetHbStrategyManager)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));

    LnnProcessSendOnceMsgPara *para =
        reinterpret_cast<LnnProcessSendOnceMsgPara *>(SoftBusCalloc(sizeof(LnnProcessSendOnceMsgPara)));
    para->hbType = HEARTBEAT_TYPE_BLE_V0;

    int32_t ret = OnProcessSendOnce(&hbFsm->fsm, TEST_ARGS, reinterpret_cast<void *>(para));
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    void *para2 = SoftBusCalloc(sizeof(LnnProcessSendOnceMsgPara));
    ret = OnProcessSendOnce(&hbFsm->fsm, TEST_ARGS, para2);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = OnProcessSendOnce(&hbFsm->fsm, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    void *para3 = SoftBusCalloc(sizeof(LnnProcessSendOnceMsgPara));
    ret = OnProcessSendOnce(nullptr, TEST_ARGS, reinterpret_cast<void *>(para3));
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusSleepMs(50);
    LnnDestroyHeartbeatFsm(hbFsm);
}

/*
 * @tc.name: RemoveCheckDevStatusMsg
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveCheckDevStatusMsgTest_01, TestSize.Level1)
{
    LnnCheckDevStatusMsgPara msgPara = {
        .hbType = HEARTBEAT_TYPE_BLE_V1,
        .hasNetworkId = true,
        .networkId = TEST_NETWORK_ID,
    };
    LnnCheckDevStatusMsgPara delMsgPara = {
        .hbType = HEARTBEAT_TYPE_BLE_V0,
        .hasNetworkId = true,
        .networkId = TEST_NETWORK_ID2,
    };
    FsmCtrlMsgObj ctrlMsgObj = {
        .obj = reinterpret_cast<void *>(&msgPara),
    };
    SoftBusMessage delMsg = {
        .obj = reinterpret_cast<void *>(&delMsgPara),
    };

    int32_t ret = RemoveCheckDevStatusMsg(&ctrlMsgObj, &delMsg);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    if (strcpy_s(const_cast<char *>(delMsgPara.networkId), sizeof(TEST_NETWORK_ID2), TEST_NETWORK_ID) != SOFTBUS_OK) {
        LLOGE("strcpy failed");
    }
    ret = RemoveCheckDevStatusMsg(&ctrlMsgObj, &delMsg);
    EXPECT_FALSE(ret == SOFTBUS_OK);

    delMsgPara.hasNetworkId = false;
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);
    ret = RemoveCheckDevStatusMsg(&ctrlMsgObj, &delMsg);
    EXPECT_FALSE(ret == SOFTBUS_OK);

    delMsgPara.hbType = HEARTBEAT_TYPE_BLE_V1;
    if (strcpy_s(const_cast<char *>(delMsgPara.networkId), sizeof(TEST_NETWORK_ID2), TEST_NETWORK_ID2) != SOFTBUS_OK) {
        LLOGE("strcpy failed");
    }
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);
    ret = RemoveCheckDevStatusMsg(&ctrlMsgObj, &delMsg);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: RemoveSendOnceMsg
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveSendOnceMsgTest_01, TestSize.Level1)
{
    LnnProcessSendOnceMsgPara *msgPara =
        reinterpret_cast<LnnProcessSendOnceMsgPara *>(SoftBusCalloc(sizeof(LnnProcessSendOnceMsgPara)));
    msgPara->hbType = HEARTBEAT_TYPE_BLE_V1;
    msgPara->strategyType = STRATEGY_HB_SEND_FIXED_PERIOD;
    LnnProcessSendOnceMsgPara delMsgPara = {
        .hbType = HEARTBEAT_TYPE_BLE_V1,
        .strategyType = STRATEGY_HB_SEND_FIXED_PERIOD,
    };
    FsmCtrlMsgObj ctrlMsgObj = {
        .obj = reinterpret_cast<void *>(&msgPara),
    };
    SoftBusMessage delMsg = {
        .obj = reinterpret_cast<void *>(&delMsgPara),
    };
    int32_t ret = RemoveSendOnceMsg(&ctrlMsgObj, &delMsg);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LnnProcessSendOnceMsgPara *msgPara2 =
        reinterpret_cast<LnnProcessSendOnceMsgPara *>(SoftBusCalloc(sizeof(LnnProcessSendOnceMsgPara)));
    msgPara->hbType = HEARTBEAT_TYPE_BLE_V1;
    msgPara->strategyType = STRATEGY_HB_SEND_FIXED_PERIOD;
    FsmCtrlMsgObj ctrlMsgObj2 = {
        .obj = reinterpret_cast<void *>(&msgPara2),
    };
    delMsgPara.strategyType = STRATEGY_HB_RECV_SINGLE;
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);
    ret = RemoveSendOnceMsg(&ctrlMsgObj2, &delMsg);
    EXPECT_FALSE(ret == SOFTBUS_OK);
    delMsgPara.hbType = HEARTBEAT_TYPE_BLE_V0;
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);
    ret = RemoveSendOnceMsg(&ctrlMsgObj2, &delMsg);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnSendOneHbBegin
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, OnSendOneHbBeginTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    void *para = SoftBusCalloc(sizeof(LnnHeartbeatSendBeginData));
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrSendBegin).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = OnSendOneHbBegin(nullptr, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = OnSendOneHbBegin(nullptr, TEST_ARGS, para);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: OnSendOneHbEnd
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, OnSendOneHbEndTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrSendEnd).WillRepeatedly(Return(SOFTBUS_ERR));
    void *para = SoftBusCalloc(sizeof(LnnHeartbeatType));
    int32_t ret = OnSendOneHbEnd(nullptr, TEST_ARGS, nullptr);
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = OnSendOneHbEnd(nullptr, TEST_ARGS, para);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    void *para2 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnSendOneHbEnd(nullptr, TEST_ARGS, para2);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    void *para3 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnSendOneHbEnd(&hbFsm->fsm, TEST_ARGS, para3);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    void *para4 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnStartHbProcess(nullptr, TEST_ARGS, para4);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusSleepMs(20);
    LnnDestroyHeartbeatFsm(hbFsm);
}

/*
 * @tc.name: OnStopHbByType
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, OnStopHbByTypeTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrStop).WillRepeatedly(Return(SOFTBUS_ERR));
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    void *para = SoftBusCalloc(sizeof(LnnHeartbeatType));
    int32_t ret = OnStopHbByType(nullptr, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = OnStopHbByType(nullptr, TEST_ARGS, para);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    void *para2 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnStopHbByType(&hbFsm->fsm, TEST_ARGS, para2);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = OnSetMediumParam(nullptr, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrSetParam).WillRepeatedly(Return(SOFTBUS_ERR));
    void *para3 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnSetMediumParam(nullptr, TEST_ARGS, para3);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusSleepMs(20);
    LnnDestroyHeartbeatFsm(hbFsm);
}

/*
 * @tc.name: OnTransHbFsmState
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, OnTransHbFsmStateTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    ON_CALL(heartbeatFsmMock, LnnGetGearModeBySpecificType).WillByDefault(Return(SOFTBUS_ERR));
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    TryAsMasterNodeNextLoop(&hbFsm->fsm);
    SoftBusSleepMs(20);
    LnnDestroyHeartbeatFsm(hbFsm);

    int32_t msgType = MSGTYPE;
    int32_t ret = OnTransHbFsmState(nullptr, msgType, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ProcessLostHeartbeat
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, ProcessLostHeartbeatTest_01, TestSize.Level1)
{
    DistributeLedgerInterfaceMock distriLedgerMock;
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    LnnConnectInterfaceMock connMock;
    ON_CALL(distriLedgerMock, LnnConvertDLidToUdid).WillByDefault(Return(TEST_UDID));
    ON_CALL(heartbeatFsmMock, LnnRequestLeaveSpecific).WillByDefault(Return(SOFTBUS_OK));
    EXPECT_CALL(distriLedgerMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(heartbeatFsmMock, LnnRequestLeaveSpecific).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = ProcessLostHeartbeat(nullptr, CONNECTION_ADDR_BLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(distriLedgerMock, LnnGetOnlineStateById).WillOnce(Return(false)).WillRepeatedly(Return(true));
    ret = ProcessLostHeartbeat(TEST_NETWORK_ID, CONNECTION_ADDR_BLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = ProcessLostHeartbeat(TEST_NETWORK_ID, CONNECTION_ADDR_BR);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = ProcessLostHeartbeat(TEST_NETWORK_ID, CONNECTION_ADDR_BLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = ProcessLostHeartbeat(TEST_NETWORK_ID, CONNECTION_ADDR_ETH);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusSleepMs(20);
}

/*
 * @tc.name: IsTimestampExceedLimit
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, IsTimestampExceedLimitTest_01, TestSize.Level1)
{
    NiceMock<DistributeLedgerInterfaceMock> distriLedgerMock;
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    EXPECT_CALL(heartbeatFsmMock, LnnGetGearModeBySpecificType)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    bool ret = IsTimestampExceedLimit(TEST_TIME2, TEST_TIME1, HEARTBEAT_TYPE_BLE_V0);
    EXPECT_FALSE(ret);
    ret = IsTimestampExceedLimit(TEST_TIME3, TEST_TIME1, HEARTBEAT_TYPE_BLE_V0);
    EXPECT_TRUE(ret);
    ret = IsTimestampExceedLimit(TEST_TIME2, TEST_TIME1, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_FALSE(ret);
    ret = IsTimestampExceedLimit(TEST_TIME2, TEST_TIME1, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_FALSE(ret);
    ret = IsTimestampExceedLimit(TEST_TIME3, TEST_TIME1, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: CheckDevStatusByNetworkId
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, CheckDevStatusByNetworkIdTest_01, TestSize.Level1)
{
    NiceMock<DistributeLedgerInterfaceMock> distriLedgerMock;
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NodeInfo nodeInfo = {
        .discoveryType = TEST_DISC_TYPE,
        .deviceInfo.deviceUdid = TEST_UDID,
    };
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    uint64_t oldTimeStamp = TEST_TIME3;
    ON_CALL(ledgerMock, LnnGetNodeInfoById).WillByDefault(Return(&nodeInfo));
    ON_CALL(heartbeatFsmMock, LnnStopOfflineTimingStrategy).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(heartbeatFsmMock, LnnGetGearModeBySpecificType).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(distriLedgerMock, LnnGetDLHeartbeatTimestamp)
        .WillByDefault(DoAll(SetArgPointee<1>(oldTimeStamp), Return(SOFTBUS_OK)));
    ON_CALL(ledgerMock, LnnHasDiscoveryType).WillByDefault(Return(true));
    ON_CALL(heartbeatFsmMock, LnnConvAddrTypeToDiscType).WillByDefault(Return(DISCOVERY_TYPE_BLE));
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, HEARTBEAT_TYPE_BLE_V0, TEST_TIME1);
    EXPECT_CALL(ledgerMock, LnnGetNodeInfoById).WillOnce(Return(nullptr)).WillRepeatedly(Return(&nodeInfo));
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, HEARTBEAT_TYPE_BLE_V0, TEST_TIME1);
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillOnce(Return(false)).WillRepeatedly(Return(true));
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, HEARTBEAT_TYPE_BLE_V0, TEST_TIME1);
    EXPECT_CALL(distriLedgerMock, LnnGetDLHeartbeatTimestamp)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(DoAll(SetArgPointee<1>(oldTimeStamp), Return(SOFTBUS_OK)));
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, HEARTBEAT_TYPE_BLE_V0, TEST_TIME1);
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, HEARTBEAT_TYPE_BLE_V0, TEST_TIME3);
    EXPECT_CALL(heartbeatFsmMock, LnnStopOfflineTimingStrategy)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_ERR));
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, HEARTBEAT_TYPE_BLE_V0, TEST_TIME1);
    SoftBusSleepMs(20);
    LnnDestroyHeartbeatFsm(hbFsm);
}

/*
 * @tc.name: OnCheckDevStatus
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, OnCheckDevStatusTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    FsmStateMachine fsm;
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    ON_CALL(netLedgerMock, LnnGetAllOnlineNodeInfo).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = OnCheckDevStatus(nullptr, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    void *para = SoftBusCalloc(sizeof(LnnCheckDevStatusMsgPara));
    ret = OnCheckDevStatus(nullptr, TEST_ARGS, para);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    LnnCheckDevStatusMsgPara *para2 =
        reinterpret_cast<LnnCheckDevStatusMsgPara *>(SoftBusCalloc(sizeof(LnnCheckDevStatusMsgPara)));
    para2->hasNetworkId = true;
    ret = OnCheckDevStatus(&hbFsm->fsm, TEST_ARGS, reinterpret_cast<void *>(para2));
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LnnCheckDevStatusMsgPara *para3 =
        reinterpret_cast<LnnCheckDevStatusMsgPara *>(SoftBusCalloc(sizeof(LnnCheckDevStatusMsgPara)));
    para2->hasNetworkId = false;
    ret = OnCheckDevStatus(&hbFsm->fsm, TEST_ARGS, reinterpret_cast<void *>(para3));
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyHeartbeatFsm(nullptr);
    DeinitHbFsmCallback(nullptr);
    ret = LnnStartHeartbeatFsm(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    hbFsm->fsm = fsm;
    ret = LnnStartHeartbeatFsm(hbFsm);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnStopHeartbeatFsm(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStopHeartbeatFsm(hbFsm);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusSleepMs(20);
    LnnDestroyHeartbeatFsm(hbFsm);
}
/*
 * @tc.name: LnnPostNextSendOnceMsgToHbFsm
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, LnnPostNextSendOnceMsgToHbFsmTest_01, TestSize.Level1)
{
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    FsmStateMachine fsm;
    LnnHeartbeatSendEndData *custData = nullptr;
    int32_t ret = LnnPostNextSendOnceMsgToHbFsm(nullptr, nullptr, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnProcessSendOnceMsgPara para;
    hbFsm->fsm = fsm;
    ret = LnnPostNextSendOnceMsgToHbFsm(hbFsm, &para, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnPostSendEndMsgToHbFsm(nullptr, custData, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostSendEndMsgToHbFsm(hbFsm, custData, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnPostStartMsgToHbFsm(nullptr, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostStopMsgToHbFsm(nullptr, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostStopMsgToHbFsm(hbFsm, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnPostTransStateMsgToHbFsm(nullptr, EVENT_HB_SEND_ONE_END);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostTransStateMsgToHbFsm(nullptr, EVENT_HB_MAX);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostSetMediumParamMsgToHbFsm(nullptr, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnHeartbeatMediumParam para2;
    ret = LnnPostSetMediumParamMsgToHbFsm(hbFsm, &para2);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnPostCheckDevStatusMsgToHbFsm(nullptr, nullptr, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostCheckDevStatusMsgToHbFsm(hbFsm, nullptr, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusSleepMs(20);
    LnnDestroyHeartbeatFsm(hbFsm);
}
} // namespace OHOS