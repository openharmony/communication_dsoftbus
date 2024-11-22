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
#include "lnn_log.h"
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
#define CHECK_DELAY_LEN  10000
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

static bool IsDeviceOnline(const char *remoteMac)
{
    return true;
}

static int32_t GetLocalIpByUuid(const char *uuid, char *localIp, int32_t localIpSize)
{
    return SOFTBUS_OK;
}

static struct WifiDirectManager manager = {
    .isDeviceOnline = IsDeviceOnline,
    .getLocalIpByUuid = GetLocalIpByUuid,
};

void HeartBeatFSMTest::SetUpTestCase() { }

void HeartBeatFSMTest::TearDownTestCase() { }

void HeartBeatFSMTest::SetUp()
{
    int32_t ret = LooperInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLnnLooper();
    ASSERT_TRUE(ret == SOFTBUS_OK);
}

void HeartBeatFSMTest::TearDown()
{
    LooperDeinit();
    LnnDeinitLnnLooper();
}

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
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrStop).WillRepeatedly(Return(SOFTBUS_NETWORK_HB_STOP_PROCESS_FAIL));
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
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    LnnProcessSendOnceMsgPara *para =
        reinterpret_cast<LnnProcessSendOnceMsgPara *>(SoftBusCalloc(sizeof(LnnProcessSendOnceMsgPara)));
    para->hbType = HEARTBEAT_TYPE_BLE_V0;

    int32_t ret = OnProcessSendOnce(&hbFsm->fsm, TEST_ARGS, reinterpret_cast<void *>(para));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HEARTBEAT_SEND_ERR);

    void *para2 = SoftBusCalloc(sizeof(LnnProcessSendOnceMsgPara));
    ret = OnProcessSendOnce(&hbFsm->fsm, TEST_ARGS, para2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HEARTBEAT_SEND_ERR);

    ret = OnProcessSendOnce(&hbFsm->fsm, TEST_ARGS, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    void *para3 = SoftBusCalloc(sizeof(LnnProcessSendOnceMsgPara));
    ret = OnProcessSendOnce(nullptr, TEST_ARGS, reinterpret_cast<void *>(para3));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HEARTBEAT_SEND_ERR);
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
        LNN_LOGE(LNN_TEST, "strcpy failed");
    }
    ret = RemoveCheckDevStatusMsg(&ctrlMsgObj, &delMsg);
    EXPECT_FALSE(ret == SOFTBUS_OK);

    delMsgPara.hasNetworkId = false;
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);
    ret = RemoveCheckDevStatusMsg(&ctrlMsgObj, &delMsg);
    EXPECT_FALSE(ret == SOFTBUS_OK);

    delMsgPara.hbType = HEARTBEAT_TYPE_BLE_V1;
    if (strcpy_s(const_cast<char *>(delMsgPara.networkId), sizeof(TEST_NETWORK_ID2), TEST_NETWORK_ID2) != SOFTBUS_OK) {
        LNN_LOGE(LNN_TEST, "strcpy failed");
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
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrSendBegin)
        .WillRepeatedly(Return(SOFTBUS_NETWORK_HB_SEND_BEGIN_FAILED));
    void *para = SoftBusCalloc(sizeof(LnnHeartbeatSendBeginData));
    int32_t ret = OnSendOneHbBegin(nullptr, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    ret = OnSendOneHbBegin(&hbFsm->fsm, TEST_ARGS, para);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_SEND_BEGIN_FAILED);
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
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrSendEnd).WillRepeatedly(Return(SOFTBUS_NETWORK_HB_SEND_END_FAILED));
    void *para = SoftBusCalloc(sizeof(LnnHeartbeatType));
    int32_t ret = OnSendOneHbEnd(nullptr, TEST_ARGS, nullptr);
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = OnSendOneHbEnd(nullptr, TEST_ARGS, para);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_SEND_END_FAILED);
    void *para2 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnSendOneHbEnd(nullptr, TEST_ARGS, para2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_SEND_END_FAILED);
    void *para3 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnSendOneHbEnd(&hbFsm->fsm, TEST_ARGS, para3);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_SEND_END_FAILED);
    void *para4 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnStartHbProcess(nullptr, TEST_ARGS, para4);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = OnReStartHbProcess(nullptr, TEST_ARGS, para4);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrStop).WillRepeatedly(Return(SOFTBUS_NETWORK_HB_STOP_PROCESS_FAIL));
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    void *para = SoftBusCalloc(sizeof(LnnHeartbeatType));
    int32_t ret = OnStopHbByType(nullptr, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = OnStopHbByType(nullptr, TEST_ARGS, para);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_STOP_PROCESS_FAIL);
    void *para2 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnStopHbByType(&hbFsm->fsm, TEST_ARGS, para2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_STOP_PROCESS_FAIL);
    ret = OnSetMediumParam(nullptr, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(heartbeatFsmMock, LnnHbMediumMgrSetParam).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_SUPPORT));
    void *para3 = SoftBusCalloc(sizeof(LnnHeartbeatType));
    ret = OnSetMediumParam(nullptr, TEST_ARGS, para3);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_SUPPORT);
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
    ON_CALL(heartbeatFsmMock, LnnGetGearModeBySpecificType).WillByDefault(Return(SOFTBUS_NETWORK_HB_INVALID_MGR));
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
    NiceMock<LnnNetLedgertInterfaceMock> lnnNetLedgerMock;
    ON_CALL(heartbeatFsmMock, LnnRequestLeaveSpecific).WillByDefault(Return(SOFTBUS_OK));
    EXPECT_CALL(distriLedgerMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(distriLedgerMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(heartbeatFsmMock, LnnRequestLeaveSpecific).WillRepeatedly(Return(SOFTBUS_STRCPY_ERR));
    EXPECT_CALL(heartbeatFsmMock, GetWifiDirectManager).WillRepeatedly(Return(&manager));
    EXPECT_CALL(distriLedgerMock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_OK));
    const char *udid = "testuuid";
    EXPECT_CALL(distriLedgerMock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    ON_CALL(lnnNetLedgerMock, LnnGetLocalNumU64Info).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = ProcessLostHeartbeat(nullptr, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(distriLedgerMock, LnnGetOnlineStateById).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnNetLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_NETWORK_GET_NODE_INFO_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = ProcessLostHeartbeat(TEST_NETWORK_ID, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(heartbeatFsmMock, LnnOfflineTimingByHeartbeat)
        .WillOnce(Return(SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL));
    ret = ProcessLostHeartbeat(TEST_NETWORK_ID, HEARTBEAT_TYPE_BLE_V0, false);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL);
    ret = ProcessLostHeartbeat(TEST_NETWORK_ID, HEARTBEAT_TYPE_TCP_FLUSH, false);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REQ_LEAVE_LNN_FAIL);
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
        .WillOnce(Return(SOFTBUS_NETWORK_HB_INVALID_MGR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    bool ret = IsTimestampExceedLimit(TEST_TIME2, TEST_TIME1, HEARTBEAT_TYPE_BLE_V0, CHECK_DELAY_LEN);
    EXPECT_FALSE(ret);
    ret = IsTimestampExceedLimit(TEST_TIME3, TEST_TIME1, HEARTBEAT_TYPE_BLE_V0, CHECK_DELAY_LEN);
    EXPECT_TRUE(ret);
    ret = IsTimestampExceedLimit(TEST_TIME2, TEST_TIME1, HEARTBEAT_TYPE_BLE_V1, CHECK_DELAY_LEN);
    EXPECT_FALSE(ret);
    ret = IsTimestampExceedLimit(TEST_TIME2, TEST_TIME1, HEARTBEAT_TYPE_BLE_V1, CHECK_DELAY_LEN);
    EXPECT_FALSE(ret);
    ret = IsTimestampExceedLimit(TEST_TIME3, TEST_TIME1, HEARTBEAT_TYPE_BLE_V1, CHECK_DELAY_LEN);
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
    EXPECT_CALL(heartbeatFsmMock, LnnStopOfflineTimingStrategy)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnCheckDevStatusMsgPara msgPara = { .hbType = HEARTBEAT_TYPE_BLE_V0 };
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, &msgPara);
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, &msgPara);
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillOnce(Return(false)).WillRepeatedly(Return(true));
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, &msgPara);
    EXPECT_CALL(distriLedgerMock, LnnGetDLHeartbeatTimestamp)
        .WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(DoAll(SetArgPointee<1>(oldTimeStamp), Return(SOFTBUS_OK)));
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, &msgPara);
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, &msgPara);
    CheckDevStatusByNetworkId(hbFsm, TEST_NETWORK_ID, &msgPara);
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
    NiceMock<HeartBeatFSMInterfaceMock> heartbeatFsmMock;
    FsmStateMachine fsm;
    LnnHeartbeatFsm *hbFsm = LnnCreateHeartbeatFsm();
    ON_CALL(netLedgerMock, LnnGetAllOnlineNodeInfo).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = OnCheckDevStatus(nullptr, TEST_ARGS, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    void *para = SoftBusCalloc(sizeof(LnnCheckDevStatusMsgPara));
    EXPECT_CALL(heartbeatFsmMock, GetScreenState)
        .WillOnce(Return(SOFTBUS_SCREEN_OFF))
        .WillRepeatedly(Return(SOFTBUS_SCREEN_ON));
    ret = OnCheckDevStatus(&hbFsm->fsm, TEST_ARGS, para);
    EXPECT_TRUE(ret == SOFTBUS_OK);
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
    EXPECT_EQ(ret, SOFTBUS_NETWORK_FSM_START_FAIL);
    ret = LnnStopHeartbeatFsm(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnStopHeartbeatFsm(hbFsm);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_FSM_STOP_FAIL);
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
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_FAIL);
    ret = LnnPostSendEndMsgToHbFsm(nullptr, custData, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostStartMsgToHbFsm(nullptr, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostStopMsgToHbFsm(nullptr, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostStopMsgToHbFsm(hbFsm, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_FAIL);
    ret = LnnPostTransStateMsgToHbFsm(nullptr, EVENT_HB_SEND_ONE_END);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostTransStateMsgToHbFsm(nullptr, EVENT_HB_MAX);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostSetMediumParamMsgToHbFsm(nullptr, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnHeartbeatMediumParam para2;
    ret = LnnPostSetMediumParamMsgToHbFsm(hbFsm, &para2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_FAIL);
    ret = LnnPostCheckDevStatusMsgToHbFsm(nullptr, nullptr, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostCheckDevStatusMsgToHbFsm(hbFsm, nullptr, TEST_TIME1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusSleepMs(20);
    LnnDestroyHeartbeatFsm(hbFsm);
}
/*
 * @tc.name: RemoveSendOneEndMsgTest_01
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveSendOneEndMsgTest_01, TestSize.Level1)
{
    int32_t ret;
    FsmCtrlMsgObj ctrlMsgObj;
    SoftBusMessage delMsg;
    LnnHeartbeatSendEndData *msgPara = nullptr;
    LnnRemoveSendEndMsgPara delMsgPara;
    bool isRemoved = false;
    msgPara = (LnnHeartbeatSendEndData *)SoftBusMalloc(sizeof(LnnHeartbeatSendEndData));
    msgPara->wakeupFlag = false;
    delMsgPara.wakeupFlag = true;
    delMsgPara.isRemoved = &isRemoved;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);

    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    msgPara->wakeupFlag = true;
    delMsgPara.wakeupFlag = false;
    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_REMOVE_MSG_FAIL);
}
/*
 * @tc.name: RemoveSendOneEndMsgTest_02
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveSendOneEndMsgTest_02, TestSize.Level1)
{
    int32_t ret;
    FsmCtrlMsgObj ctrlMsgObj;
    SoftBusMessage delMsg;
    LnnHeartbeatSendEndData *msgPara = nullptr;
    LnnRemoveSendEndMsgPara delMsgPara;
    bool isRemoved = false;
    msgPara = (LnnHeartbeatSendEndData *)SoftBusMalloc(sizeof(LnnHeartbeatSendEndData));
    msgPara->wakeupFlag = true;
    delMsgPara.wakeupFlag = true;
    delMsgPara.isRemoved = &isRemoved;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);

    msgPara->hbType = 0;
    msgPara->isRelay = true;
    msgPara->hbType |= HEARTBEAT_TYPE_BLE_V0;
    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    delMsgPara.hbType = 0;
    delMsgPara.isRelay = true;
    msgPara->isRelay = false;
    msgPara->hbType = 0;
    delMsgPara.hbType |= HEARTBEAT_TYPE_BLE_V0;
    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_REMOVE_MSG_FAIL);
}
/*
 * @tc.name: RemoveSendOneEndMsgTest_03
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveSendOneEndMsgTest_03, TestSize.Level1)
{
    int32_t ret;
    FsmCtrlMsgObj ctrlMsgObj;
    SoftBusMessage delMsg;
    LnnHeartbeatSendEndData *msgPara = nullptr;
    LnnRemoveSendEndMsgPara delMsgPara;
    bool isRemoved = false;
    msgPara = (LnnHeartbeatSendEndData *)SoftBusMalloc(sizeof(LnnHeartbeatSendEndData));
    msgPara->wakeupFlag = true;
    msgPara->isRelay = false;
    delMsgPara.wakeupFlag = true;
    delMsgPara.isRelay = false;
    delMsgPara.isRemoved = &isRemoved;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);

    msgPara->hbType = HEARTBEAT_TYPE_BLE_V1;
    delMsgPara.hbType = HEARTBEAT_TYPE_BLE_V0;
    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LnnHeartbeatSendEndData *msgPara1 = (LnnHeartbeatSendEndData *)SoftBusMalloc(sizeof(LnnHeartbeatSendEndData));
    msgPara1->wakeupFlag = true;
    msgPara1->isRelay = false;
    delMsgPara.wakeupFlag = true;
    delMsgPara.isRelay = false;
    delMsgPara.isRemoved = &isRemoved;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara1);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);
    msgPara1->hbType = HEARTBEAT_TYPE_BLE_V0;
    delMsgPara.hbType = HEARTBEAT_TYPE_BLE_V1;
    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_REMOVE_MSG_FAIL);
}
/*
 * @tc.name: RemoveSendOneEndMsgTest_04
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveSendOneEndMsgTest_04, TestSize.Level1)
{
    int32_t ret;
    FsmCtrlMsgObj ctrlMsgObj;
    SoftBusMessage delMsg;
    LnnHeartbeatSendEndData *msgPara = nullptr;
    LnnRemoveSendEndMsgPara delMsgPara;
    bool isRemoved = false;
    msgPara = (LnnHeartbeatSendEndData *)SoftBusMalloc(sizeof(LnnHeartbeatSendEndData));
    msgPara->wakeupFlag = true;
    msgPara->isRelay = false;
    delMsgPara.wakeupFlag = true;
    delMsgPara.isRelay = false;
    delMsgPara.isRemoved = &isRemoved;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);

    msgPara->hbType = HEARTBEAT_TYPE_BLE_V0;
    delMsgPara.hbType = HEARTBEAT_TYPE_BLE_V0;
    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LnnHeartbeatSendEndData *msgPara1 = (LnnHeartbeatSendEndData *)SoftBusMalloc(sizeof(LnnHeartbeatSendEndData));
    msgPara1->wakeupFlag = true;
    msgPara1->isRelay = false;
    delMsgPara.wakeupFlag = true;
    delMsgPara.isRelay = false;
    delMsgPara.isRemoved = &isRemoved;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara1);
    msgPara1->hbType = HEARTBEAT_TYPE_BLE_V1;
    delMsgPara.hbType = HEARTBEAT_TYPE_BLE_V1;
    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_REMOVE_MSG_FAIL);
}
/*
 * @tc.name: RemoveSendOneEndMsgTest_05
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveSendOneEndMsgTest_05, TestSize.Level1)
{
    int32_t ret;
    FsmCtrlMsgObj ctrlMsgObj;
    SoftBusMessage delMsg;
    LnnHeartbeatSendEndData *msgPara = nullptr;
    LnnRemoveSendEndMsgPara delMsgPara;
    bool isRemoved = false;
    msgPara = (LnnHeartbeatSendEndData *)SoftBusMalloc(sizeof(LnnHeartbeatSendEndData));
    msgPara->wakeupFlag = true;
    msgPara->isRelay = false;
    delMsgPara.wakeupFlag = true;
    delMsgPara.isRelay = false;
    delMsgPara.isRemoved = &isRemoved;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);

    msgPara->hbType = 0;
    delMsgPara.hbType = 0;
    ret = RemoveSendOneEndMsg(&ctrlMsgObj, &delMsg);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_REMOVE_MSG_FAIL);
}
/*
 * @tc.name: RemoveScreenOffCheckStatus_01
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveScreenOffCheckStatus_01, TestSize.Level1)
{
    int32_t ret;
    FsmCtrlMsgObj ctrlMsgObj;
    SoftBusMessage delMsg;
    LnnCheckDevStatusMsgPara *msgPara = nullptr;
    LnnCheckDevStatusMsgPara delMsgPara = {};
    msgPara = (LnnCheckDevStatusMsgPara *)SoftBusMalloc(sizeof(LnnCheckDevStatusMsgPara));
    msgPara->hasNetworkId = true;
    delMsgPara.hasNetworkId = false;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);

    ret = RemoveScreenOffCheckStatus(&ctrlMsgObj, &delMsg);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_REMOVE_MSG_FAIL);

    msgPara->hasNetworkId = false;
    delMsgPara.hasNetworkId = false;
    msgPara->hbType = 0;
    delMsgPara.hbType = 0;
    ret = RemoveScreenOffCheckStatus(&ctrlMsgObj, &delMsg);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
/*
 * @tc.name: RemoveScreenOffCheckStatus_02
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveScreenOffCheckStatus_02, TestSize.Level1)
{
    int32_t ret;
    const char *networkId = "123";
    FsmCtrlMsgObj ctrlMsgObj;
    SoftBusMessage delMsg;
    LnnCheckDevStatusMsgPara *msgPara = nullptr;
    LnnCheckDevStatusMsgPara delMsgPara = {};
    msgPara = (LnnCheckDevStatusMsgPara *)SoftBusMalloc(sizeof(LnnCheckDevStatusMsgPara));
    msgPara->hasNetworkId = true;
    delMsgPara.hasNetworkId = true;
    msgPara->hbType = 0;
    delMsgPara.hbType = 0;
    ret = strcpy_s((char *)(msgPara->networkId), sizeof(msgPara->networkId), networkId);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s((char *)(delMsgPara.networkId), sizeof(delMsgPara.networkId), networkId);
    EXPECT_EQ(ret, EOK);
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);

    ret = RemoveScreenOffCheckStatus(&ctrlMsgObj, &delMsg);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
/*
 * @tc.name: RemoveScreenOffCheckStatus_03
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, RemoveScreenOffCheckStatus_03, TestSize.Level1)
{
    int32_t ret;
    FsmCtrlMsgObj ctrlMsgObj;
    SoftBusMessage delMsg;
    LnnCheckDevStatusMsgPara *msgPara = nullptr;
    LnnCheckDevStatusMsgPara delMsgPara = {};
    msgPara = (LnnCheckDevStatusMsgPara *)SoftBusMalloc(sizeof(LnnCheckDevStatusMsgPara));
    msgPara->hasNetworkId = true;
    delMsgPara.hasNetworkId = true;
    msgPara->hbType = 0;
    delMsgPara.hbType = 0;
    ctrlMsgObj.obj = reinterpret_cast<void *>(msgPara);
    delMsg.obj = reinterpret_cast<void *>(&delMsgPara);
    ret = strcpy_s((char *)(msgPara->networkId), sizeof(msgPara->networkId), TEST_NETWORK_ID);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s((char *)(delMsgPara.networkId), sizeof(delMsgPara.networkId), TEST_NETWORK_ID2);
    EXPECT_EQ(ret, EOK);

    ret = RemoveScreenOffCheckStatus(&ctrlMsgObj, &delMsg);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_REMOVE_MSG_FAIL);
}
/*
 * @tc.name: OnScreeOffCheckDevStatus_01
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, OnScreeOffCheckDevStatus_01, TestSize.Level1)
{
    int32_t ret;
    LnnHeartbeatFsm hbFsm = {};
    LnnCheckDevStatusMsgPara msgParas = {};
    LnnCheckDevStatusMsgPara *msgPara = nullptr;
    msgPara = (LnnCheckDevStatusMsgPara *)SoftBusMalloc(sizeof(LnnCheckDevStatusMsgPara));

    ret = OnScreeOffCheckDevStatus(nullptr, 0, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = OnScreeOffCheckDevStatus(nullptr, 0, reinterpret_cast<void *>(msgPara));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_CHECK_DEV_STATUS_ERROR);

    LnnRemoveScreenOffCheckStatusMsg(nullptr, &msgParas);
    LnnRemoveScreenOffCheckStatusMsg(&hbFsm, nullptr);
    LnnRemoveScreenOffCheckStatusMsg(&hbFsm, &msgParas);
    ReportSendBroadcastResultEvt();
}

/*
 * @tc.name: LnnPostSendBeginMsgToHbFsm_01
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, LnnPostSendBeginMsgToHbFsm_01, TestSize.Level1)
{
    LnnHeartbeatFsm hbFsm = {};
    LnnProcessSendOnceMsgPara msgParas = {};
    int32_t ret = LnnPostSendBeginMsgToHbFsm(nullptr, 0, true, &msgParas, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    msgParas.isRelay = true;
    msgParas.isSyncData = true;
    ret = LnnPostSendBeginMsgToHbFsm(&hbFsm, 0, true, &msgParas, 0);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_DELAY_FAIL);
}

/*
 * @tc.name: LnnPostTransStateMsgToHbFsm_01
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, LnnPostTransStateMsgToHbFsm_01, TestSize.Level1)
{
    LnnHeartbeatFsm hbFsm = {};
    int32_t ret = LnnPostTransStateMsgToHbFsm(&hbFsm, EVENT_HB_STOP_SPECIFIC);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostTransStateMsgToHbFsm(&hbFsm, EVENT_HB_AS_NORMAL_NODE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostTransStateMsgToHbFsm(&hbFsm, EVENT_HB_IN_NONE_STATE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPostScreenOffCheckDevMsgToHbFsm_01
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, LnnPostScreenOffCheckDevMsgToHbFsm_01, TestSize.Level1)
{
    LnnHeartbeatFsm hbFsm = {};
    LnnCheckDevStatusMsgPara para = {};
    int32_t ret = LnnPostScreenOffCheckDevMsgToHbFsm(nullptr, &para, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostScreenOffCheckDevMsgToHbFsm(&hbFsm, nullptr, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPostUpdateSendInfoMsgToHbFsm_01
 * @tc.desc: check heartbeat fsm state message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, LnnPostUpdateSendInfoMsgToHbFsm_01, TestSize.Level1)
{
    LnnHeartbeatFsm hbFsm = {};
    int32_t ret = LnnPostUpdateSendInfoMsgToHbFsm(nullptr, UPDATE_HB_INFO_MIN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnPostUpdateSendInfoMsgToHbFsm(&hbFsm, UPDATE_HB_INFO_MIN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnPostUpdateSendInfoMsgToHbFsm(&hbFsm, UPDATE_HB_MAX_INFO);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnPostUpdateSendInfoMsgToHbFsm(&hbFsm, UPDATE_HB_NETWORK_INFO);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPostSendBeginMsgToHbFsm_02
 * @tc.desc: lnn post send begin msg to hb fsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, LnnPostSendBeginMsgToHbFsm_02, TestSize.Level1)
{
    LnnHeartbeatFsm hbFsm;
    LnnHeartbeatType type = HEARTBEAT_TYPE_BLE_V1;
    bool wakeupFlag = true;
    LnnProcessSendOnceMsgPara msgPara;
    int32_t ret = LnnPostSendBeginMsgToHbFsm(nullptr, type, wakeupFlag, &msgPara, TEST_TIME3);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostSendBeginMsgToHbFsm(&hbFsm, type, wakeupFlag, &msgPara, TEST_TIME3);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_DELAY_FAIL);
}

/*
 * @tc.name: LnnPostScreenOffCheckDevMsgToHbFsm_02
 * @tc.desc: lnn post screen off check dev msg to hb fsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, LnnPostScreenOffCheckDevMsgToHbFsm_02, TestSize.Level1)
{
    LnnHeartbeatFsm hbFsm = {
        .fsmName = "test66",
    };
    LnnCheckDevStatusMsgPara *msgPara = nullptr;
    msgPara = (LnnCheckDevStatusMsgPara *)SoftBusMalloc(sizeof(LnnCheckDevStatusMsgPara));
    int32_t ret = LnnPostScreenOffCheckDevMsgToHbFsm(nullptr, msgPara, TEST_TIME3);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostScreenOffCheckDevMsgToHbFsm(&hbFsm, nullptr, TEST_TIME3);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnPostScreenOffCheckDevMsgToHbFsm(&hbFsm, msgPara, TEST_TIME3);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_POST_MSG_DELAY_FAIL);
}

/*
 * @tc.name: CheckHbFsmStateMsgArgs_01
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, CheckHbFsmStateMsgArgs_01, TestSize.Level1)
{
    LnnHeartbeatFsm hbFsm;
    (void)memset_s(&hbFsm, sizeof(LnnHeartbeatFsm), 0, sizeof(LnnHeartbeatFsm));

    bool ret = CheckHbFsmStateMsgArgs(nullptr);
    EXPECT_EQ(ret, false);

    hbFsm.state = STATE_HB_INDEX_MAX;
    ret = CheckHbFsmStateMsgArgs(&hbFsm.fsm);
    EXPECT_EQ(ret, false);

    hbFsm.state = STATE_HB_NORMAL_NODE_INDEX;
    ret = CheckHbFsmStateMsgArgs(&hbFsm.fsm);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: HbFsmStateProcessFunc_01
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatFSMTest, HbFsmStateProcessFunc_01, TestSize.Level1)
{
    LnnHeartbeatFsm hbFsm;
    (void)memset_s(&hbFsm, sizeof(LnnHeartbeatFsm), 0, sizeof(LnnHeartbeatFsm));
    void *para = SoftBusCalloc(sizeof(LnnCheckDevStatusMsgPara));
    (void)memset_s(para, sizeof(LnnCheckDevStatusMsgPara), 0, sizeof(LnnCheckDevStatusMsgPara));
    int32_t msgType = EVENT_HB_MIN;
    bool ret = HbFsmStateProcessFunc(nullptr, msgType, nullptr);
    EXPECT_EQ(ret, false);

    ret = HbFsmStateProcessFunc(&hbFsm.fsm, msgType, nullptr);
    EXPECT_EQ(ret, false);

    msgType = EVENT_HB_MAX;
    ret = HbFsmStateProcessFunc(&hbFsm.fsm, msgType, nullptr);
    EXPECT_EQ(ret, false);

    msgType = EVENT_HB_PROCESS_SEND_ONCE;
    ret = HbFsmStateProcessFunc(&hbFsm.fsm, msgType, nullptr);
    EXPECT_EQ(ret, false);

    ret = HbFsmStateProcessFunc(&hbFsm.fsm, msgType, para);
    EXPECT_EQ(ret, false);
}
} // namespace OHOS
