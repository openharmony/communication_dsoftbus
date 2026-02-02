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
#include "event_mock.h"
#include "heartbeat_new_mock.h"
#include "ledger_mock.h"
#include "lnn_connection_fsm.h"
#include "lnn_connection_mock.h"
#include "lnn_device_info.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_node_info.h"
#include "message_handler.h"
#include "softbus_broadcast_mgr_mock.h"
#include "softbus_error_code.h"
#include "softbus_adapter_bt_common_struct.h"

namespace OHOS {
#define TEST_SLEEP_TIME 50
using namespace testing;
using namespace testing::ext;

NodeInfo nodeinfo1;

class HeartBeatEnhanceTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void InitLedgerMock(LedgerInterfaceMock &hbLnnMock)
{
    (void)memset_s(&nodeinfo1, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    ON_CALL(hbLnnMock, LnnGetLocalDeviceInfo(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbLnnMock, LnnGetLocalStrInfo(_, _, _)).WillByDefault(LedgerInterfaceMock::ActionOfLnnGetLocalStrInfo);
    ON_CALL(hbLnnMock, LnnGetLocalByteInfo(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbLnnMock, LnnGetLocalNumInfo(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbLnnMock, LnnGetNodeInfoById(_, _)).WillByDefault(Return(&nodeinfo1));
    ON_CALL(hbLnnMock, LnnHasDiscoveryType(_, _)).WillByDefault(Return(true));
    ON_CALL(hbLnnMock, LnnGetDLHeartbeatTimestamp(_, _)).WillByDefault(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    ON_CALL(hbLnnMock, LnnGetOnlineStateById(_, _)).WillByDefault(Return(true));
    ON_CALL(hbLnnMock, LnnGetRemoteStrInfo(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbLnnMock, LnnRequestLeaveSpecific(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbLnnMock, LnnGetAllOnlineNodeInfo(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbLnnMock, LnnGetTrustedDevInfoFromDb(_, _))
        .WillByDefault(LedgerInterfaceMock::ActionOfGetTrustedDevInfoFromDb);
}

void InitBTMock(SoftbusBroadcastMgrMock &bcMgrMock)
{
    ON_CALL(bcMgrMock, SoftBusGetBtState()).WillByDefault(Return(BLE_ENABLE));
    ON_CALL(bcMgrMock, InitBroadcastMgr()).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, DeInitBroadcastMgr()).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, RegisterScanListener(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, UnRegisterScanListener(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, RegisterBroadcaster(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, UnRegisterBroadcaster(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, StartScan(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, StopScan(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, StartBroadcasting(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, StopBroadcasting(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, UpdateBroadcasting(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, SetBroadcastingData(_, _)).WillByDefault(Return(SOFTBUS_OK));
}

void InitConnMock(LnnConnectInterfaceMock &lnnConnMock)
{
    ON_CALL(lnnConnMock, CheckActiveConnection(_, _)).WillByDefault(Return(true));
}

void InitEventMock(EventInterfaceMock &hbEventMock)
{
    ON_CALL(hbEventMock, LnnRegisterEventHandler(_, _))
        .WillByDefault(EventInterfaceMock::ActionifLnnRegisterEventHandler);
    ON_CALL(hbEventMock, LnnNotifyDiscoveryDevice(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
}

void HeartBeatEnhanceTest::SetUpTestCase()
{
    LnnInitLnnLooper();
    NiceMock<EventInterfaceMock> hbEventMock;
    InitEventMock(hbEventMock);
    int ret = LooperInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    NiceMock<LedgerInterfaceMock> hbLnnMock;
    EXPECT_CALL(hbLnnMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbLnnMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    ret = LnnInitHeartbeat();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void HeartBeatEnhanceTest::TearDownTestCase()
{
    NiceMock<LedgerInterfaceMock> hbLnnMock;
    NiceMock<LnnConnectInterfaceMock> lnnConnMock;
    NiceMock<EventInterfaceMock> hbEventMock;
    NiceMock<SoftbusBroadcastMgrMock> bcMgrMock;
    ON_CALL(bcMgrMock, UnRegisterBroadcaster(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(bcMgrMock, UnRegisterScanListener(_)).WillByDefault(Return(SOFTBUS_OK));
    LnnDeinitHeartbeat();
    LooperDeinit();
    LnnDeinitBusCenterEvent();
    LnnDeinitLnnLooper();
    SoftBusSleepMs(TEST_SLEEP_TIME);
}

void HeartBeatEnhanceTest::SetUp()
{}

void HeartBeatEnhanceTest::TearDown()
{}

LnnEventHandler GetEventHandler(LnnEventType type)
{
    if (EventInterfaceMock::g_event_handlers.find(type) != EventInterfaceMock::g_event_handlers.end()) {
        return (EventInterfaceMock::g_event_handlers[type]);
    }
    return nullptr;
}

/*
 * @tc.name: IpAddrChangeTest01
 * @tc.desc: This test verifies whether the system can correctly handle an IP address change
 *           event and adjust the heartbeat mechanism, especially whether the TCP heartbeat is disabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatEnhanceTest, IpAddrChangeTest01, TestSize.Level1)
{
    NiceMock<LedgerInterfaceMock> hbLnnMock;
    NiceMock<SoftbusBroadcastMgrMock> bcMgrMock;
    NiceMock<LnnConnectInterfaceMock> lnnConnMock;
    NiceMock<HeartBeatNewInterfaceMock> hbNewMock;

    InitLedgerMock(hbLnnMock);
    InitBTMock(bcMgrMock);
    InitConnMock(lnnConnMock);

    EXPECT_CALL(hbNewMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    LnnStartHeartbeatFrameDelay();

    LnnEventHandler handler;
    handler = GetEventHandler(LNN_EVENT_IP_ADDR_CHANGED);
    ASSERT_TRUE(handler != nullptr);
    handler(nullptr);
    LnnEventBasicInfo info1 = {
        .event = LNN_EVENT_BT_STATE_CHANGED,
    };
    handler(&info1);
    LnnEventBasicInfo info2 = {
        .event = LNN_EVENT_IP_ADDR_CHANGED,
    };
    handler(&info2);
    bool res = LnnIsHeartbeatEnable(HEARTBEAT_TYPE_TCP_FLUSH);
    EXPECT_FALSE(res);
    SoftBusSleepMs(TEST_SLEEP_TIME);
}

/*
 * @tc.name: HbBtStateChangeTest01
 * @tc.desc: The enablement status of the heartbeat function under different conditions was tested
 *           by simulating different events and states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatEnhanceTest, HbBtStateChangeTest01, TestSize.Level1)
{
    NiceMock<LedgerInterfaceMock> hbLnnMock;
    NiceMock<SoftbusBroadcastMgrMock> bcMgrMock;
    NiceMock<LnnConnectInterfaceMock> lnnConnMock;
    NiceMock<HeartBeatNewInterfaceMock> hbNewMock;

    InitLedgerMock(hbLnnMock);
    InitBTMock(bcMgrMock);
    InitConnMock(lnnConnMock);

    EXPECT_CALL(hbNewMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    LnnStartHeartbeatFrameDelay();

    LnnEventHandler handler;
    handler = GetEventHandler(LNN_EVENT_BT_STATE_CHANGED);
    ASSERT_TRUE(handler != nullptr);

    LnnEventBasicInfo info1 = {
        .event = LNN_EVENT_SCREEN_STATE_CHANGED,
    };
    LnnMonitorHbStateChangedEvent event1 = {
        .basic = info1,
        .status = SOFTBUS_BLE_TURN_ON,
    };
    auto input1 = reinterpret_cast<LnnEventBasicInfo *>(&event1);
    handler(input1);
    handler(nullptr);

    LnnEventBasicInfo info2 = {
        .event = LNN_EVENT_BT_STATE_CHANGED,
    };
    LnnMonitorHbStateChangedEvent event2 = {
        .basic = info2,
        .status = SOFTBUS_BT_UNKNOWN,
    };
    auto input2 = reinterpret_cast<LnnEventBasicInfo *>(&event2);
    handler(input2);

    LnnMonitorHbStateChangedEvent event3 = {
        .basic = info2,
        .status = SOFTBUS_BLE_TURN_ON,
    };
    auto input3 = reinterpret_cast<LnnEventBasicInfo *>(&event3);
    handler(input3);
    bool res = LnnIsHeartbeatEnable(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1);
    EXPECT_FALSE(res);

    LnnMonitorHbStateChangedEvent event4 = {
        .basic = info2,
        .status = SOFTBUS_BLE_TURN_OFF,
    };
    auto input4 = reinterpret_cast<LnnEventBasicInfo *>(&event4);
    handler(input4);
    res = LnnIsHeartbeatEnable(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1);
    EXPECT_FALSE(res);
    SoftBusSleepMs(500);
}

/*
 * @tc.name: HbMasterNodeChangeTest01
 * @tc.desc: The logic for handling the LNN_EVENT_NODE_MASTER_STATE_CHANGED event was tested
 *           by simulating dependencies and setting expected behaviors
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatEnhanceTest, HbMasterNodeChangeTest01, TestSize.Level1)
{
    NiceMock<LedgerInterfaceMock> hbLnnMock;
    NiceMock<SoftbusBroadcastMgrMock> bcMgrMock;
    NiceMock<LnnConnectInterfaceMock> lnnConnMock;
    NiceMock<HeartBeatNewInterfaceMock> hbNewMock;

    InitLedgerMock(hbLnnMock);
    InitBTMock(bcMgrMock);
    InitConnMock(lnnConnMock);

    EXPECT_CALL(hbNewMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    LnnStartHeartbeatFrameDelay();

    LnnEventHandler handler;
    handler = GetEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED);
    ASSERT_TRUE(handler != nullptr);
    LnnEventBasicInfo info1 = {
        .event = LNN_EVENT_BT_STATE_CHANGED,
    };
    LnnMasterNodeChangedEvent masterEvent1 = {
        .basic = info1,
        .masterNodeUDID = "06D1D93A2AED76215FC5EF7D8FCC551045A9DC35F0878A1E2DBA7D2D4FC9B5DA",
        .weight = 1,
        .isMasterNode = false,
    };
    auto input1 = reinterpret_cast<LnnEventBasicInfo *>(&masterEvent1);
    handler(input1);
    handler(nullptr);

    LnnEventBasicInfo info2 = {
        .event = LNN_EVENT_NODE_MASTER_STATE_CHANGED,
    };
    LnnMasterNodeChangedEvent masterEvent2 = {
        .basic = info2,
        .masterNodeUDID = "06D1D93A2AED76215FC5EF7D8FCC551045A9DC35F0878A1E2DBA7D2D4FC9B5DA",
        .weight = 1,
        .isMasterNode = false,
    };
    auto input2 = reinterpret_cast<LnnEventBasicInfo *>(&masterEvent2);
    handler(input2);

    LnnMasterNodeChangedEvent masterEvent3 = {
        .basic = info2,
        .masterNodeUDID = "06D1D93A2AED76215FC5EF7D8FCC551045A9DC35F0878A1E2DBA7D2D4FC9B5DA",
        .weight = 1,
        .isMasterNode = true,
    };
    auto input3 = reinterpret_cast<LnnEventBasicInfo *>(&masterEvent3);
    handler(input3);
    SoftBusSleepMs(200);
}

/*
 * @tc.name: HbScreenStateChange_Test01
 * @tc.desc: The logic for processing the LNN_EVENT_SCREEN_STATE_CHANGED event was tested by simulating dependent
 *           interfaces, including the screen state being ON, OFF, and UNKNOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatEnhanceTest, HbScreenStateChange_Test01, TestSize.Level1)
{
    NiceMock<LedgerInterfaceMock> hbLnnMock;
    NiceMock<SoftbusBroadcastMgrMock> bcMgrMock;
    NiceMock<LnnConnectInterfaceMock> lnnConnMock;
    NiceMock<HeartBeatNewInterfaceMock> hbNewMock;

    InitLedgerMock(hbLnnMock);
    InitBTMock(bcMgrMock);
    InitConnMock(lnnConnMock);

    EXPECT_CALL(hbNewMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    LnnStartHeartbeatFrameDelay();

    LnnEventHandler handler;
    handler = GetEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED);
    ASSERT_TRUE(handler != nullptr);
    LnnEventBasicInfo info1 = {
        .event = LNN_EVENT_BT_STATE_CHANGED,
    };
    LnnMonitorScreenStateChangedEvent screenStateEevent1 = {
        .basic = info1,
    };
    auto input1 = reinterpret_cast<LnnEventBasicInfo *>(&screenStateEevent1);
    handler(input1);
    handler(nullptr);
    LnnEventBasicInfo info2 = {
        .event = LNN_EVENT_SCREEN_STATE_CHANGED,
    };
    LnnMonitorScreenStateChangedEvent screenStateOn = {
        .basic = info2,
        .status = SOFTBUS_SCREEN_ON,
    };
    auto inputOn = reinterpret_cast<LnnEventBasicInfo *>(&screenStateOn);
    handler(inputOn);

    LnnMonitorScreenStateChangedEvent screenStateOff = {
        .basic = info2,
        .status = SOFTBUS_SCREEN_OFF,
    };
    auto inputOff = reinterpret_cast<LnnEventBasicInfo *>(&screenStateOff);
    handler(inputOff);
    LnnMonitorScreenStateChangedEvent screenStateUnknow = {
        .basic = info2,
        .status = SOFTBUS_SCREEN_UNKNOWN,
    };
    auto inputUnknow = reinterpret_cast<LnnEventBasicInfo *>(&screenStateUnknow);
    handler(inputUnknow);
    SoftBusSleepMs(200);
}
}  // namespace OHOS
