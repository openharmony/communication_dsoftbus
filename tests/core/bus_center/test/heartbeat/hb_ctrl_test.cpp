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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_manager.h"
#include "distribute_net_ledger_mock.h"
#include "hb_ctrl_deps_mock.h"
#include "hb_fsm_mock.h"
#include "hb_strategy_mock.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_ip_network_impl_mock.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_state_machine.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
constexpr char NETWORKID[] = "ABCDEFG";
constexpr char PKGNAME[] = "PKGNAME";
constexpr char CALLERID[] = "123ABCDEFG";
constexpr char TARGETNETWORKID[] = "6542316a57d";

using namespace testing::ext;
using namespace testing;

class HeartBeatCtrlTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HeartBeatCtrlTest::SetUpTestCase()
{
    int32_t ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void HeartBeatCtrlTest::TearDownTestCase() { }

void HeartBeatCtrlTest::SetUp() { }

void HeartBeatCtrlTest::TearDown() { }

/*
 * @tc.name: LNN_OFFLINE_TIMEING_BY_HEARTBEAT_TEST_001
 * @tc.desc: test LnnOfflineTimingByHeartbeat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlTest, LNN_OFFLINE_TIMEING_BY_HEARTBEAT_TEST_001, TestSize.Level1)
{
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    DistributeLedgerInterfaceMock distributeNetLedgerMock;
    HeartBeatCtrlDepsInterfaceMock hbCtrlDepsMock;
    EXPECT_CALL(hbStrateMock, LnnStartOfflineTimingStrategy)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(distributeNetLedgerMock, LnnSetDLHeartbeatTimestamp).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbCtrlDepsMock, SoftBusGetBtState).WillRepeatedly(Return(BLE_ENABLE));

    int32_t ret = LnnOfflineTimingByHeartbeat(nullptr, CONNECTION_ADDR_BLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnOfflineTimingByHeartbeat(NETWORKID, CONNECTION_ADDR_BR);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnOfflineTimingByHeartbeat(NETWORKID, CONNECTION_ADDR_BLE);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL);
    ret = LnnOfflineTimingByHeartbeat(NETWORKID, CONNECTION_ADDR_BLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SHIFT_LNN_GEAR_TEST_001
 * @tc.desc: test LnnShiftLNNGear
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlTest, LNN_SHIFT_LNN_GEAR_TEST_001, TestSize.Level1)
{
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    DistributeLedgerInterfaceMock distributeNetLedgerMock;
    HeartBeatCtrlDepsInterfaceMock hbCtrlDepsMock;

    EXPECT_CALL(hbStrateMock, LnnSetGearModeBySpecificType)
        .WillOnce(Return(SOFTBUS_NETWORK_HB_INVALID_MGR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(distributeNetLedgerMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(hbCtrlDepsMock, AuthFlushDevice).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbCtrlDepsMock, AuthSendKeepaliveOption).WillRepeatedly(Return(SOFTBUS_OK));

    GearMode mode;
    int32_t ret = LnnShiftLNNGear(nullptr, CALLERID, TARGETNETWORKID, &mode);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnShiftLNNGear(PKGNAME, CALLERID, TARGETNETWORKID, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnShiftLNNGear(PKGNAME, nullptr, TARGETNETWORKID, &mode);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnShiftLNNGear(PKGNAME, CALLERID, TARGETNETWORKID, &mode);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_SET_GEAR_MODE_FAIL);
    ret = LnnShiftLNNGear(PKGNAME, CALLERID, TARGETNETWORKID, &mode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SHIFT_LNN_GEAR_WITHOUT_PKG_NAME_TEST_001
 * @tc.desc: test LnnShiftLNNGearWithoutPkgName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlTest, LNN_SHIFT_LNN_GEAR_WITHOUT_PKG_NAME_TEST_001, TestSize.Level1)
{
    GearMode mode;
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(hbStrateMock, LnnSetGearModeBySpecificType)
        .WillOnce(Return(SOFTBUS_NETWORK_HB_INVALID_MGR))
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = LnnShiftLNNGearWithoutPkgName(CALLERID, nullptr, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM || ret == SOFTBUS_NOT_IMPLEMENT);
    ret = LnnShiftLNNGearWithoutPkgName(nullptr, &mode, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM || ret == SOFTBUS_NOT_IMPLEMENT);
    ret = LnnShiftLNNGearWithoutPkgName(CALLERID, &mode, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_HB_SET_GEAR_MODE_FAIL || ret == SOFTBUS_NOT_IMPLEMENT);
    ret = LnnShiftLNNGearWithoutPkgName(CALLERID, &mode, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
    EXPECT_TRUE(ret == SOFTBUS_NO_ONLINE_DEVICE || ret == SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LNN_INIT_HEARBEAT_TEST_001
 * @tc.desc: test LnnInitHeartbeat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatCtrlTest, LNN_INIT_HEARBEAT_TEST_001, TestSize.Level1)
{
    NiceMock<LnnIpNetworkImplInterfaceMock> serviceMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    HeartBeatCtrlDepsInterfaceMock hbCtrlDepsMock;
    LnnNetLedgertInterfaceMock netLedgerMock;
    EXPECT_CALL(serviceMock, LnnRegisterEventHandler)
        .WillOnce(Return(SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStrateMock, LnnHbStrategyInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbCtrlDepsMock, IsEnableSoftBusHeartbeat).WillRepeatedly(Return(true));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitHeartbeat();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);
    ret = LnnInitHeartbeat();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);
    ret = LnnInitHeartbeat();
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
