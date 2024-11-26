/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "lnn_bt_network_impl.c"
#include "lnn_bt_network_impl_mock.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

#define BLE_DISABLE            0
#define LNN_DEFAULT_IF_NAME_BR "br0"
namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNBtNetworkImplMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNBtNetworkImplMockTest::SetUpTestCase()
{
    LooperInit();
}

void LNNBtNetworkImplMockTest::TearDownTestCase()
{
    LooperDeinit();
}

void LNNBtNetworkImplMockTest::SetUp() { }

void LNNBtNetworkImplMockTest::TearDown() { }

/*
 * @tc.name: LNN_BT_NETWORK_IMPL_TEST_001
 * @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNBtNetworkImplMockTest, LNN_BT_NETWORK_IMPL_TEST_001, TestSize.Level1)
{
    NiceMock<LnnBtNetworkImplInterfaceMock> btMock;
    EXPECT_CALL(btMock, LnnRegisterEventHandler(_, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitBtProtocol(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = LnnInitBtProtocol(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_BT_NETWORK_IMPL_TEST_002
 * @tc.desc: relationNum is NULL return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNBtNetworkImplMockTest, LNN_BT_NETWORK_IMPL_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnBtNetworkImplInterfaceMock> btMock;
    EXPECT_CALL(ledgerMock, LnnGetNetworkIdByBtMac)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(btMock, LnnRequestLeaveSpecific)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnMonitorBtAclStateChangedEvent btEvent1 = {
        .basic.event = LNN_EVENT_BT_ACL_STATE_CHANGED,
        .status = (uint8_t)SOFTBUS_BR_ACL_CONNECTED,
    };
    LnnMonitorBtAclStateChangedEvent btEvent2 = {
        .basic.event = LNN_EVENT_BT_ACL_STATE_CHANGED,
        .status = (uint8_t)SOFTBUS_BR_ACL_DISCONNECTED,
        .btMac = "btmac",
    };
    BtAclStateChangedEvtHandler(nullptr);
    BtAclStateChangedEvtHandler((LnnEventBasicInfo *)&btEvent1);
    BtAclStateChangedEvtHandler((LnnEventBasicInfo *)&btEvent2);
    BtAclStateChangedEvtHandler((LnnEventBasicInfo *)&btEvent2);
    BtAclStateChangedEvtHandler((LnnEventBasicInfo *)&btEvent2);
}

/*
 * @tc.name: LNN_BT_NETWORK_IMPL_TEST_003
 * @tc.desc: *invalid parameter
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNBtNetworkImplMockTest, LNN_BT_NETWORK_IMPL_TEST_003, TestSize.Level1)
{
    NiceMock<LnnBtNetworkImplInterfaceMock> btMock;
    EXPECT_CALL(btMock, LnnNotifyPhysicalSubnetStatusChanged).WillRepeatedly(Return());
    LnnNetIfMgr netifManager1 = {
        .type = LNN_NETIF_TYPE_BR,
    };
    const LnnNetIfMgr netifManager2 = {
        .type = LNN_NETIF_TYPE_BLE,
    };
    const LnnNetIfMgr netifManager3 = {
        .type = LNN_NETIF_TYPE_WLAN,
    };
    SoftBusBtState btState = SOFTBUS_BR_TURN_ON;
    void *data = (void *)(&btState);
    EXPECT_TRUE(NotifyBtStatusChanged(&netifManager1, data) == CHOICE_VISIT_NEXT);
    btState = SOFTBUS_BLE_TURN_ON;
    data = (void *)(&btState);
    EXPECT_TRUE(NotifyBtStatusChanged(&netifManager2, data) == CHOICE_VISIT_NEXT);
    EXPECT_TRUE(NotifyBtStatusChanged(&netifManager3, data) == CHOICE_VISIT_NEXT);
}

/*
 * @tc.name: LNN_BT_NETWORK_IMPL_TEST_004
 * @tc.desc: *invalid parameter
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNBtNetworkImplMockTest, LNN_BT_NETWORK_IMPL_TEST_004, TestSize.Level1)
{
    NiceMock<LnnBtNetworkImplInterfaceMock> btMock;
    EXPECT_CALL(btMock, LnnGetNetIfTypeByName)
        .WillRepeatedly(LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBr);
    EXPECT_CALL(btMock, LnnRegistPhysicalSubnet)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnProtocolManager self = { 0 };
    LnnNetIfMgr netifMgr = {
        .ifName = "name",
    };
    int32_t ret = LnnEnableBtProtocol(&self, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnEnableBtProtocol(&self, &netifMgr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = LnnEnableBtProtocol(&self, &netifMgr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_BT_NETWORK_IMPL_TEST_005
 * @tc.desc: *invalid parameter
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNBtNetworkImplMockTest, LNN_BT_NETWORK_IMPL_TEST_005, TestSize.Level1)
{
    NiceMock<LnnBtNetworkImplInterfaceMock> btMock;
    EXPECT_CALL(btMock, LnnRequestLeaveByAddrType)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnPhysicalSubnet *subnet = reinterpret_cast<LnnPhysicalSubnet *>(SoftBusMalloc(sizeof(LnnPhysicalSubnet)));
    memset_s(subnet, sizeof(LnnPhysicalSubnet), 0, sizeof(LnnPhysicalSubnet));
    subnet->status = LNN_SUBNET_IDLE;
    DestroyBtSubnetManager(subnet);

    LnnPhysicalSubnet *subnet1 = reinterpret_cast<LnnPhysicalSubnet *>(SoftBusMalloc(sizeof(LnnPhysicalSubnet)));
    memset_s(subnet1, sizeof(LnnPhysicalSubnet), 0, sizeof(LnnPhysicalSubnet));
    subnet1->status = LNN_SUBNET_RUNNING;
    DestroyBtSubnetManager(subnet1);
}

/*
 * @tc.name: LNN_BT_NETWORK_IMPL_TEST_006
 * @tc.desc: *invalid parameter
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNBtNetworkImplMockTest, LNN_BT_NETWORK_IMPL_TEST_006, TestSize.Level1)
{
    NiceMock<LnnBtNetworkImplInterfaceMock> btMock;
    LnnPhysicalSubnet subnet = {
        .ifName = LNN_DEFAULT_IF_NAME_BR,
        .status = LNN_SUBNET_RUNNING,
    };
    EXPECT_CALL(btMock, SoftBusGetBtState).WillRepeatedly(Return(BLE_DISABLE));
    EXPECT_CALL(btMock, LnnRequestLeaveByAddrType)
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    OnBtNetifStatusChanged(nullptr, nullptr);

    EXPECT_CALL(btMock, LnnGetNetIfTypeByName)
        .WillOnce(LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBr);
    SoftBusBtState btState1 = SOFTBUS_BR_TURN_ON;
    OnBtNetifStatusChanged(&subnet, (void *)(&btState1));

    EXPECT_CALL(btMock, LnnGetNetIfTypeByName)
        .WillOnce(LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBle);
    OnBtNetifStatusChanged(&subnet, (void *)(&btState1));

    EXPECT_CALL(btMock, LnnGetNetIfTypeByName)
    .WillOnce(LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBr);
    SoftBusBtState btState2 = SOFTBUS_BR_TURN_OFF;
    OnBtNetifStatusChanged(&subnet, (void *)(&btState2));

    EXPECT_CALL(btMock, LnnGetNetIfTypeByName)
        .WillOnce(LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBle);
    OnBtNetifStatusChanged(&subnet, (void *)(&btState2));
}

/*
 * @tc.name: LNN_BT_NETWORK_IMPL_TEST_007
 * @tc.desc: *invalid parameter
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNBtNetworkImplMockTest, LNN_BT_NETWORK_IMPL_TEST_007, TestSize.Level1)
{
    char macStr[] = "123456789";
    NiceMock<LnnBtNetworkImplInterfaceMock> btMock;
    EXPECT_CALL(btMock, SoftBusGetBtMacAddr)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(btMock, ConvertBtMacToStr).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = GetAvailableBtMac(macStr, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = GetAvailableBtMac(macStr, BT_MAC_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = GetAvailableBtMac(macStr, BT_MAC_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = GetAvailableBtMac(macStr, BT_MAC_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS
