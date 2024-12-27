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

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_decision_center.h"
#include "bus_center_decision_center_mock.h"
#include "bus_center_manager.h"
#include "lnn_decision_center.h"
#include "lnn_log.h"
#include "lnn_net_builder_mock.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define HCI_ERR_BR_CONN_PAGE_TIMEOUT               0x04
#define HCI_ERR_BR_CONN_PEER_NOT_SUPORT_SDP_RECODE 0x54
#define HCI_ERR_BR_CONN_ACL_RECREATE               0x57

typedef struct {
    SoftBusList *connections;
    bool initFlag;
} ExceptionConnMgr;

static ExceptionConnMgr g_exceptionConnMgr;

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class BusCenterDecisionCenterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterDecisionCenterTest::SetUpTestCase() { }

void BusCenterDecisionCenterTest::TearDownTestCase() { }

void BusCenterDecisionCenterTest::SetUp() { }

void BusCenterDecisionCenterTest::TearDown() { }

/*
 * @tc.name: LnnDCProcessOnlineState_Test01
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCProcessOnlineState_Test01, TestSize.Level1)
{
    bool isOnline = true;
    NodeBasicInfo info;
    int32_t ret = InitDecisionCenter();
    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    LnnDCProcessOnlineState(isOnline, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCProcessOnlineState_Test02
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCProcessOnlineState_Test02, TestSize.Level1)
{
    bool isOnline = false;
    NodeBasicInfo info;
    int32_t ret = InitDecisionCenter();
    NiceMock<BusCenterDecisionCenterInterfaceMock> busCenterDecisionCenterMock;
    EXPECT_CALL(busCenterDecisionCenterMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    LnnDCProcessOnlineState(isOnline, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCProcessOnlineState_Test03
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCProcessOnlineState_Test03, TestSize.Level1)
{
    bool isOnline = false;
    NodeBasicInfo info;
    NiceMock<BusCenterDecisionCenterInterfaceMock> busCenterDecisionCenterMock;
    int32_t ret = InitDecisionCenter();
    EXPECT_CALL(busCenterDecisionCenterMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    LnnDCProcessOnlineState(isOnline, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LeaveSpecificBrNetworkTest_01
 * @tc.desc: test int endian convert functionp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LeaveSpecificBrNetworkTest_01, TestSize.Level1)
{
    NiceMock<BusCenterDecisionCenterInterfaceMock> busCenterDecisionCenterMock;
    EXPECT_CALL(busCenterDecisionCenterMock, LnnGetNetworkIdByBtMac).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(option != nullptr);
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    LnnDCReportConnectException(option, errorCode);
    SoftBusFree(option);
}

/*
 * @tc.name: LeaveSpecificBrNetworkTest_02
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BusCenterDecisionCenterTest, LeaveSpecificBrNetworkTest_02, TestSize.Level1)
{
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    NiceMock<BusCenterDecisionCenterInterfaceMock> busCenterDecisionCenterMock;
    EXPECT_CALL(busCenterDecisionCenterMock, LnnGetNetworkIdByBtMac).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillOnce(Return(SOFTBUS_OK));
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(option != nullptr);
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    LnnDCReportConnectException(option, errorCode);
    SoftBusFree(option);
}

/*
 * @tc.name: LeaveSpecificBrNetworkTest_03
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LeaveSpecificBrNetworkTest_03, TestSize.Level1)
{
    NiceMock<BusCenterDecisionCenterInterfaceMock> busCenterDecisionCenterMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(busCenterDecisionCenterMock, LnnGetNetworkIdByBtMac).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(option != nullptr);
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    LnnDCReportConnectException(option, errorCode);
    SoftBusFree(option);
}

/*
 * @tc.name: HandleBrConnectExceptionTest_01
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, HandleBrConnectExceptionTest_01, TestSize.Level1)
{
    int32_t errorCode = SOFTBUS_OK;
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(option != nullptr);
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    LnnDCReportConnectException(option, errorCode);
    SoftBusFree(option);
}

/*
 * @tc.name: HandleBrConnectExceptionTest_02
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, HandleBrConnectExceptionTest_02, TestSize.Level1)
{
    int32_t errorCode = HCI_ERR_BR_CONN_PAGE_TIMEOUT;
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(option != nullptr);
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    LnnDCReportConnectException(option, errorCode);
    SoftBusFree(option);
}

/*
 * @tc.name: HandleBrConnectExceptionTest_03
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, HandleBrConnectExceptionTest_03, TestSize.Level1)
{
    int32_t errorCode = HCI_ERR_BR_CONN_PEER_NOT_SUPORT_SDP_RECODE;
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(option != nullptr);
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    LnnDCReportConnectException(option, errorCode);
    SoftBusFree(option);
}

/*
 * @tc.name: HandleBrConnectExceptionTest_04
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, HandleBrConnectExceptionTest_04, TestSize.Level1)
{
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    int32_t ret = InitDecisionCenter();
    NiceMock<BusCenterDecisionCenterInterfaceMock> busCenterDecisionCenterMock;
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(option != nullptr);
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    EXPECT_CALL(busCenterDecisionCenterMock, LnnGetNetworkIdByBtMac)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnDCReportConnectException(option, errorCode);
    SoftBusFree(option);
}

/*
 * @tc.name: ClearBrConnectExceptionTest_01
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, ClearBrConnectExceptionTest_01, TestSize.Level1)
{
    int32_t ret = InitDecisionCenter();
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(option != nullptr);
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    LnnDCClearConnectException(option);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(option);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_01
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_01, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_TCP;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_02
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_02, TestSize.Level1)
{
    ConnectOption option = {};
    NiceMock<BusCenterDecisionCenterInterfaceMock> busCenterDecisionCenterMock;
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    int32_t ret = InitDecisionCenter();
    option.type = CONNECT_BR;
    (void)strcpy_s(option.brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    EXPECT_CALL(busCenterDecisionCenterMock, LnnGetNetworkIdByBtMac)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_03
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_03, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_BLE;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_04
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_04, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_P2P;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_05
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_05, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_P2P;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_06
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_06, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_P2P_REUSE;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_07
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_07, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_BLE_DIRECT;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_08
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_08, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_HML;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_09
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_09, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_TRIGGER_HML;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnDCReportConnectExceptionTest_10
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, LnnDCReportConnectExceptionTest_10, TestSize.Level1)
{
    ConnectOption option = {};
    int32_t ret = InitDecisionCenter();
    int32_t errorCode = HCI_ERR_BR_CONN_ACL_RECREATE;
    option.type = CONNECT_TYPE_MAX;
    LnnDCReportConnectException(&option, errorCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: InitDecisionCenterTest_1
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, InitDecisionCenterTest_1, TestSize.Level1)
{
    g_exceptionConnMgr.connections = nullptr;
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: InitDecisionCenterTest_2
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, InitDecisionCenterTest_2, TestSize.Level1)
{
    g_exceptionConnMgr.connections = (SoftBusList *)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_TRUE(g_exceptionConnMgr.connections != nullptr);
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (g_exceptionConnMgr.connections != nullptr) {
        SoftBusFree(g_exceptionConnMgr.connections);
    }
}

/*
 * @tc.name: DeinitDecisionCenterTest_1
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, DeinitDecisionCenterTest_1, TestSize.Level1)
{
    g_exceptionConnMgr.connections = nullptr;
    int32_t ret = InitDecisionCenter();
    DeinitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DeinitDecisionCenterTest_2
 * @tc.desc: test int endian convert function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterDecisionCenterTest, DeinitDecisionCenterTest_2, TestSize.Level1)
{
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeinitDecisionCenter();
    EXPECT_FALSE(g_exceptionConnMgr.initFlag);
    EXPECT_EQ(g_exceptionConnMgr.connections, nullptr);
    if (g_exceptionConnMgr.connections != nullptr) {
        SoftBusFree(g_exceptionConnMgr.connections);
        g_exceptionConnMgr.connections = nullptr;
    }
}

} // namespace OHOS