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
} // namespace OHOS
