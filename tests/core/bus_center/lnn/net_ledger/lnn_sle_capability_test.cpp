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

#include "lnn_sle_capability.h"
#include "lnn_sle_capability_mock.h"
#include "lnn_sle_capability.c"
#include "cJSON.h"
#include "softbus_json_utils.h"
#include "lnn_sync_info_manager_struct.h"

namespace OHOS {
using namespace testing::ext;
constexpr char NETWORK_ID[] = "235689BNHFCF";
constexpr char MSG[] = "testmsg";
constexpr char EMPTYMSG[] = "";

using namespace testing;
class LNNSleCapabilityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNSleCapabilityTest::SetUpTestCase() { }

void LNNSleCapabilityTest::TearDownTestCase() { }

void LNNSleCapabilityTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNSleCapabilityTest start");
}

void LNNSleCapabilityTest::TearDown()
{
    LNN_LOGI(LNN_TEST, "LNNSleCapabilityTest end");
}

/*
 * @tc.name: SetSleRangeCapToLocalLedgerTest001
 * @tc.desc: Verify SetSleRangeCapToLocalLedger sets SLE range capability
 *           to local ledger with different return values
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNSleCapabilityTest, SetSleRangeCapToLocalLedgerTest001, TestSize.Level1)
{
    int32_t sleRangeCap = 0;
    int32_t ret = 0;
    NiceMock<LnnSleCapabilityInterfaceMock> sleCapabilityMock;
    EXPECT_CALL(sleCapabilityMock, GetSleRangeCapacityPacked).WillRepeatedly(Return(sleRangeCap));
    EXPECT_CALL(sleCapabilityMock, LnnGetLocalNumInfo)
        .WillOnce(DoAll(SetArgPointee<1>(sleRangeCap), Return(SOFTBUS_OK)));
    ret = SetSleRangeCapToLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(sleCapabilityMock, LnnGetLocalNumInfo)
        .WillOnce(DoAll(SetArgPointee<1>(sleRangeCap), Return(SOFTBUS_ERR)));
    ret = SetSleRangeCapToLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetSleRangeCapToLocalLedgerTest002
 * @tc.desc: Verify SetSleRangeCapToLocalLedger handles different
 *           LnnUpdateSleCapacityAndVersion return values
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNSleCapabilityTest, SetSleRangeCapToLocalLedgerTest002, TestSize.Level1)
{
    int32_t sleRangeCap1 = 0;
    int32_t ret = 0;
    NiceMock<LnnSleCapabilityInterfaceMock> sleCapabilityMock;
    EXPECT_CALL(sleCapabilityMock, GetSleRangeCapacityPacked)
        .WillRepeatedly(Return(sleRangeCap1));
    int32_t sleRangeCap2 = 1;
    EXPECT_CALL(sleCapabilityMock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(sleRangeCap2), Return(SOFTBUS_OK)));
    EXPECT_CALL(sleCapabilityMock, LnnUpdateSleCapacityAndVersion)
        .WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));

    ret = SetSleRangeCapToLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = SetSleRangeCapToLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: SetSleAddrToLocalLedgerTest001
 * @tc.desc: Verify SetSleAddrToLocalLedger handles SLE enabled check
 *           and different GetLocalSleAddrPacked return values
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNSleCapabilityTest, SetSleAddrToLocalLedgerTest001, TestSize.Level1)
{
    int32_t ret = 0;
    NiceMock<LnnSleCapabilityInterfaceMock> sleCapabilityMock;
    EXPECT_CALL(sleCapabilityMock, IsSleEnabledPacked)
        .WillOnce(Return(false)).WillRepeatedly(Return(true));

    ret = SetSleAddrToLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_SLE_RANGING_NOT_ENABLE);

    EXPECT_CALL(sleCapabilityMock, GetLocalSleAddrPacked)
        .WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    ret = SetSleAddrToLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(sleCapabilityMock, LnnSetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    ret = SetSleAddrToLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = SetSleAddrToLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SleStateChangeEventHandlerTest001
 * @tc.desc: Verify SleStateChangeEventHandler handles SLE state change
 *           event with different GetSleRangeCapacityPacked results
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNSleCapabilityTest, SleStateChangeEventHandlerTest001, TestSize.Level1)
{
    int32_t sleRangeCap = 0;
    NiceMock<LnnSleCapabilityInterfaceMock> sleCapabilityMock;
    EXPECT_CALL(sleCapabilityMock, GetSleRangeCapacityPacked)
        .WillRepeatedly(Return(sleRangeCap));
    EXPECT_CALL(sleCapabilityMock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(sleRangeCap), Return(SOFTBUS_OK)));

    int state = SOFTBUS_SLE_STATE_TURN_ON;
    SleStateChangeEventHandler(state);
    state = SOFTBUS_SLE_STATE_TURNING_ON;
    SleStateChangeEventHandler(state);
    EXPECT_EQ(g_sleRangeCap, sleRangeCap);

    LnnSyncInfoType type = LNN_INFO_TYPE_SLE_MAC;
    uint32_t size = strlen(MSG) + 1;
    EXPECT_NO_FATAL_FAILURE(OnReceiveSleMacChangedMsg(LNN_INFO_TYPE_COUNT, NETWORK_ID, (const uint8_t *)MSG, size));
    EXPECT_NO_FATAL_FAILURE(OnReceiveSleMacChangedMsg(type, NULL, (const uint8_t *)MSG, size));
    EXPECT_NO_FATAL_FAILURE(OnReceiveSleMacChangedMsg(type, NETWORK_ID, NULL, size));
    EXPECT_NO_FATAL_FAILURE(OnReceiveSleMacChangedMsg(type, NETWORK_ID, NULL, 0));
    EXPECT_NO_FATAL_FAILURE(OnReceiveSleMacChangedMsg(type, NETWORK_ID, (const uint8_t *)EMPTYMSG, 1));
    EXPECT_NO_FATAL_FAILURE(OnReceiveSleMacChangedMsg(type, NETWORK_ID, (const uint8_t *)MSG, size + 1));
    EXPECT_NO_FATAL_FAILURE(OnReceiveSleMacChangedMsg(type, NETWORK_ID, (const uint8_t *)MSG, size));
}

/*
 * @tc.name: LocalLedgerInitSleCapacityTest001
 * @tc.desc: local ledger init sle capacity test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNSleCapabilityTest, LocalLedgerInitSleCapacityTest001, TestSize.Level1)
{
    NiceMock<LnnSleCapabilityInterfaceMock> sleCapabilityMock;
    int32_t ret = 0;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    ret = LocalLedgerInitSleCapacity(NULL);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(sleCapabilityMock, GetSleRangeCapacityPacked)
        .WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(sleCapabilityMock, SoftBusAddSleStateListenerPacked)
        .WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = LocalLedgerInitSleCapacity(&nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LocalLedgerInitSleCapacity(&nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: LnnInitSleInfoTest001
 * @tc.desc: lnn init sle info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNSleCapabilityTest, LnnInitSleInfoTest001, TestSize.Level1)
{
    NiceMock<LnnSleCapabilityInterfaceMock> sleCapabilityMock;
    int32_t ret = 0;
    EXPECT_CALL(sleCapabilityMock, LnnRegSyncInfoHandler)
        .WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = LnnInitSleInfo();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnInitSleInfo();
    EXPECT_EQ(ret, SOFTBUS_ERR);
}
} // namespace OHOS