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
#include "bus_center_manager.h"
#include "lnn_decision_center.h"
#include "lnn_heartbeat_ctrl.h"
#include "message_handler.h"
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;

static constexpr char TEST_PKG_NAME1[] = "com.softbus.test";
static constexpr char TEST_PKG_NAME2[] = "com.softbus.test1";

class BusCenterHeartbeatSdkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterHeartbeatSdkTest::SetUpTestCase()
{
    SetAccessTokenPermission("busCenterTest");
    LnnInitLnnLooper();
    LooperInit();
    LnnInitBusCenterEvent();
    LnnInitHeartbeat();
}

void BusCenterHeartbeatSdkTest::TearDownTestCase()
{
    LnnDeinitHeartbeat();
    LnnDeinitBusCenterEvent();
    LooperDeinit();
    LnnDeinitLnnLooper();
}

void BusCenterHeartbeatSdkTest::SetUp() { }

void BusCenterHeartbeatSdkTest::TearDown() { }

/*
 * @tc.name: Shift_Lnn_Gear_Test_001
 * @tc.desc: heart beat parameter adjust test
 * @tc.type: FUNC
 * @tc.require: I5HMXC
 */
HWTEST_F(BusCenterHeartbeatSdkTest, Shift_Lnn_Gear_Test_001, TestSize.Level1)
{
    char networkId1[] = "012345678B987654321001234A678998";
    char networkId2[] = "012345678B987654321001234A67899876543210012E4567899876543210012FFFFFFFFF012345678B9876";
    const char *callerId1 = "1";
    const char *callerId2 = "2";
    const char *callerId3 = "3";
    const char *callerId4 = "4";
    const char *callerId5 = "5";
    const char *callerId6 = "";
    const char *callerId7 = "012345678B987654321001234A67899876543210012E4567899876543210012FFFFFFFFF012345678B9876"
                            "54321001234A67899876543210012E4567899876543210012FFFFFFFFF";
    GearMode mode1 = { .cycle = MID_FREQ_CYCLE, .duration = DEFAULT_DURATION, .wakeupFlag = false };
    GearMode mode2 = { .cycle = HIGH_FREQ_CYCLE, .duration = DEFAULT_DURATION, .wakeupFlag = true };
    GearMode mode3 = { .cycle = LOW_FREQ_CYCLE, .duration = LONG_DURATION, .wakeupFlag = true };
    GearMode mode4 = { .cycle = HIGH_FREQ_CYCLE, .duration = NORMAL_DURATION, .wakeupFlag = true };
    GearMode mode5 = { .cycle = MID_FREQ_CYCLE, .duration = LONG_DURATION, .wakeupFlag = false };

    int32_t ret = ShiftLNNGear(TEST_PKG_NAME1, callerId1, NULL, &mode1);
    if (ret != SOFTBUS_NOT_IMPLEMENT) {
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId1, networkId1, &mode1), SOFTBUS_INVALID_PARAM);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId1, networkId2, &mode1), SOFTBUS_INVALID_PARAM);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId1, NULL, &mode1), SOFTBUS_OK);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME2, callerId1, NULL, &mode1), SOFTBUS_OK);
        EXPECT_EQ(ShiftLNNGear(NULL, callerId1, NULL, &mode1), SOFTBUS_INVALID_PARAM);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId1, NULL, NULL), SOFTBUS_INVALID_PARAM);

        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId1, NULL, &mode2), SOFTBUS_OK);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId2, NULL, &mode2), SOFTBUS_OK);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId3, NULL, &mode3), SOFTBUS_OK);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId4, NULL, &mode4), SOFTBUS_OK);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId5, NULL, &mode5), SOFTBUS_OK);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId6, NULL, &mode5), SOFTBUS_INVALID_PARAM);
        EXPECT_EQ(ShiftLNNGear(TEST_PKG_NAME1, callerId7, NULL, &mode5), SOFTBUS_INVALID_PARAM);
    }
}
} // namespace OHOS
