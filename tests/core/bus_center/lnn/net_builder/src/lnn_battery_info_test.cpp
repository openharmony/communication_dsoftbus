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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_net_ledger_mock.h"
#include "softbus_errcode.h"
#include "lnn_battery_info.c"
#include "lnn_battery_info.h"
#include "lnn_sync_info_mock.h"

#define TEST_VALID_PEER_NETWORKID "12345678"
#define TEST_VALID_UDID_LEN 32

constexpr int32_t LEVEL = 10;
constexpr char UDID1[] = "123456789AB";

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class LNNBatteryInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNBatteryInfoTest::SetUpTestCase()
{
}

void LNNBatteryInfoTest::TearDownTestCase()
{
}

void LNNBatteryInfoTest::SetUp()
{
}

void LNNBatteryInfoTest::TearDown()
{
}

/*
* @tc.name: LNN_SYNC_BATTERY_INFO_TEST_001
* @tc.desc: test LnnSyncBatteryInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNBatteryInfoTest, LNN_SYNC_BATTERY_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnSyncInfoInterfaceMock> SyncInfoMock;
    EXPECT_CALL(SyncInfoMock, LnnSendSyncInfoMsg).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnSyncBatteryInfo(UDID1, LEVEL, true);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = LnnSyncBatteryInfo(UDID1, LEVEL, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS

