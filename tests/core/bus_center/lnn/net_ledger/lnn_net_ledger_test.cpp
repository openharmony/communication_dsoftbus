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
#include <securec.h>

#include "lnn_net_ledger.c"
#include "lnn_net_ledger_test_mock.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNNetLedgerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNetLedgerMockTest::SetUpTestCase() { }

void LNNNetLedgerMockTest::TearDownTestCase() { }

void LNNNetLedgerMockTest::SetUp() { }

void LNNNetLedgerMockTest::TearDown() { }

/*
 * @tc.name: LnnSetLocalFeatureTest001
 * @tc.desc: Verify LnnSetLocalFeature sets local feature capability
 *           with different mock return values
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnSetLocalFeatureTest001, TestSize.Level0)
{
    NiceMock<LnnNetLedgerInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, IsSupportLpFeaturePacked).WillOnce(Return(true)).WillRepeatedly(Return(false));
    EXPECT_CALL(netLedgerMock, LnnIsSupportLpSparkFeaturePacked).WillOnce(Return(true)).WillRepeatedly(Return(false));
    EXPECT_CALL(netLedgerMock, LnnClearFeatureCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetFeatureCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalByteInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
}
} // namespace OHOS