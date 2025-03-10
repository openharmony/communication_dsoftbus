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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>
#include <securec.h>
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_ledger.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNLaneLinkLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkLedgerTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkLedgerTest start";
    int32_t ret = InitLinkLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void LNNLaneLinkLedgerTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkLedgerTest end";
    DeinitLinkLedger();
}

void LNNLaneLinkLedgerTest::SetUp()
{
}

void LNNLaneLinkLedgerTest::TearDown()
{
}

/*
* @tc.name: LNN_ADD_LINK_BUILD_INFO_TEST_001
* @tc.desc: test lane add link build info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_ADD_LINK_BUILD_INFO_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnAddLinkLedgerInfo(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS