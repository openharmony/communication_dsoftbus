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

#include "lnn_node_weight.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr char UDID1[] = "123456789AB";
constexpr char UDID2[] = "123456789ab";
constexpr int32_t WEIGHT = 10;
constexpr int32_t WEIGHT2 = 5;
constexpr int32_t WEIGHT3 = 5;

class LnnNodeWeightTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnNodeWeightTest::SetUpTestCase()
{
}

void LnnNodeWeightTest::TearDownTestCase()
{
}

void LnnNodeWeightTest::SetUp()
{
}

void LnnNodeWeightTest::TearDown()
{
}

/*
* @tc.name: LNN_COMPARE_NODE_WEIGHT_TEST_001
* @tc.desc: test LnnCompareNodeWeight
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnNodeWeightTest, LNN_COMPARE_NODE_WEIGHT_TEST_001, TestSize.Level1)
{
    char *masterUdid = nullptr;
    int32_t ret = LnnCompareNodeWeight(WEIGHT, UDID1, WEIGHT2, UDID2);
    EXPECT_TRUE(ret == (WEIGHT - WEIGHT2));
    ret = LnnCompareNodeWeight(WEIGHT, masterUdid, WEIGHT2, UDID2);
    EXPECT_TRUE(ret == (WEIGHT - WEIGHT2));
    ret = LnnCompareNodeWeight(WEIGHT2, UDID1, WEIGHT3, UDID2);
    EXPECT_TRUE(ret < 0);
}
} // namespace OHOS
