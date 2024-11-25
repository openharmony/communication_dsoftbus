/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "lnn_node_weight.c"
#include "lnn_node_weight.h"
#include "lnn_service_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr char UDID1[] = "123456789AB";
constexpr char UDID2[] = "123456789ab";
constexpr int32_t WEIGHT = 10;
constexpr int32_t WEIGHT2 = 5;
constexpr int32_t WEIGHT3 = 5;

class LNNNodeWeightTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNodeWeightTest::SetUpTestCase() { }

void LNNNodeWeightTest::TearDownTestCase() { }

void LNNNodeWeightTest::SetUp() { }

void LNNNodeWeightTest::TearDown() { }

/*
 * @tc.name: LNN_COMPARE_NODE_WEIGHT_TEST_001
 * @tc.desc: test LnnCompareNodeWeight
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNNodeWeightTest, LNN_COMPARE_NODE_WEIGHT_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnCompareNodeWeight(WEIGHT, UDID1, WEIGHT2, UDID2);
    EXPECT_TRUE(ret == (WEIGHT - WEIGHT2));
    ret = LnnCompareNodeWeight(WEIGHT, nullptr, WEIGHT, UDID2);
    EXPECT_TRUE(ret == (WEIGHT - WEIGHT));
    ret = LnnCompareNodeWeight(WEIGHT, UDID1, WEIGHT, nullptr);
    EXPECT_TRUE(ret == (WEIGHT - WEIGHT));
    ret = LnnCompareNodeWeight(WEIGHT2, UDID1, WEIGHT3, UDID2);
    EXPECT_TRUE(ret < 0);
}

/*
 * @tc.name: LNN_GET_LOCAL_WEIGHT_TEST_001
 * @tc.desc: test LnnGetLocalWeight
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNodeWeightTest, LNN_GET_LOCAL_WEIGHT_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> lnnServiceMock;
    EXPECT_CALL(lnnServiceMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_GENERATE_RANDOM_ARRAY_FAIL));
    int32_t ret = LnnGetLocalWeight();
    EXPECT_EQ(ret, SOFTBUS_OK);
    unsigned char randStr = 20;
    EXPECT_CALL(lnnServiceMock, SoftBusGenerateRandomArray)
        .WillRepeatedly(DoAll(SetArgPointee<0>(randStr), Return(SOFTBUS_OK)));
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    ret = LnnGetLocalWeight();
    EXPECT_EQ(ret, 78);
    ret = LnnGetLocalWeight();
    EXPECT_EQ(ret, 78);
}
} // namespace OHOS
