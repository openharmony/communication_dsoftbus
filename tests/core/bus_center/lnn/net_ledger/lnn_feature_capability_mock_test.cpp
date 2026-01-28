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

#include "lnn_feature_capability.h"
#include "lnn_feature_capability_mock.h"
#include "lnn_log.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;

using namespace testing;
class LNNFeatureCapabilityMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNFeatureCapabilityMockTest::SetUpTestCase() { }

void LNNFeatureCapabilityMockTest::TearDownTestCase() { }

void LNNFeatureCapabilityMockTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNFeatureCapabilityMockTest start");
}

void LNNFeatureCapabilityMockTest::TearDown()
{
    LNN_LOGI(LNN_TEST, "LNNFeatureCapabilityMockTest end");
}

/*
 * @tc.name: SetSparkGroupFearureTest001
 * @tc.desc: test SetSparkGroupFearure branch
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNFeatureCapabilityMockTest, SetSparkGroupFeatureTest001, TestSize.Level1)
{
    uint64_t configValue = 0;
    NiceMock<LnnFeatureCapabilityInterfaceMock> featureCapMock;
    EXPECT_CALL(featureCapMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<1>(configValue), Return(SOFTBUS_OK)));
    EXPECT_CALL(featureCapMock, IsSparkGroupEnabledPacked).WillOnce(Return(false)).WillRepeatedly(Return(true));
    uint64_t sparkFeature = 1 << BIT_SUPPORT_SPARK_GROUP_CAPABILITY;
    uint64_t ret = LnnGetFeatureCapabilty();
    EXPECT_FALSE(ret & sparkFeature);
    ret = LnnGetFeatureCapabilty();
    EXPECT_TRUE(ret & sparkFeature);
}
} // namespace OHOS