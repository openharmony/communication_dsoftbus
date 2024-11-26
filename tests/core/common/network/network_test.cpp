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

#include "securec.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_network_utils.h"

#define TEST_2G_CHANNEL   8
#define TEST_5G_CHANNEL   36
#define TEST_2G_FREQUENCY 2424
#define TEST_5G_FREQUENCY 5248

using namespace std;
using namespace testing::ext;

namespace OHOS {
class CommonCoreNetworkTest : public testing::Test {
public:
    CommonCoreNetworkTest() { }
    ~CommonCoreNetworkTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void CommonCoreNetworkTest::SetUpTestCase(void) { }
void CommonCoreNetworkTest::TearDownTestCase(void) { }

/**
 * @tc.name: SoftBusChannelToFrequencyTest001
 * @tc.desc: core common network channel to frequency test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreNetworkTest, SoftBusChannelToFrequencyTest001, TestSize.Level0)
{
    int32_t channel = -1;
    int32_t ret = SoftBusChannelToFrequency(channel);
    EXPECT_NE(SOFTBUS_ERR, ret);

    channel = TEST_2G_CHANNEL;
    ret = SoftBusChannelToFrequency(channel);
    EXPECT_NE(SOFTBUS_ERR, ret);

    channel = TEST_5G_CHANNEL;
    ret = SoftBusChannelToFrequency(channel);
    EXPECT_NE(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: SoftBusFrequencyToChannelTest001
 * @tc.desc: core common network frequency to channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreNetworkTest, SoftBusFrequencyToChannelTest001, TestSize.Level0)
{
    int32_t frequency = -1;
    int32_t ret = SoftBusFrequencyToChannel(frequency);
    EXPECT_NE(SOFTBUS_ERR, ret);

    frequency = TEST_2G_FREQUENCY;
    ret = SoftBusFrequencyToChannel(frequency);
    EXPECT_NE(SOFTBUS_ERR, ret);

    frequency = TEST_5G_FREQUENCY;
    ret = SoftBusFrequencyToChannel(frequency);
    EXPECT_NE(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: SoftBusBandCheckTest001
 * @tc.desc: core common network band check test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreNetworkTest, SoftBusBandCheckTest001, TestSize.Level0)
{
    int32_t frequency = -1;
    bool result = SoftBusIs5GBand(frequency);
    EXPECT_NE(true, result);

    result = SoftBusIs2GBand(frequency);
    EXPECT_NE(true, result);

    frequency = TEST_2G_FREQUENCY;
    result = SoftBusIs2GBand(frequency);
    EXPECT_EQ(true, result);

    frequency = TEST_5G_FREQUENCY;
    result = SoftBusIs5GBand(frequency);
    EXPECT_EQ(true, result);
}
} // namespace OHOS