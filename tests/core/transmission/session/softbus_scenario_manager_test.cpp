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

#include <gtest/gtest.h>

#include "softbus_scenario_manager.h"

#define VALID_TYPE_MIN 3

using namespace testing::ext;

namespace OHOS {

const char *g_localMac = "00:00:00:00:00:00";
const char *g_peerMac = "11:11:11:11:11:11";
const char *g_localMac1 = "18:65";
const char *g_localMac2 = "82:13";

class TransScenarioManagerTest : public testing::Test {
public:
    TransScenarioManagerTest()
    {}
    ~TransScenarioManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransScenarioManagerTest::SetUpTestCase(void)
{
    ScenarioManagerGetInstance();
}

void TransScenarioManagerTest::TearDownTestCase(void)
{
    ScenarioManagerdestroyInstance();
}

/**
 * @tc.name: TransScenarioManagerTest01
 * @tc.desc: Transmission scenario manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransScenarioManagerTest, TransScenarioManagerTest01, TestSize.Level1)
{
    int32_t ret = AddScenario(nullptr, g_peerMac, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = AddScenario(g_localMac, nullptr, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = AddScenario(g_localMac, g_peerMac, -1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = AddScenario(g_localMac, g_peerMac, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_NUM, ret);
    ret = AddScenario(g_localMac, g_peerMac, 1, VALID_TYPE_MIN);
    EXPECT_EQ(SOFTBUS_INVALID_NUM, ret);
    ret = AddScenario(g_localMac1, g_peerMac, 1, VALID_TYPE_MIN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddScenario(g_localMac2, g_peerMac, 1, VALID_TYPE_MIN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddScenario(g_localMac1, g_peerMac, 1, VALID_TYPE_MIN);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransScenarioManagerTest02
 * @tc.desc: Transmission scenario manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransScenarioManagerTest, TransScenarioManagerTest02, TestSize.Level1)
{
    int32_t ret = DelScenario(nullptr, g_peerMac, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = DelScenario(g_localMac, nullptr, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = DelScenario(g_localMac, g_peerMac, -1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = DelScenario(g_localMac, g_peerMac, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_NUM, ret);
    ret = DelScenario(g_localMac, g_peerMac, 1, VALID_TYPE_MIN);
    EXPECT_EQ(SOFTBUS_INVALID_NUM, ret);
    ret = DelScenario(g_localMac1, g_peerMac, 1, VALID_TYPE_MIN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelScenario(g_localMac2, g_peerMac, 1, VALID_TYPE_MIN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelScenario(g_localMac1, g_peerMac, 1, VALID_TYPE_MIN);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS