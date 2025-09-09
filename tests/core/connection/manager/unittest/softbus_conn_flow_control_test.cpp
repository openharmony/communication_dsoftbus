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

#include <iostream>

#include <gtest/gtest.h>

#include "softbus_conn_flow_control.h"

using namespace testing::ext;

namespace OHOS::SoftBus {
class ConnFlowControlTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: ConstructAndDestruct
 * @tc.desc: check construct and destruct flow controller
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnFlowControlTest, ConstructAndDestruct, TestSize.Level1)
{
    {
        struct ConnSlideWindowController controller { };
        auto ret = ConnSlideWindowControllerConstructor(&controller);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }

    {
        auto controller = ConnSlideWindowControllerNew();
        EXPECT_NE(controller, nullptr);
        ConnSlideWindowControllerDelete(controller);
    }
}

/*
 * @tc.name: FlowControlWhenDefault
 * @tc.desc: check flow control when default case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnFlowControlTest, FlowControlWhenDefault, TestSize.Level1)
{
    auto controller = ConnSlideWindowControllerNew();
    EXPECT_NE(controller, nullptr);

    for (int32_t i = 0; i < 100; ++i) {
        int32_t expect = 512;
        uint64_t now = SoftBusGetSysTimeMs();
        auto value = controller->apply(controller, expect);
        uint64_t delta = SoftBusGetSysTimeMs() - now;
        EXPECT_EQ(value, expect);
        // less than 10ms
        EXPECT_TRUE(delta < 10);
    }
    ConnSlideWindowControllerDelete(controller);
}

/*
 * @tc.name: FlowControlWhenEnable
 * @tc.desc: check flow control when enable case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnFlowControlTest, FlowControlWhenEnable, TestSize.Level1)
{
    auto controller = ConnSlideWindowControllerNew();
    EXPECT_NE(controller, nullptr);

    auto ret = controller->enable(controller, 1, MIN_QUOTA_IN_BYTES);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = controller->enable(controller, MIN_WINDOW_IN_MILLIS, 1);
    EXPECT_NE(ret, SOFTBUS_OK);

    int32_t windowInMillis = MIN_WINDOW_IN_MILLIS;
    int32_t quotaInBytes = MIN_QUOTA_IN_BYTES;
    ret = controller->enable(controller, windowInMillis, quotaInBytes);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t applyValue = quotaInBytes / 2;
    uint64_t startTimestamp = SoftBusGetSysTimeMs();
    auto got = controller->apply(controller, applyValue);
    uint64_t delta = SoftBusGetSysTimeMs() - startTimestamp;
    EXPECT_EQ(got, applyValue);
    // less than 10ms
    EXPECT_TRUE(delta < 10);

    int32_t remain = quotaInBytes - got;
    startTimestamp = SoftBusGetSysTimeMs();
    got = controller->apply(controller, remain + 1);
    delta = SoftBusGetSysTimeMs() - startTimestamp;
    EXPECT_EQ(remain, got);
    // less than 10ms
    EXPECT_TRUE(delta < 10);

    startTimestamp = SoftBusGetSysTimeMs();
    got = controller->apply(controller, applyValue);
    delta = SoftBusGetSysTimeMs() - startTimestamp;
    EXPECT_EQ(got, applyValue);
    // more than 10ms, as it wait in controller
    EXPECT_TRUE(delta > 10);

    ret = controller->disable(controller);
    EXPECT_EQ(ret, SOFTBUS_OK);

    applyValue = quotaInBytes + 1;
    for (int32_t i = 0; i < 10; ++i) {
        startTimestamp = SoftBusGetSysTimeMs();
        got = controller->apply(controller, applyValue);
        delta = SoftBusGetSysTimeMs() - startTimestamp;
        EXPECT_EQ(got, applyValue);
        // less than 10ms
        EXPECT_TRUE(delta < 10);
    }
    ConnSlideWindowControllerDelete(controller);
}

} // namespace OHOS::SoftBus