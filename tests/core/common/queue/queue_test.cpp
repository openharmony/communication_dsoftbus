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

#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_queue.h"

#define INVALID_NUM        (-1)
#define IS_POWER_OF_2_NUM  4
#define NOT_POWER_OF_2_NUM 5
#define QUEUE_SIZE_MAX     8193

using namespace std;
using namespace testing::ext;

namespace OHOS {
class CommonCoreQueueTest : public testing::Test {
public:
    CommonCoreQueueTest() { }
    ~CommonCoreQueueTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void CommonCoreQueueTest::SetUpTestCase(void) { }
void CommonCoreQueueTest::TearDownTestCase(void) { }

/**
 * @tc.name: QueueInitTest001
 * @tc.desc: core common QueueInit invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreQueueTest, QueueInitTest001, TestSize.Level1)
{
    LockFreeQueue queue;
    int32_t ret = QueueInit(nullptr, IS_POWER_OF_2_NUM);
    EXPECT_EQ(ret, QUEUE_INVAL);
    ret = QueueInit(&queue, INVALID_NUM);
    EXPECT_EQ(ret, QUEUE_INVAL);
    ret = QueueInit(&queue, NOT_POWER_OF_2_NUM);
    EXPECT_EQ(ret, QUEUE_INVAL);
}

/**
 * @tc.name: QueueSizeCalcTest001
 * @tc.desc: core common QueueSizeCalc invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreQueueTest, QueueSizeCalcTest001, TestSize.Level1)
{
    uint32_t queueSize;
    int32_t ret = QueueSizeCalc(IS_POWER_OF_2_NUM, nullptr);
    EXPECT_EQ(ret, QUEUE_INVAL);
    ret = QueueSizeCalc(QUEUE_SIZE_MAX + 1, &queueSize);
    EXPECT_EQ(ret, QUEUE_INVAL);
}

/**
 * @tc.name: QueueCountGetTest001
 * @tc.desc: core common QueueCountGet invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreQueueTest, QueueCountGetTest001, TestSize.Level1)
{
    LockFreeQueue queue;
    uint32_t count;
    int32_t ret = QueueCountGet(nullptr, &count);
    EXPECT_EQ(ret, QUEUE_INVAL);
    ret = QueueCountGet(&queue, nullptr);
    EXPECT_EQ(ret, QUEUE_INVAL);
}

/**
 * @tc.name: CreateQueueTest001
 * @tc.desc: core common CreateQueueTest invalid param test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreQueueTest, CreateQueueTest001, TestSize.Level1)
{
    LockFreeQueue *queue = CreateQueue(INVALID_NUM);
    EXPECT_EQ(queue, nullptr);
    queue = CreateQueue(NOT_POWER_OF_2_NUM);
    EXPECT_EQ(queue, nullptr);
    SoftBusFree(queue);
}

/**
 * @tc.name: CreateQueueTest002
 * @tc.desc: core common CreateQueue success test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreQueueTest, CreateQueueTest002, TestSize.Level1)
{
    uint32_t count;
    LockFreeQueue *queue = CreateQueue(IS_POWER_OF_2_NUM);
    EXPECT_NE(queue, nullptr);
    int32_t ret = QueueCountGet(queue, &count);
    EXPECT_EQ(ret, 0);
    SoftBusFree(queue);
}
} // namespace OHOS