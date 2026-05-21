/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;

constexpr uint64_t TEST_DELAY_MILLIS = 1000;
constexpr uint32_t TEST_DATA_VALUE = 12345;

static bool g_callbackExecuted = false;
static uint32_t g_callbackData = 0;

static void TestCallback(void *para)
{
    g_callbackExecuted = true;
    if (para != nullptr) {
        g_callbackData = *(uint32_t *)para;
    }
}

class LnnAsyncCallbackUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnAsyncCallbackUtilsTest::SetUpTestCase()
{
    LooperInit();
}

void LnnAsyncCallbackUtilsTest::TearDownTestCase()
{
    LooperDeinit();
}

void LnnAsyncCallbackUtilsTest::SetUp()
{
    g_callbackExecuted = false;
    g_callbackData = 0;
}

void LnnAsyncCallbackUtilsTest::TearDown()
{
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_HELPER_TEST_001
 * @tc.desc: Verify LnnAsyncCallbackHelper handles null looper gracefully
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_HELPER_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnAsyncCallbackHelper((SoftBusLooper *)nullptr, TestCallback, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_HELPER_TEST_002
 * @tc.desc: Verify LnnAsyncCallbackHelper handles null callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_HELPER_TEST_002, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    int32_t ret = LnnAsyncCallbackHelper(looper, (LnnAsyncCallbackFunc)nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_HELPER_TEST_003
 * @tc.desc: Verify LnnAsyncCallbackHelper executes callback successfully
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_HELPER_TEST_003, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    g_callbackExecuted = false;
    int32_t ret = LnnAsyncCallbackHelper(looper, TestCallback, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    sleep(1);
    EXPECT_TRUE(g_callbackExecuted);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_HELPER_TEST_004
 * @tc.desc: Verify LnnAsyncCallbackHelper passes parameter to callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_HELPER_TEST_004, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    uint32_t testData = TEST_DATA_VALUE;
    g_callbackData = 0;
    int32_t ret = LnnAsyncCallbackHelper(looper, TestCallback, &testData);
    EXPECT_EQ(ret, SOFTBUS_OK);

    sleep(1);
    EXPECT_TRUE(g_callbackExecuted);
    EXPECT_EQ(g_callbackData, TEST_DATA_VALUE);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_001
 * @tc.desc: Verify LnnAsyncCallbackDelayHelper handles null looper
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnAsyncCallbackDelayHelper((SoftBusLooper *)nullptr, TestCallback, nullptr, TEST_DELAY_MILLIS);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_002
 * @tc.desc: Verify LnnAsyncCallbackDelayHelper handles null callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_002, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    int32_t ret = LnnAsyncCallbackDelayHelper(looper, (LnnAsyncCallbackFunc)nullptr, nullptr, TEST_DELAY_MILLIS);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_003
 * @tc.desc: Verify LnnAsyncCallbackDelayHelper executes callback after delay
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_003, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    g_callbackExecuted = false;
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, TestCallback, nullptr, TEST_DELAY_MILLIS);
    EXPECT_EQ(ret, SOFTBUS_OK);

    sleep(1);
    EXPECT_FALSE(g_callbackExecuted);

    sleep(1);
    EXPECT_TRUE(g_callbackExecuted);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_004
 * @tc.desc: Verify LnnAsyncCallbackDelayHelper passes parameter correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_004, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    uint32_t testData = TEST_DATA_VALUE;
    g_callbackData = 0;
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, TestCallback, &testData, TEST_DELAY_MILLIS);
    EXPECT_EQ(ret, SOFTBUS_OK);

    sleep(2);
    EXPECT_TRUE(g_callbackExecuted);
    EXPECT_EQ(g_callbackData, TEST_DATA_VALUE);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_005
 * @tc.desc: Verify LnnAsyncCallbackDelayHelper with zero delay
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_005, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    g_callbackExecuted = false;
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, TestCallback, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    sleep(1);
    EXPECT_TRUE(g_callbackExecuted);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_006
 * @tc.desc: Verify LnnAsyncCallbackHelper with multiple calls
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_HELPER_TEST_006, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    g_callbackExecuted = false;
    int32_t ret = LnnAsyncCallbackHelper(looper, TestCallback, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LnnAsyncCallbackHelper(looper, TestCallback, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    sleep(2);
}

/*
 * @tc.name: LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_007
 * @tc.desc: Verify LnnAsyncCallbackDelayHelper with different delay values
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnAsyncCallbackUtilsTest, LNN_ASYNC_CALLBACK_DELAY_HELPER_TEST_007, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(looper, nullptr);

    g_callbackExecuted = false;
    g_callbackData = 0;

    uint32_t testData1 = 111;
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, TestCallback, &testData1, 100);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint32_t testData2 = 222;
    ret = LnnAsyncCallbackDelayHelper(looper, TestCallback, &testData2, 200);
    EXPECT_EQ(ret, SOFTBUS_OK);

    sleep(2);
}
} // namespace OHOS
