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

#include "softbus_conn_async_helper.h"

#include <future>

#include <gtest/gtest.h>

#include "conn_log.h"

#include "softbus_conn_common_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS::SoftBus {
class ConnAsyncTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override { }

    void TearDown() override { }
};

/*
 * @tc.name: CreateDestroyAsyncTest
 * @tc.desc: test create and destroy async instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnAsyncTest, CreateDestroyAsyncTest, TestSize.Level1)
{
    auto ret = ConnAsyncConstruct(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ConnAsyncConstruct("test async", nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ConnAsync async {};
    ret = ConnAsyncConstruct("test async", &async, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    auto looper = CreateNewLooper("test_Lp");
    ret = ConnAsyncConstruct("test async", &async, looper);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnAsyncDestruct(&async);
    DestroyLooper(looper);
}

struct TestCase {
    std::string name;
    int64_t delayMs;
    bool cancel;
};

/*
 * @tc.name: AsyncOperationTest
 * @tc.desc: test async call and cancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnAsyncTest, AsyncOperationTest, TestSize.Level1)
{
    ConnCommonTestMock mock;

    ConnAsync async {};
    auto looper = CreateNewLooper("test_Lp");
    auto ret = ConnAsyncConstruct("test async", &async, looper);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TestCase testcases[] = {
        {
         .name = "timeout_0_no_cancel",
         .delayMs = 0,
         .cancel = false,
         },
        {
         .name = "timeout_500_no_cancel",
         .delayMs = 500,
         .cancel = false,
         },
        {
         .name = "timeout_500_cancel",
         .delayMs = 500,
         .cancel = true,
         }
    };

    for (auto &tc : testcases) {
        std::promise<int32_t> wait;
        EXPECT_CALL(mock, AsyncFunctionHook).Times(AtMost(1)).WillOnce([&wait, tc](int32_t callId, void *arg) {
            wait.set_value(callId);
            CONN_LOGI(CONN_TEST, "async function hook enter, tc name: %{public}s", tc.name.c_str());
        });

        auto start = std::chrono::system_clock::now();
        auto arg = std::make_shared<int>(0);
        auto callId = ConnAsyncCall(&async, ConnCommonTestMock::asyncFunction_, arg.get(), tc.delayMs);
        EXPECT_TRUE(callId > 0) << "test case:" << tc.name;
        if (tc.cancel) {
            EXPECT_CALL(mock, FreeAsyncArgHook).Times(1);
            ConnAsyncCancel(&async, callId, ConnCommonTestMock::asyncFreeHook_);
        }
        auto future = wait.get_future();
        auto status = future.wait_for(std::chrono::milliseconds(tc.delayMs + 100));
        if (tc.cancel) {
            EXPECT_NE(status, std::future_status::ready) << "test case:" << tc.name;
        } else {
            if (status == std::future_status::ready) {
                EXPECT_EQ(callId, future.get()) << "test case:" << tc.name;
            } else {
                ADD_FAILURE() << "test case:" << tc.name << ", async function not called";
            }
            auto end = std::chrono::system_clock::now();
            auto pastedMs = std::chrono::duration_cast<std::chrono::duration<int, std::milli>>(end - start).count();
            EXPECT_GE(pastedMs, tc.delayMs) << "test case:" << tc.name;
        }
        testing::Mock::VerifyAndClearExpectations(&mock);
    }

    ConnAsyncDestruct(&async);
    DestroyLooper(looper);
}

} // namespace OHOS::SoftBus