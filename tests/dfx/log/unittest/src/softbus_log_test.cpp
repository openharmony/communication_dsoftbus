/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gmock/gmock-matchers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>

#include "hilog_mock.h"
#include "softbus_log.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace {
const char *TEST_LOG_DETAIL = "softbus test log";
} // namespace

namespace OHOS {
class SoftBusLogTest : public testing::Test { };
/**
 * @tc.name: SoftBusLogTest001
 * @tc.desc: Test SOFTBUS_LOG_INNER macro
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(SoftBusLogTest, SoftBusLogTest001, TestSize.Level0)
{
    LogLevel level = LOG_INFO;
    SoftBusLogLabel label = {
        .domain = DOMAIN_ID_TEST,
        .tag = "SoftBusTest",
    };

    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(level), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    SOFTBUS_LOG_INNER(level, label, "%{public}s", TEST_LOG_DETAIL);
}
} // namespace OHOS
