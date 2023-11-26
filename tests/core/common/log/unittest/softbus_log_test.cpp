/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <gtest/gtest.h>

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_log_old.h"
#include "softbus_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class SoftBusLogTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SoftBusLogTest::SetUpTestCase(void)
{
}

void SoftBusLogTest::TearDownTestCase(void)
{
}

void SoftBusLogTest::SetUp(void)
{
}

void SoftBusLogTest::TearDown(void)
{
}

/**
 * @tc.name: AnonymizesTest001
 * @tc.desc: Anonymize.
 * @tc.type: FUNC
 * @tc.require: I60DWN
 */
HWTEST_F(SoftBusLogTest, AnonymizesTest001, TestSize.Level1)
{
    const char *target = nullptr;
    uint8_t expectAnonymizedLength = 0;
    const char *expected = "NULL";
    const char *actual = Anonymizes(target, expectAnonymizedLength);
    EXPECT_STREQ(expected, actual);

    const char *target1 = "target";
    uint8_t expectAnonymizedLength1 = 0;
    const char *expected1 = "BADLENGTH";
    const char *actual1 = Anonymizes(target1, expectAnonymizedLength1);
    EXPECT_STREQ(expected1, actual1);

    const char *target2 = "target";
    uint8_t expectAnonymizedLength2 = 6;
    const char *expected2 = "TOOSHORT";
    const char *actual2 = Anonymizes(target2, expectAnonymizedLength2);
    EXPECT_STREQ(expected2, actual2);
}

/**
 * @tc.name: AnonyDevIdTest001
 * @tc.desc: Anonymize devid.
 * @tc.type: FUNC
 * @tc.require: I60DWN
 */
HWTEST_F(SoftBusLogTest, AnonyDevIdTest001, TestSize.Level1)
{
    char *outName = nullptr;
    const char *inName = nullptr;
    const char *expected = "null";
    const char *actual = AnonyDevId(&outName, inName);
    EXPECT_STREQ(expected, actual);
    SoftBusFree(outName);

    char *outName2 = nullptr;
    const char *inName2 = "abcdeg";
    const char *expected2 = "abcdeg";
    const char *actual2 = AnonyDevId(&outName2, inName2);
    EXPECT_STREQ(expected2, actual2);
    SoftBusFree(outName2);
}

} // namespace OHOS