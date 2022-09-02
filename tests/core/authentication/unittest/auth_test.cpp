/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <sys/time.h>
#include <cinttypes>

#include "auth_common.h"
#include "auth_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_access_token_test.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
using namespace testing::ext;
class AuthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthTest::SetUpTestCase()
{
    SetAceessTokenPermission("AuthTest");
}

void AuthTest::TearDownTestCase()
{
}

void AuthTest::SetUp()
{
    LOG_INFO("AuthTest start.");
}

void AuthTest::TearDown()
{
}

/*
* @tc.name: AUTH_COMMON_Test_001
* @tc.desc: auth commone test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(AuthTest, AUTH_COMMON_Test_001, TestSize.Level0)
{
    int32_t ret = AuthCommonInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS
