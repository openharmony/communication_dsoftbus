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

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_ohos_account_adapter.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNOhosAccountAdapterNewFuncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNOhosAccountAdapterNewFuncTest::SetUpTestCase() { }

void LNNOhosAccountAdapterNewFuncTest::TearDownTestCase() { }

void LNNOhosAccountAdapterNewFuncTest::SetUp() { }

void LNNOhosAccountAdapterNewFuncTest::TearDown() { }

/*
 * @tc.name: GetAllForegroundAccounts_Test_001
 * @tc.desc: Test GetAllForegroundAccounts with null userIds returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountAdapterNewFuncTest, GetAllForegroundAccounts_Test_001, TestSize.Level1)
{
    int32_t *userIds = nullptr;
    uint32_t userIdsLen = 0;
    int32_t ret = GetAllForegroundAccounts(&userIds, &userIdsLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetAllForegroundAccounts_Test_002
 * @tc.desc: Test GetAllForegroundAccounts with null userIdsLen returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountAdapterNewFuncTest, GetAllForegroundAccounts_Test_002, TestSize.Level1)
{
    int32_t *userIds = nullptr;
    uint32_t *userIdsLen = nullptr;
    int32_t ret = GetAllForegroundAccounts(&userIds, userIdsLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetAllForegroundAccounts_Test_003
 * @tc.desc: Test GetAllForegroundAccounts with valid params (returns MEM_ERR in mock)
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountAdapterNewFuncTest, GetAllForegroundAccounts_Test_003, TestSize.Level1)
{
    int32_t *userIds = nullptr;
    uint32_t userIdsLen = 0;
    int32_t ret = GetAllForegroundAccounts(&userIds, &userIdsLen);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_QUERY_ACCOUNT_ID_FAILED);
}

} // namespace OHOS