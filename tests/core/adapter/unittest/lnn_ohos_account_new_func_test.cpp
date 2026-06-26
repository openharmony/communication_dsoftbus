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

#include "lnn_ohos_account.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNOhosAccountNewFuncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNOhosAccountNewFuncTest::SetUpTestCase() { }

void LNNOhosAccountNewFuncTest::TearDownTestCase() { }

void LNNOhosAccountNewFuncTest::SetUp() { }

void LNNOhosAccountNewFuncTest::TearDown() { }

/*
 * @tc.name: LnnGetAccountIdByUserId_Test_001
 * @tc.desc: Test LnnGetAccountIdByUserId with null accountId returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountNewFuncTest, LnnGetAccountIdByUserId_Test_001, TestSize.Level1)
{
    int32_t userId = 100;
    int64_t *accountId = nullptr;
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = LnnGetAccountIdByUserId(userId, accountId, accountHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetAccountIdByUserId_Test_002
 * @tc.desc: Test LnnGetAccountIdByUserId with null accountHash returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountNewFuncTest, LnnGetAccountIdByUserId_Test_002, TestSize.Level1)
{
    int32_t userId = 100;
    int64_t accountId = 0;
    uint8_t *accountHash = nullptr;
    int32_t ret = LnnGetAccountIdByUserId(userId, &accountId, accountHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetAccountIdByUserId_Test_003
 * @tc.desc: Test LnnGetAccountIdByUserId with invalid len returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountNewFuncTest, LnnGetAccountIdByUserId_Test_003, TestSize.Level1)
{
    int32_t userId = 100;
    int64_t accountId = 0;
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = LnnGetAccountIdByUserId(userId, &accountId, accountHash, SHA_256_HASH_LEN - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetAccountIdByUserId_Test_004
 * @tc.desc: Test LnnGetAccountIdByUserId with userId <= 0 returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountNewFuncTest, LnnGetAccountIdByUserId_Test_004, TestSize.Level1)
{
    int32_t userId = -1;
    int64_t accountId = 0;
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = LnnGetAccountIdByUserId(userId, &accountId, accountHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetAccountIdByUserId_Test_005
 * @tc.desc: Test LnnGetAccountIdByUserId with valid params (returns MEM_ERR in mock)
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountNewFuncTest, LnnGetAccountIdByUserId_Test_005, TestSize.Level1)
{
    int32_t userId = 100;
    int64_t accountId = 0;
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = LnnGetAccountIdByUserId(userId, &accountId, accountHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
}

} // namespace OHOS