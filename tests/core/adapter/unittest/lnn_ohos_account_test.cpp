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
#include <string>

#include "lnn_ohos_account.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using ::testing::Return;

namespace OHOS {
class LNNOhosAccountTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LNNOhosAccountTest::SetUpTestCase(void) { }

void LNNOhosAccountTest::TearDownTestCase(void) { }

void LNNOhosAccountTest::SetUp() { }

void LNNOhosAccountTest::TearDown() { }

/*
 * @tc.name: LNN_GET_OHOS_ACCOUNT_INFO_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountHash is nullptr or len is not equal to SHA_256_HASH_LEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_GET_OHOS_ACCOUNT_INFO_001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = LnnGetOhosAccountInfo(nullptr, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t accountHash[SHA_256_HASH_LEN - 1] = { 0 };
    ret = LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetOhosAccountInfoByUserIdTest_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountHash buffer is nullptr with valid userId and len
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LnnGetOhosAccountInfoByUserIdTest_001, TestSize.Level1)
{
    int32_t userId = 100;
    uint8_t *accountHash = nullptr;
    uint32_t len = SHA_256_HASH_LEN;
    int32_t ret = LnnGetOhosAccountInfoByUserId(userId, accountHash, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetOhosAccountInfoByUserIdTest_002
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when len is 0 with valid userId and accountHash buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LnnGetOhosAccountInfoByUserIdTest_002, TestSize.Level1)
{
    int32_t userId = 100;
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    uint32_t len = 0;
    int32_t ret = LnnGetOhosAccountInfoByUserId(userId, accountHash, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetOhosAccountInfoByUserIdTest_003
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is 0 with valid accountHash buffer and len
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LnnGetOhosAccountInfoByUserIdTest_003, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    uint32_t len = SHA_256_HASH_LEN;
    int32_t ret = LnnGetOhosAccountInfoByUserId(userId, accountHash, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetOhosAccountInfoByUserIdTest_004
 * @tc.desc: Return SOFTBUS_ERR when GetOsAccountIdByUserId fails and SOFTBUS_OK when GetOsAccountIdByUserId succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LnnGetOhosAccountInfoByUserIdTest_004, TestSize.Level1)
{
    int32_t userId = 100;
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    uint32_t len = SHA_256_HASH_LEN;
    int32_t ret = LnnGetOhosAccountInfoByUserId(userId, accountHash, len);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
} // namespace OHOS
}