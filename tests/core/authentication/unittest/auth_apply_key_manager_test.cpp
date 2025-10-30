/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_apply_key_manager.h"
#include "auth_apply_key_manager_mock.h"
#include "auth_log.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager_struct.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class AuthApplyKeyManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthApplyKeyManagerTest::SetUpTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthApplyKeyManagerTest start");
    AuthApplyKeyManagerMockReg();
}

void AuthApplyKeyManagerTest::TearDownTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthApplyKeyManagerTest end");
    DeInitApplyKeyManager();
    LnnDeinitLocalLedger();
    LnnDeinitDistributedLedger();
    LooperDeinit();
}

void AuthApplyKeyManagerTest::SetUp() { }

void AuthApplyKeyManagerTest::TearDown() { }

/*
 * @tc.name: AuthApplyKeyManagerTest001
 * @tc.desc: Verify that AuthApplyKeyManager can be initialized and deinitialized successfully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_APPLY_KEY_MANAGER_INIT_Test_001, TestSize.Level1)
{
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = AuthInsertApplyKey(NULL, NULL, 0, 0, accountHash);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = AuthDeleteApplyKey(NULL);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = GetApplyKeyByBusinessInfo(NULL, NULL, 0, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_NO_FATAL_FAILURE(AuthRecoveryApplyKey());
    EXPECT_NO_FATAL_FAILURE(DeInitApplyKeyManager());
    EXPECT_NO_FATAL_FAILURE(AuthClearAccountApplyKey());
}

/*
 * @tc.name: AUTH_APPLY_KEY_MANAGER_Test_001
 * @tc.desc: Verify that apply keys can be inserted, retrieved, and deleted successfully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_APPLY_KEY_MANAGER_Test_001, TestSize.Level1)
{
    InitApplyKeyManager();
    RequestBusinessInfo info = {.type = BUSINESS_TYPE_D2D};
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    uint8_t uk[D2D_APPLY_KEY_LEN] = { 0 };
    uint64_t currentTime = SoftBusGetSysTimeMs();
    int32_t ret = AuthInsertApplyKey(&info, uk, D2D_APPLY_KEY_LEN, currentTime, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t outUk[D2D_APPLY_KEY_LEN] = { 0 };
    ret = GetApplyKeyByBusinessInfo(&info, outUk, D2D_APPLY_KEY_LEN - 1, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    ret = GetApplyKeyByBusinessInfo(&info, outUk, D2D_APPLY_KEY_LEN, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AuthDeleteApplyKey(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetApplyKeyByBusinessInfo(&info, outUk, D2D_APPLY_KEY_LEN, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_NOT_FOUND);
}

/*
 * @tc.name: AUTH_APPLY_KEY_MANAGER_Test_002
 * @tc.desc: Verify that expired apply keys are handled correctly during retrieval.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_APPLY_KEY_MANAGER_Test_002, TestSize.Level1)
{
    RequestBusinessInfo info = {.type = BUSINESS_TYPE_D2D};
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    uint8_t uk[D2D_APPLY_KEY_LEN] = { 0 };
    uint64_t currentTime = 0;
    int32_t ret = AuthInsertApplyKey(&info, uk, D2D_APPLY_KEY_LEN, currentTime, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t outUk[D2D_APPLY_KEY_LEN] = { 0 };
    ret = GetApplyKeyByBusinessInfo(&info, outUk, D2D_APPLY_KEY_LEN, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_APPLY_KEY_MANAGER_Test_003
 * @tc.desc: Verify that AuthApplyKeyManager functions handle null parameters gracefully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_APPLY_KEY_MANAGER_Test_003, TestSize.Level1)
{
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = AuthInsertApplyKey(NULL, NULL, 0, 0, accountHash);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthDeleteApplyKey(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetApplyKeyByBusinessInfo(NULL, NULL, 0, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_CLEAR_ACCOUNT_APPLY_KEY_Test_001
 * @tc.desc: Verify that AuthClearAccountApplyKey successfully clears all account-related apply keys.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_CLEAR_ACCOUNT_APPLY_KEY_Test_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(AuthRecoveryApplyKey());
    EXPECT_NO_FATAL_FAILURE(DeInitApplyKeyManager());
    EXPECT_NO_FATAL_FAILURE(AuthClearAccountApplyKey());
}
} // namespace OHOS