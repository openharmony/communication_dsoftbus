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

#include "auth_log.h"
#include "auth_uk_manager.h"
#include "auth_user_common_key.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"

#define OVERHEAD_LEN  28
#define UK_AGING_TIME (168 * 60 * 60 * 1000L)

namespace OHOS {
using namespace testing;
using namespace testing::ext;
constexpr char NODE1_UDID[] = "123456ABCDEF";
constexpr char NODE2_UDID[] = "123456ABCDEG";
constexpr char NODE1_ACCOUNT_ID[] = "123456ABCDEFACCOUNTID";
constexpr char NODE2_ACCOUNT_ID[] = "123456ABCDEGACCOUNTID";
constexpr int32_t TEST_DATA_LEN = 9;
constexpr char TEST_DATA[] = "testdata";

class AuthUkManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthUkManagerTest::SetUpTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthUkManagerTest start");
    int32_t ret = LooperInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnInitLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnInitDistributedLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void AuthUkManagerTest::TearDownTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthUkManagerTest end");
    DeinitUserKeyList();
    LnnDeinitDistributedLedger();
    LnnDeinitLocalLedger();
    LooperDeinit();
}

void AuthUkManagerTest::SetUp() { }

void AuthUkManagerTest::TearDown() { }

/*
 * @tc.name: AUTH_UK_MANAGER_Test_001
 * @tc.desc: AuthFindUkIdByAclInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_001, TestSize.Level1)
{
    AuthACLInfo aclInfo = { 0 };
    int32_t ukId;
    int32_t ret = AuthFindUkIdByAclInfo(nullptr, &ukId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthFindUkIdByAclInfo(&aclInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthFindUkIdByAclInfo(&aclInfo, &ukId);
    EXPECT_EQ(ret, SOFTBUS_AUTH_ACL_NOT_FOUND);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_002
 * @tc.desc: AuthGenUkIdByAclInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_002, TestSize.Level1)
{
    AuthACLInfo aclInfo = { 0 };
    uint32_t requestId = 1;
    AuthGenUkCallback genCb = { 0 };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    int32_t ret = AuthGenUkIdByAclInfo(nullptr, requestId, &genCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthGenUkIdByAclInfo(&aclInfo, requestId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthGenUkIdByAclInfo(&aclInfo, requestId, &genCb);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_003
 * @tc.desc: AuthGetUkEncryptSize test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_003, TestSize.Level1)
{
    uint32_t inLen = 1;
    uint32_t ret = AuthGetUkEncryptSize(inLen);
    EXPECT_EQ(ret, inLen + OVERHEAD_LEN);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_004
 * @tc.desc: AuthGetUkDecryptSize test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_004, TestSize.Level1)
{
    uint32_t inLen = OVERHEAD_LEN - 1;
    uint32_t ret = AuthGetUkDecryptSize(inLen);
    EXPECT_EQ(ret, inLen);
    inLen = OVERHEAD_LEN;
    ret = AuthGetUkDecryptSize(inLen);
    EXPECT_EQ(ret, inLen - OVERHEAD_LEN);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_005
 * @tc.desc: AuthEncryptByUkId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_005, TestSize.Level1)
{
    int32_t ukId = 0;
    uint8_t *inData = nullptr;
    inData = static_cast<uint8_t *>(SoftBusCalloc(TEST_DATA_LEN));
    ASSERT_TRUE(inData != nullptr);
    int32_t ret = memcpy_s(inData, TEST_DATA_LEN, TEST_DATA, sizeof(TEST_DATA));
    EXPECT_EQ(ret, EOK);
    uint32_t inLen = TEST_DATA_LEN;
    uint8_t outData[TEST_DATA_LEN + OVERHEAD_LEN - 1] = { 0 };
    uint32_t outLen = TEST_DATA_LEN + OVERHEAD_LEN - 1;
    ret = AuthEncryptByUkId(ukId, nullptr, inLen, outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthEncryptByUkId(ukId, inData, 0, outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthEncryptByUkId(ukId, inData, inLen, nullptr, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthEncryptByUkId(ukId, inData, inLen, outData, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthEncryptByUkId(ukId, inData, inLen, outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint8_t outData1[TEST_DATA_LEN + OVERHEAD_LEN] = { 0 };
    uint32_t outLen1 = TEST_DATA_LEN + OVERHEAD_LEN;
    ret = AuthEncryptByUkId(ukId, inData, inLen, outData1, &outLen1);
    EXPECT_EQ(ret, SOFTBUS_AUTH_ACL_NOT_FOUND);
    SoftBusFree(inData);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_006
 * @tc.desc: AuthDecryptByUkId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_006, TestSize.Level1)
{
    int32_t ukId = 1;
    uint8_t *inData = nullptr;
    inData = static_cast<uint8_t *>(SoftBusCalloc(TEST_DATA_LEN));
    ASSERT_TRUE(inData != nullptr);
    int32_t ret = memcpy_s(inData, TEST_DATA_LEN, TEST_DATA, sizeof(TEST_DATA));
    EXPECT_EQ(ret, EOK);
    uint32_t inLen = TEST_DATA_LEN;
    uint8_t outData[SESSION_KEY_LENGTH] = { 0 };
    uint32_t outLen = SESSION_KEY_LENGTH;
    ret = AuthDecryptByUkId(ukId, nullptr, inLen, outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthDecryptByUkId(ukId, inData, inLen, outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    inLen = OVERHEAD_LEN;
    ret = AuthDecryptByUkId(ukId, inData, inLen, nullptr, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthDecryptByUkId(ukId, inData, inLen, outData, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint8_t *inData1 = nullptr;
    inData1 = static_cast<uint8_t *>(SoftBusCalloc(inLen));
    ret = AuthDecryptByUkId(ukId, inData1, inLen, outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_AUTH_ACL_NOT_FOUND);
    SoftBusFree(inData);
    SoftBusFree(inData1);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_007
 * @tc.desc: GenUkSeq test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_007, TestSize.Level1)
{
    uint32_t ret = GenUkSeq();
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_008
 * @tc.desc: CompareByAllAcl test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_008, TestSize.Level1)
{
    AuthACLInfo oldAcl = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthACLInfo newAcl = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(newAcl.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    bool ret = CompareByAllAcl(&oldAcl, &newAcl, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAllAcl(&oldAcl, &newAcl, true);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_009
 * @tc.desc: CompareByAclDiffAccount test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_009, TestSize.Level1)
{
    AuthACLInfo oldAcl = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthACLInfo newAcl = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(newAcl.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    bool ret = CompareByAclDiffAccount(&oldAcl, &newAcl, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAclDiffAccount(&oldAcl, &newAcl, true);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_010
 * @tc.desc: CompareByAclSameAccount test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_010, TestSize.Level1)
{
    AuthACLInfo oldAcl = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthACLInfo newAcl = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(newAcl.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    bool ret = CompareByAclSameAccount(&oldAcl, &newAcl, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAclSameAccount(&oldAcl, &newAcl, true);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_011
 * @tc.desc: CompareByAllAcl test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_011, TestSize.Level1)
{
    AuthACLInfo oldAcl = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthACLInfo newAcl = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(newAcl.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    bool ret = CompareByAllAcl(&oldAcl, &newAcl, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAllAcl(&oldAcl, &newAcl, true);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_012
 * @tc.desc: AuthIsUkExpired test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_012, TestSize.Level1)
{
    bool ret = AuthIsUkExpired(0);
    EXPECT_EQ(ret, false);
    uint64_t currentTime = SoftBusGetSysTimeMs();
    ret = AuthIsUkExpired(currentTime - UK_AGING_TIME + 1);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_013
 * @tc.desc: UkNegotiateInit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_013, TestSize.Level1)
{
    int32_t ret = UkNegotiateInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_014
 * @tc.desc: UkNegotiateDeinit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_014, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UkNegotiateDeinit());
}

/*
 * @tc.name: AUTH_UK_MANAGER_Test_015
 * @tc.desc: UkNegotiateSessionInit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, AUTH_UK_MANAGER_Test_015, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UkNegotiateSessionInit());
}
} // namespace OHOS