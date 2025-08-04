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
#include "auth_uk_manager.c"
#include "auth_uk_manager.h"
#include "auth_user_common_key.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
constexpr char NODE1_UDID[] = "123456ABCDEF";
constexpr char NODE2_UDID[] = "123456ABCDEG";
constexpr char NODE1_ACCOUNT_ID[] = "123456ABCDEFACCOUNTID";
constexpr char NODE2_ACCOUNT_ID[] = "123456ABCDEGACCOUNTID";
constexpr int32_t TEST_DATA_LEN = 9;
constexpr char TEST_DATA[] = "testdata";
constexpr uint64_t UK_DECAY_TIME = 15552000000;

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
 * @tc.name: COMPARE_BY_ALL_ACL_Test_001
 * @tc.desc: CompareByAllAcl test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, COMPARE_BY_ALL_ACL_Test_001, TestSize.Level1)
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
 * @tc.name: COMPARE_BY_ACL_DIFF_ACCOUNT_WITH_USERKEY_Test_001
 * @tc.desc: CompareByAclDiffAccountWithUserLevel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, COMPARE_BY_ACL_DIFF_ACCOUNT_WITH_USERKEY_Test_001, TestSize.Level1)
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
    bool ret = CompareByAclDiffAccountWithUserLevel(&oldAcl, &newAcl, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAclDiffAccount(nullptr, nullptr, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAclDiffAccount(&oldAcl, nullptr, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAclDiffAccountWithUserLevel(&oldAcl, &newAcl, true);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: COMPARE_BY_ACL_DIFF_ACCOUNT_Test_001
 * @tc.desc: CompareByAclDiffAccount test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, COMPARE_BY_ACL_DIFF_ACCOUNT_Test_001, TestSize.Level1)
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
 * @tc.name: COMPARE_BY_ACL_SAME_ACCOUNT_Test_001
 * @tc.desc: CompareByAclSameAccount test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, COMPARE_BY_ACL_SAME_ACCOUNT_Test_001, TestSize.Level1)
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
    ret = CompareByAclSameAccount(nullptr, nullptr, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAclSameAccount(&oldAcl, nullptr, false);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(EOK, strcpy_s(oldAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(newAcl.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
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
    ret = CompareByAllAcl(nullptr, nullptr, false);
    EXPECT_EQ(ret, false);
    ret = CompareByAllAcl(&oldAcl, nullptr, false);
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
HWTEST_F(AuthUkManagerTest, AUTH_IS_UK_EXPIRED_Test_001, TestSize.Level1)
{
    bool ret = AuthIsUkExpired(0);
    EXPECT_EQ(ret, false);
    uint64_t currentTime = SoftBusGetSysTimeMs();
    ret = AuthIsUkExpired(currentTime - UK_DECAY_TIME + 1);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: UK_NEGOTIATE_INIT_Test_001
 * @tc.desc: UkNegotiateInit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, UK_NEGOTIATE_INIT_Test_001, TestSize.Level1)
{
    int32_t ret = UkNegotiateInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: UK_NEGOTIATE_DEINIT_Test_001
 * @tc.desc: UkNegotiateDeinit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, UK_NEGOTIATE_DEINIT_Test_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UkNegotiateDeinit());
}

/*
 * @tc.name: UK_NEGOTIATE_SESSION_INIT_Test_001
 * @tc.desc: UkNegotiateSessionInit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, UK_NEGOTIATE_SESSION_INIT_Test_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UkNegotiateSessionInit());
}

/*
 * @tc.name: GET_SHORT_UDID_HASH_Test_001
 * @tc.desc: GetShortUdidHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, GET_SHORT_UDID_HASH_Test_001, TestSize.Level1)
{
    char udid[SHA_256_HEX_HASH_LEN] = {0};
    char udidHash[SHA_256_HEX_HASH_LEN] = {0};
    uint32_t len = 0;

    int32_t ret = GetShortUdidHash(nullptr, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetShortUdidHash(nullptr, nullptr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetShortUdidHash(nullptr, udidHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetShortUdidHash(udid, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    (void)strcpy_s(udid, SHA_256_HEX_HASH_LEN, "0123456789ABCDEFG");
    ret = GetShortUdidHash(udid, udidHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_UK_NEGO_AUTH_PARAM_INFO_Test_001
 * @tc.desc: GetUkNegoAuthParamInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, GET_UK_NEGO_AUTH_PARAM_INFO_Test_001, TestSize.Level1)
{
    HiChainAuthParam authParam;
    AuthACLInfo info;

    (void)memset_s(&authParam, sizeof(HiChainAuthParam), 0, sizeof(HiChainAuthParam));
    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    int32_t ret = GetUkNegoAuthParamInfo(nullptr, HICHAIN_AUTH_DEVICE, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetUkNegoAuthParamInfo(&info, HICHAIN_AUTH_DEVICE, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetUkNegoAuthParamInfo(nullptr, HICHAIN_AUTH_DEVICE, &authParam);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetUkNegoAuthParamInfo(&info, HICHAIN_AUTH_DEVICE, &authParam);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
}

/*
 * @tc.name: UK_MSG_HANDLER_Test_001
 * @tc.desc: UkMsgHandler test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, UK_MSG_HANDLER_Test_001, TestSize.Level1)
{
    int32_t channelId = 0;
    uint32_t requestId = 0;
    AuthDataHead head;

    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    int32_t ret = UkMsgHandler(channelId, requestId, nullptr, nullptr, TEST_DATA_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UkMsgHandler(channelId, requestId, nullptr, TEST_DATA, TEST_DATA_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UkMsgHandler(channelId, requestId, &head, nullptr, TEST_DATA_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    head.dataType = DATA_TYPE_DEVICE_ID;
    ret = UkMsgHandler(channelId, requestId, &head, TEST_DATA, TEST_DATA_LEN);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
    head.dataType = DATA_TYPE_AUTH;
    ret = UkMsgHandler(channelId, requestId, &head, TEST_DATA, TEST_DATA_LEN);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    head.dataType = DATA_TYPE_CLOSE_ACK;
    ret = UkMsgHandler(channelId, requestId, &head, TEST_DATA, TEST_DATA_LEN);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    head.dataType = DATA_TYPE_DECRYPT_FAIL;
    ret = UkMsgHandler(channelId, requestId, &head, TEST_DATA, TEST_DATA_LEN);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_HANDLE_DATA_FAIL);
}

static void OnGenSuccessTest(uint32_t requestId, int32_t ukId)
{
    AUTH_LOGI(AUTH_CONN, "OnGenSuccessTest called");
    (void)requestId;
    (void)ukId;
}

static void OnGenFailedTest(uint32_t requestId, int32_t reason)
{
    AUTH_LOGI(AUTH_CONN, "OnGenFailedTest called");
    (void)requestId;
    (void)reason;
}

/*
 * @tc.name: CREATE_UK_NEGOTIATE_INSTANCE_Test_001
 * @tc.desc: CreateUkNegotiateInstance test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, CREATE_UK_NEGOTIATE_INSTANCE_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    uint32_t channelId = 0;
    AuthACLInfo info;
    UkNegotiateInstance instance;
    AuthGenUkCallback genCb = {
        .onGenSuccess = OnGenSuccessTest,
        .onGenFailed = OnGenFailedTest,
    };

    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = CreateUkNegotiateInstance(requestId, channelId, &info, &genCb);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = InitUkNegoInstanceList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CreateUkNegotiateInstance(requestId, channelId, &info, &genCb);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = UkNegotiateInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CreateUkNegotiateInstance(requestId, channelId, &info, &genCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateUkNegotiateInfo(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeleteUkNegotiateInstance(requestId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: PACK_UK_ACL_PARAM_Test_001
 * @tc.desc: PackUkAclParam test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, PACK_UK_ACL_PARAM_Test_001, TestSize.Level1)
{
    AuthACLInfo info;
    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    char *data = PackUkAclParam(&info, true);
    EXPECT_NE(data, nullptr);
    int32_t ret = UnpackUkAclParam(data, sizeof(AuthACLInfo), &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

static int32_t CreateUkNegotiateInstanceInner(void)
{
    EXPECT_EQ(UkNegotiateInit(), SOFTBUS_OK);
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    uint32_t requestId = 1;
    uint32_t channelId = 1;
    AuthACLInfo info = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(info.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(info.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthGenUkCallback genCb = {
        .onGenSuccess = OnGenSuccessTest,
        .onGenFailed = OnGenFailedTest,
    };
    return CreateUkNegotiateInstance(requestId, channelId, &info, &genCb);
}

/*
 * @tc.name: GET_GEN_UK_INSTANCE_BY_CHANNEL_Test_001
 * @tc.desc: GetGenUkInstanceByChannel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, GET_GEN_UK_INSTANCE_BY_CHANNEL_Test_001, TestSize.Level1)
{
    int32_t channelId = 0;
    uint32_t requestId = 1;
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByChannel(channelId, &instance);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = GetGenUkInstanceByChannel(channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    ret = GetGenUkInstanceByChannel(channelId, &instance);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    EXPECT_EQ(UkNegotiateInit(), SOFTBUS_OK);
    ret = GetGenUkInstanceByChannel(channelId, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UK_INSTANCE_NOT_FIND);
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    channelId = 1;
    ret = GetGenUkInstanceByChannel(channelId, &instance);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeleteUkNegotiateInstance(requestId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: GET_SAME_UK_INSTANCE_NUM_Test_001
 * @tc.desc: GetSameUkInstanceNum test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, GET_SAME_UK_INSTANCE_NUM_Test_001, TestSize.Level1)
{
    AuthACLInfo info = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(info.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(info.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    uint32_t ret = GetSameUkInstanceNum(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    ret = GetSameUkInstanceNum(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(UkNegotiateInit(), SOFTBUS_OK);
    uint32_t requestId = 1;
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    ret = GetSameUkInstanceNum(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeleteUkNegotiateInstance(requestId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: GET_GEN_UK_INSTANCE_BY_REQ_Test_001
 * @tc.desc: GetGenUkInstanceByReq test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, GET_GEN_UK_INSTANCE_BY_REQ_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    ret = GetGenUkInstanceByReq(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    EXPECT_EQ(UkNegotiateInit(), SOFTBUS_OK);
    ret = GetGenUkInstanceByReq(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UK_INSTANCE_NOT_FIND);
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    requestId = 1;
    ret = GetGenUkInstanceByReq(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const uint8_t *data = reinterpret_cast<const uint8_t *>("123456");
    uint32_t len = strlen("123456");
    bool res = OnTransmitted(requestId, data, len);
    EXPECT_EQ(res, false);
    res = OnTransmitted(requestId, nullptr, len);
    EXPECT_EQ(res, false);
    DeleteUkNegotiateInstance(requestId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: GET_UK_NEGOTIATE_INFO_Test_001
 * @tc.desc: GetUkNegotiateInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, GET_UK_NEGOTIATE_INFO_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    UkNegotiateInfo *info = GetUkNegotiateInfo(requestId);
    EXPECT_EQ(info, nullptr);
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    info = GetUkNegotiateInfo(requestId);
    EXPECT_EQ(info, nullptr);
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    requestId = 1;
    info = GetUkNegotiateInfo(requestId);
    EXPECT_NE(info, nullptr);
}

/*
 * @tc.name: UPDATE_UK_NEGOTIATE_INFO_Test_001
 * @tc.desc: UpdateUkNegotiateInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, UPDATE_UK_NEGOTIATE_INFO_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    UkNegotiateInstance instance = { 0 };
    EXPECT_NO_FATAL_FAILURE(DeleteUkNegotiateInstance(requestId));
    int32_t ret = UpdateUkNegotiateInfo(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_ACL_SET_CHANNEL_FAIL);
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DeleteUkNegotiateInstance(requestId));
    ret = UpdateUkNegotiateInfo(requestId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateUkNegotiateInfo(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_ACL_SET_CHANNEL_FAIL);
    EXPECT_EQ(UkNegotiateInit(), SOFTBUS_OK);
    ret = UpdateUkNegotiateInfo(requestId, &instance);
    EXPECT_EQ(ret, SOFTBUS_AUTH_ACL_SET_CHANNEL_FAIL);
}
/*
 * @tc.name: ASYNC_CALL_GEN_UK_RESULT_RECEIVED_Test_001
 * @tc.desc: AsyncCallGenUkResultReceived test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, ASYNC_CALL_GEN_UK_RESULT_RECEIVED_Test_001, TestSize.Level1)
{
    SyncGenUkResult *res = (SyncGenUkResult*)SoftBusMalloc(sizeof(SyncGenUkResult));
    ASSERT_TRUE(res != nullptr);
    res->requestId = 0;
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(AsyncCallGenUkResultReceived(nullptr));
    EXPECT_NO_FATAL_FAILURE(AsyncCallGenUkResultReceived(reinterpret_cast<void *>(res)));
    SyncGenUkResult *res1 = (SyncGenUkResult*)SoftBusMalloc(sizeof(SyncGenUkResult));
    ASSERT_TRUE(res1 != nullptr);
    res1->requestId = 1;
    res1->isGenUkSuccess = true;
    EXPECT_NO_FATAL_FAILURE(AsyncCallGenUkResultReceived(reinterpret_cast<void *>(res1)));
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    SyncGenUkResult *res2 = (SyncGenUkResult*)SoftBusMalloc(sizeof(SyncGenUkResult));
    ASSERT_TRUE(res2 != nullptr);
    res2->requestId = 1;
    res2->isGenUkSuccess = false;
    EXPECT_NO_FATAL_FAILURE(AsyncCallGenUkResultReceived(reinterpret_cast<void *>(res2)));
    DeleteUkNegotiateInstance(res2->requestId = 1);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: UPDATE_ALL_GEN_CB_CALLBACK_Test_001
 * @tc.desc: UpdateAllGenCbCallback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, UPDATE_ALL_GEN_CB_CALLBACK_Test_001, TestSize.Level1)
{
    AuthACLInfo info = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(info.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(info.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    bool isSuccess = true;
    int32_t reason = SOFTBUS_AUTH_UK_INSTANCE_NOT_FIND;
    EXPECT_NO_FATAL_FAILURE(UpdateAllGenCbCallback(&info, isSuccess, reason, 0));
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(UpdateAllGenCbCallback(&info, isSuccess, reason, 0));
    EXPECT_EQ(UkNegotiateInit(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(UpdateAllGenCbCallback(&info, isSuccess, reason, 0));
    uint32_t requestId = 1;
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(UpdateAllGenCbCallback(&info, isSuccess, reason, 0));
    EXPECT_NO_FATAL_FAILURE(OnGenSuccess(reason));
    DeleteUkNegotiateInstance(requestId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: JUDGE_IS_SAME_ACCOUNT_Test_001
 * @tc.desc: JudgeIsSameAccount test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, JUDGE_IS_SAME_ACCOUNT_Test_001, TestSize.Level1)
{
    char accountHashStr[SHA_256_HEX_HASH_LEN] = { 0 };
    bool isSameAccount = JudgeIsSameAccount(accountHashStr);
    EXPECT_EQ(isSameAccount, true);
}

/*
 * @tc.name: GET_CRED_ID_BY_ID_SERVICE_Test_001
 * @tc.desc: GetCredIdByIdService test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, GET_CRED_ID_BY_ID_SERVICE_Test_001, TestSize.Level1)
{
    const char *localUdidHash = "5fec";
    const char *remoteUdidHash = "5fec";
    const char *accountHash = "accountTest";
    int32_t userId = 100;
    char *ptr = GetCredIdByIdService(const_cast<char *>(localUdidHash),
        const_cast<char *>(remoteUdidHash), const_cast<char *>(accountHash), userId);
    EXPECT_EQ(ptr, nullptr);
}

/*
 * @tc.name: GENERATE_AUTH_PARAM_Test_001
 * @tc.desc: GenerateAuthParam test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, GENERATE_AUTH_PARAM_Test_001, TestSize.Level1)
{
    NodeInfo localNodeInfo;
    (void)memset_s(&localNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(strcpy_s(localNodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID), EOK);
    NodeInfo remoteNodeInfo;
    (void)memset_s(&remoteNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(strcpy_s(remoteNodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE2_UDID), EOK);
    AuthACLInfo info = { 0 };
    info.sinkUserId = 1;
    info.isServer = true;
    EXPECT_EQ(EOK, strcpy_s(info.sinkUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    HiChainAuthMode authMode = HICHAIN_AUTH_IDENTITY_SERVICE;
    HiChainAuthParam authParam;
    (void)memset_s(&authParam, sizeof(HiChainAuthParam), 0, sizeof(HiChainAuthParam));
    int32_t ret = GenerateAuthParam(nullptr, &remoteNodeInfo, &info, authMode, &authParam);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GenerateAuthParam(&localNodeInfo, nullptr, &info, authMode, &authParam);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GenerateAuthParam(&localNodeInfo, &remoteNodeInfo, nullptr, authMode, &authParam);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GenerateAuthParam(&localNodeInfo, &remoteNodeInfo, &info, authMode, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GenerateAuthParam(&localNodeInfo, &remoteNodeInfo, &info, authMode, &authParam);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_ID_FAIL);
    authMode = HICHAIN_AUTH_DEVICE;
    ret = GenerateAuthParam(&localNodeInfo, &remoteNodeInfo, &info, authMode, &authParam);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_SESSION_KEY_RETURNED_Test_001
 * @tc.desc: OnSessionKeyReturned test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, ON_SESSION_KEY_RETURNED_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    const uint8_t *sessionKey = reinterpret_cast<const uint8_t *>("123456789");
    uint32_t sessionKeyLen = strlen("123456789");
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(requestId, nullptr, sessionKeyLen));
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(requestId, sessionKey, SESSION_KEY_LENGTH + 1));
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(requestId, sessionKey, sessionKeyLen));
    requestId = 1;
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyReturned(requestId, sessionKey, sessionKeyLen));
    DeleteUkNegotiateInstance(requestId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: ON_FINISHED_Test_001
 * @tc.desc: OnFinished test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, ON_FINISHED_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    int32_t operationCode = 1;
    const char *returnData = "returnData";
    EXPECT_NO_FATAL_FAILURE(OnFinished(requestId, operationCode, returnData));
    requestId = 1;
    EXPECT_NO_FATAL_FAILURE(OnFinished(requestId, operationCode, returnData));
    DeleteUkNegotiateInstance(requestId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: ON_ERROR_Test_001
 * @tc.desc: OnError test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, ON_ERROR_Test_001, TestSize.Level1)
{
    uint32_t authSeq = 0;
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    int32_t operationCode = 1;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    const char *errorReturn = "errorReturn";
    EXPECT_NO_FATAL_FAILURE(OnError(authSeq, operationCode, errCode, errorReturn));
    authSeq = 1;
    EXPECT_NO_FATAL_FAILURE(OnError(authSeq, operationCode, errCode, errorReturn));
    DeleteUkNegotiateInstance(authSeq);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: JSON_OBJECT_PACK_AUTH_BASE_INFO_Test_001
 * @tc.desc: JsonObjectPackAuthBaseInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, JSON_OBJECT_PACK_AUTH_BASE_INFO_Test_001, TestSize.Level1)
{
    UkNegotiateInstance instance = { 0 };
    instance.info.isServer = true;
    instance.info.sinkUserId = 1;
    EXPECT_EQ(EOK, strcpy_s(instance.info.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(instance.info.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    cJSON json;
    (void)memset_s(&json, sizeof(cJSON), 0, sizeof(cJSON));
    int32_t ret = JsonObjectPackAuthBaseInfo(&instance, &json);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_REQUEST_Test_001
 * @tc.desc: OnRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, ON_REQUEST_Test_001, TestSize.Level1)
{
    uint32_t authSeq = 0;
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    int32_t operationCode = 1;
    const char *reqParams = "reqParams";
    char *ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);
    authSeq = 1;
    ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);
    DeleteUkNegotiateInstance(authSeq);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: PROCESS_AUTH_HICHAIN_PARAM_Test_001
 * @tc.desc: ProcessAuthHichainParam test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, PROCESS_AUTH_HICHAIN_PARAM_Test_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    AuthACLInfo info = { 0 };
    HiChainAuthMode authMode = HICHAIN_AUTH_DEVICE;
    int32_t ret = ProcessAuthHichainParam(requestId, &info, authMode);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
}

/*
 * @tc.name: SEND_UK_NEGO_DEVICEID_Test_001
 * @tc.desc: SendUkNegoDeviceId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, SEND_UK_NEGO_DEVICEID_Test_001, TestSize.Level1)
{
    UkNegotiateInstance instance = { 0 };
    int32_t ret = SendUkNegoDeviceId(&instance);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: PROCESS_UK_NEGO_STATE_Test_001
 * @tc.desc: ProcessUkNegoState test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, PROCESS_UK_NEGO_STATE_Test_001, TestSize.Level1)
{
    AuthACLInfo info = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(info.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    bool isGreater = false;
    int32_t ret = ProcessUkNegoState(&info, &isGreater);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PROCESS_UK_DEVICE_ID_Test_001
 * @tc.desc: ProcessUkDeviceId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, PROCESS_UK_DEVICE_ID_Test_001, TestSize.Level1)
{
    AuthACLInfo info;
    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    char *data = PackUkAclParam(&info, true);
    EXPECT_NE(data, nullptr);
    int32_t channelId = 1;
    uint32_t requestId = 0;
    uint32_t dataLen = strlen(data);
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    int32_t ret = ProcessUkDeviceId(channelId, requestId, data, dataLen);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    requestId = 1;
    ret = ProcessUkDeviceId(channelId, requestId, data, dataLen);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    DeleteUkNegotiateInstance(requestId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: SEND_UK_NEGO_CLOSE_ACK_EVENT_Test_001
 * @tc.desc: SendUkNegoCloseAckEvent test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, SEND_UK_NEGO_CLOSE_ACK_EVENT_Test_001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t requestId = 1;
    int32_t ret = SendUkNegoCloseAckEvent(channelId, requestId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: PROCESS_CLOSE_ACK_DATA_Test_001
 * @tc.desc: ProcessCloseAckData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, PROCESS_CLOSE_ACK_DATA_Test_001, TestSize.Level1)
{
    const uint8_t *data = reinterpret_cast<const uint8_t *>("123456789");
    uint32_t dataLen = strlen("123456789");
    uint32_t requestId = 1;
    int32_t ret = ProcessCloseAckData(requestId, data, dataLen);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    ret = ProcessCloseAckData(requestId, data, dataLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SECURITY_ON_SESSION_OPENED_Test_001
 * @tc.desc: SecurityOnSessionOpened test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, SECURITY_ON_SESSION_OPENED_Test_001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    const char *peerNetworkId = "peerNetworkId";
    int32_t result = SOFTBUS_INVALID_PARAM;
    int32_t ret = SecurityOnSessionOpened(channelId, channelType, const_cast<char *>(peerNetworkId), result);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    result = SOFTBUS_OK;
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    ret = SecurityOnSessionOpened(channelId, channelType, const_cast<char *>(peerNetworkId), result);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
    DeleteUkNegotiateInstance(channelId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: SECURITY_ON_SESSION_CLOSED_Test_001
 * @tc.desc: SecurityOnSessionClosed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, SECURITY_ON_SESSION_CLOSED_Test_001, TestSize.Level1)
{
    int32_t channelId = 1;
    EXPECT_NO_FATAL_FAILURE(SecurityOnSessionClosed(channelId));
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(SecurityOnSessionClosed(channelId));
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}

/*
 * @tc.name: SECURITY_ON_BYTES_RECEIVED_Test_001
 * @tc.desc: SecurityOnBytesReceived test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, SECURITY_ON_BYTES_RECEIVED_Test_001, TestSize.Level1)
{
    const uint8_t *data = reinterpret_cast<const uint8_t *>("123456789");
    uint32_t len = strlen("123456789");
    AuthDataHead head = {
        .dataType = DATA_TYPE_AUTH,
        .module = MODULE_HICHAIN,
        .seq = 1,
        .flag = 0,
        .len = len,
    };
    uint32_t size = AUTH_PKT_HEAD_LEN + len;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    ASSERT_TRUE(buf != nullptr);
    int32_t ret = PackAuthData(&head, data, buf, size);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = 1;
    uint32_t dataLen = size;
    EXPECT_NO_FATAL_FAILURE(SecurityOnBytesReceived(channelId, buf, dataLen));
    SoftBusFree(buf);
}

/*
 * @tc.name: SECURITY_SET_CHANNEL_INFO_BY_REQ_ID_Test_001
 * @tc.desc: SecuritySetChannelInfoByReqId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUkManagerTest, SECURITY_SET_CHANNEL_INFO_BY_REQ_ID_Test_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    int32_t channelId = 1;
    int32_t channelType = 1;
    int32_t ret = SecuritySetChannelInfoByReqId(requestId, channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_EQ(CreateUkNegotiateInstanceInner(), SOFTBUS_OK);
    ret = SecuritySetChannelInfoByReqId(requestId, channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeleteUkNegotiateInstance(channelId);
    DeInitUkNegoInstanceList();
    UkNegotiateDeinit();
}
} // namespace OHOS
