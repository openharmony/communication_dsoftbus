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

#include "auth_uk_manager.h"
#include "auth_user_common_key.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
constexpr char NODE1_UDID[] = "123456ABCDEF";
constexpr char NODE2_UDID[] = "123456ABCDEG";
constexpr char NODE1_ACCOUNT_ID[] = "123456ABCDEFACCOUNTID";
constexpr char NODE2_ACCOUNT_ID[] = "123456ABCDEGACCOUNTID";

class AuthUserCommonKeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthUserCommonKeyTest::SetUpTestCase() { }

void AuthUserCommonKeyTest::TearDownTestCase() { }

void AuthUserCommonKeyTest::SetUp() { }

void AuthUserCommonKeyTest::TearDown() { }

/*
 * @tc.name: AUTH_USER_COMMON_KEY_Test_001
 * @tc.desc: Test user key functions before initialization.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_COMMON_KEY_Test_001, TestSize.Level1)
{
    AuthACLInfo aclInfo = {};
    AuthUserKeyInfo userKeyInfo = {};
    int32_t ret = AuthInsertUserKey(&aclInfo, &userKeyInfo, false);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = GetUserKeyInfoSameAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    int32_t sessionKeyId = 3;
    uint32_t ukLen = SESSION_KEY_LENGTH;
    uint8_t uk[SESSION_KEY_LENGTH] = { 0 };
    ret = GetUserKeyByUkId(sessionKeyId, uk, ukLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UTH_USER_COMMON_KEY_Test_002
 * @tc.desc: AuthUserKeyInit test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, UTH_USER_COMMON_KEY_Test_002, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeinitUserKeyList();
}

/*
 * @tc.name: UTH_USER_COMMON_KEY_Test_003
 * @tc.desc: AuthInsertUserKey test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, UTH_USER_COMMON_KEY_Test_003, TestSize.Level1)
{
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {
        .keyLen = strlen("testKey"),
        .time = 12345,
        .keyIndex = 1,
    };
    EXPECT_EQ(EOK, memcpy_s(userKeyInfo.deviceKey, SESSION_KEY_LENGTH, "testKey", strlen("testKey")));
    int32_t ret = AuthInsertUserKey(nullptr, &userKeyInfo, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthInsertUserKey(&aclInfo, nullptr, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthInsertUserKey(&aclInfo, &userKeyInfo, false);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo1 = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo1.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo1.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo1.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo1.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo1 = {
        .keyLen = strlen("testKey1"),
        .time = 12345,
        .keyIndex = 2,
    };
    EXPECT_EQ(EOK, memcpy_s(userKeyInfo1.deviceKey, SESSION_KEY_LENGTH, "testKey1", strlen("testKey1")));
    ret = AuthInsertUserKey(&aclInfo1, &userKeyInfo1, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_USERKEY_INFO_SAME_ACCOUNT_Test_001
 * @tc.desc: GetUserKeyInfoSameAccount test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USERKEY_INFO_SAME_ACCOUNT_Test_001, TestSize.Level1)
{
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 2,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo1 = {
        .keyLen = strlen("testKey1"),
        .time = 12345,
        .keyIndex = 1,
    };
    int32_t ret = AuthInsertUserKey(&aclInfo, &userKeyInfo1, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoSameAccount(nullptr, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    aclInfo.sinkUserId = 1;
    ret = GetUserKeyInfoSameAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    aclInfo.sinkUserId = 2;
    ret = GetUserKeyInfoSameAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_USERKEY_INFO_DIFF_ACCOUNT_Test_001
 * @tc.desc: GetUserKeyInfoDiffAccount test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USERKEY_INFO_DIFF_ACCOUNT_Test_001, TestSize.Level1)
{
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 1,
        .sourceUserId = 2,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {};
    int32_t ret = GetUserKeyInfoDiffAccount(nullptr, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    aclInfo.isServer = true;
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    aclInfo.isServer = false;
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_USERKEY_INFO_DIFF_ACCOUNT_WITH_USER_Test_001
 * @tc.desc: GetUserKeyInfoDiffAccountWithUserLevel test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USERKEY_INFO_DIFF_ACCOUNT_WITH_USER_Test_001, TestSize.Level1)
{
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 10,
        .sourceUserId = 10,
        .sourceTokenId = 3,
        .sinkTokenId = 4,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo1 = {
        .keyLen = strlen("testKey1"),
        .time = 12345,
        .keyIndex = 5,
    };
    int32_t ret = AuthInsertUserKey(&aclInfo, &userKeyInfo1, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    aclInfo.isServer = true;
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoDiffAccountWithUserLevel(nullptr, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    aclInfo.isServer = false;
    ret = GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_USERKEY_BY_UKID_Test_001
 * @tc.desc: GetUserKeyByUkId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USERKEY_BY_UKID_Test_001, TestSize.Level1)
{
    int32_t sessionKeyId = 3;
    uint32_t ukLen = SESSION_KEY_LENGTH;
    uint8_t uk[SESSION_KEY_LENGTH] = { 0 };
    int32_t ret = GetUserKeyByUkId(sessionKeyId, uk, ukLen);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    sessionKeyId = 2;
    ukLen = 1;
    ret = GetUserKeyByUkId(sessionKeyId, uk, ukLen);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    ukLen = strlen("testKey1");
    ret = GetUserKeyByUkId(sessionKeyId, uk, ukLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeinitUserKeyList();
}

/*
 * @tc.name: DEL_USERKEY_BY_NETWORKID_Test_001
 * @tc.desc: DelUserKeyByNetworkId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, DEL_USERKEY_BY_NETWORKID_Test_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DelUserKeyByNetworkId(nullptr));
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    char peerNetworkId[NETWORK_ID_BUF_LEN] = {};
    EXPECT_NO_FATAL_FAILURE(DelUserKeyByNetworkId(peerNetworkId));
}

/*
 * @tc.name: DEINIT_USERKEY_LIST_Test_001
 * @tc.desc: DeinitUserKeyList test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, DEINIT_USERKEY_LIST_Test_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DeinitUserKeyList());
}
} // namespace OHOS