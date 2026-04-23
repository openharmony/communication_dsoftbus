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
    int32_t ret = AuthInsertUserKey(&aclInfo, &userKeyInfo, false, DP_BIND_TYPE_DIFF_ACCOUNT);
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
    int32_t ret = AuthInsertUserKey(nullptr, &userKeyInfo, false, DP_BIND_TYPE_SAME_ACCOUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthInsertUserKey(&aclInfo, nullptr, false, DP_BIND_TYPE_SAME_ACCOUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthInsertUserKey(&aclInfo, &userKeyInfo, false, DP_BIND_TYPE_SAME_ACCOUNT);
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
    ret = AuthInsertUserKey(&aclInfo1, &userKeyInfo1, false, DP_BIND_TYPE_SAME_ACCOUNT);
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
    int32_t ret = AuthInsertUserKey(&aclInfo, &userKeyInfo1, false, DP_BIND_TYPE_SAME_ACCOUNT);
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
    int32_t ret = AuthInsertUserKey(&aclInfo, &userKeyInfo1, true, DP_BIND_TYPE_DIFF_ACCOUNT);
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

/*
 * @tc.name: AUTH_USER_KEY_INIT_MULTI_TEST_001
 * @tc.desc: Test multiple AuthUserKeyInit calls
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_INIT_MULTI_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeinitUserKeyList();
}

/*
 * @tc.name: DEL_USER_KEY_BY_NETWORKID_NULL_TEST_001
 * @tc.desc: Test DelUserKeyByNetworkId with null parameter
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, DEL_USER_KEY_BY_NETWORKID_NULL_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DelUserKeyByNetworkId(nullptr));
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    EXPECT_NO_FATAL_FAILURE(DelUserKeyByNetworkId(networkId));
    DeinitUserKeyList();
}

/*
 * @tc.name: AUTH_USER_KEY_DEINIT_MULTI_TEST_001
 * @tc.desc: Test multiple DeinitUserKeyList calls
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_DEINIT_MULTI_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DeinitUserKeyList());
    EXPECT_NO_FATAL_FAILURE(DeinitUserKeyList());
}

/*
 * @tc.name: AUTH_USER_KEY_INIT_DEINIT_CYCLE_TEST_001
 * @tc.desc: Test init and deinit cycle
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_INIT_DEINIT_CYCLE_TEST_001, TestSize.Level1)
{
    for (int i = 0; i < 3; i++) {
        int32_t ret = AuthUserKeyInit();
        EXPECT_EQ(ret, SOFTBUS_OK);
        DeinitUserKeyList();
    }
}

/*
 * @tc.name: GET_USER_KEY_BY_UKID_INVALID_LEN_TEST_001
 * @tc.desc: Test GetUserKeyByUkId with invalid length
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USER_KEY_BY_UKID_INVALID_LEN_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t uk[SESSION_KEY_LENGTH] = { 0 };
    uint32_t ukLen = SESSION_KEY_LENGTH + 1;
    ret = GetUserKeyByUkId(1, uk, ukLen);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}

/*
 * @tc.name: DEL_USER_KEY_BY_NETWORKID_VARIOUS_TEST_001
 * @tc.desc: Test DelUserKeyByNetworkId with various network IDs
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, DEL_USER_KEY_BY_NETWORKID_VARIOUS_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    char networkId1[NETWORK_ID_BUF_LEN] = "networkId1";
    char networkId2[NETWORK_ID_BUF_LEN] = "networkId2";
    char networkId3[NETWORK_ID_BUF_LEN] = "networkId3";
    EXPECT_NO_FATAL_FAILURE(DelUserKeyByNetworkId(networkId1));
    EXPECT_NO_FATAL_FAILURE(DelUserKeyByNetworkId(networkId2));
    EXPECT_NO_FATAL_FAILURE(DelUserKeyByNetworkId(networkId3));
    DeinitUserKeyList();
}

/*
 * @tc.name: AUTH_USER_KEY_GET_INFO_NOT_FOUND_TEST_001
 * @tc.desc: Test get user key info when key not found
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_GET_INFO_NOT_FOUND_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 100,
        .sourceUserId = 101,
        .sourceTokenId = 102,
        .sinkTokenId = 103,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoSameAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &(userKeyInfo));
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    ret = GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}

/*
 * @tc.name: GET_USER_KEY_BY_UKID_NOT_FOUND_TEST_001
 * @tc.desc: Test GetUserKeyByUkId when key not found
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USER_KEY_BY_UKID_NOT_FOUND_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t uk[SESSION_KEY_LENGTH] = { 0 };
    uint32_t ukLen = SESSION_KEY_LENGTH;
    int32_t testUkIds[] = {1, 10, 100, 1000};
    for (size_t i = 0; i < sizeof(testUkIds) / sizeof(testUkIds[0]); i++) {
        ret = GetUserKeyByUkId(testUkIds[i], uk, ukLen);
        EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    }
    DeinitUserKeyList();
}

/*
 * @tc.name: AUTH_USER_KEY_DEINIT_BEFORE_INIT_TEST_001
 * @tc.desc: Test DeinitUserKeyList before init
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_DEINIT_BEFORE_INIT_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DeinitUserKeyList());
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeinitUserKeyList();
}

/*
 * @tc.name: AUTH_USER_KEY_NULL_UDID_TEST_001
 * @tc.desc: Test user key functions with null UDID
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_NULL_UDID_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 200,
        .sourceUserId = 201,
        .sourceTokenId = 202,
        .sinkTokenId = 203,
    };
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoSameAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    ret = GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}

/*
 * @tc.name: AUTH_USER_KEY_SAME_USER_ID_TEST_001
 * @tc.desc: Test user key functions with same user ID
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_SAME_USER_ID_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 300,
        .sourceUserId = 300,
        .sourceTokenId = 302,
        .sinkTokenId = 303,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoSameAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}

/*
 * @tc.name: AUTH_USER_KEY_DIFF_USER_ID_TEST_001
 * @tc.desc: Test user key functions with different user ID
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_DIFF_USER_ID_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 400,
        .sourceUserId = 401,
        .sourceTokenId = 402,
        .sinkTokenId = 403,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    ret = GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}

/*
 * @tc.name: AUTH_USER_KEY_SERVER_MODE_TEST_001
 * @tc.desc: Test user key functions in server mode
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_SERVER_MODE_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = true,
        .sinkUserId = 500,
        .sourceUserId = 501,
        .sourceTokenId = 502,
        .sinkTokenId = 503,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    ret = GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}

/*
 * @tc.name: AUTH_USER_KEY_CLIENT_MODE_TEST_001
 * @tc.desc: Test user key functions in client mode
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, AUTH_USER_KEY_CLIENT_MODE_TEST_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 600,
        .sourceUserId = 601,
        .sourceTokenId = 602,
        .sinkTokenId = 603,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    ret = GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}
/*
 * @tc.name: GET_USERKEY_INFO_GROUP_SHARE_Test_001
 * @tc.desc: Test GetUserKeyInfoGroupShare via refactored GetUserKeyInfoByFilter
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USERKEY_INFO_GROUP_SHARE_Test_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 700,
        .sourceUserId = 701,
        .sourceTokenId = 702,
        .sinkTokenId = 703,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {};
    ret = GetUserKeyInfoGroupShare(nullptr, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetUserKeyInfoGroupShare(&aclInfo, &userKeyInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}

/*
 * @tc.name: GET_USERKEY_INFO_GROUP_SHARE_Test_002
 * @tc.desc: Test GetUserKeyInfoGroupShare inserts and retrieves share key
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USERKEY_INFO_GROUP_SHARE_Test_002, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 800,
        .sourceUserId = 801,
        .sourceTokenId = 802,
        .sinkTokenId = 803,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {
        .keyLen = SESSION_KEY_LENGTH,
        .time = 54321,
        .keyIndex = 10,
    };
    ret = AuthInsertUserKey(&aclInfo, &userKeyInfo, true, DP_BIND_TYPE_SHARE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthUserKeyInfo resultInfo = {};
    ret = GetUserKeyInfoGroupShare(&aclInfo, &resultInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(resultInfo.keyIndex, 10);
    DeinitUserKeyList();
}

/*
 * @tc.name: GET_USERKEY_INFO_SAME_ACCOUNT_REFINED_Test_001
 * @tc.desc: Test refactored GetUserKeyInfoSameAccount via FilterSameAccount
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USERKEY_INFO_SAME_ACCOUNT_REFINED_Test_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 900,
        .sourceUserId = 901,
        .sourceTokenId = 902,
        .sinkTokenId = 903,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {
        .keyLen = SESSION_KEY_LENGTH,
        .time = 99999,
        .keyIndex = 20,
    };
    ret = AuthInsertUserKey(&aclInfo, &userKeyInfo, false, DP_BIND_TYPE_DIFF_ACCOUNT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthUserKeyInfo resultInfo = {};
    ret = GetUserKeyInfoSameAccount(&aclInfo, &resultInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}

/*
 * @tc.name: GET_USERKEY_INFO_DIFF_ACCOUNT_REFINED_Test_001
 * @tc.desc: Test refactored GetUserKeyInfoDiffAccount rejects non-diff-account bind type
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyTest, GET_USERKEY_INFO_DIFF_ACCOUNT_REFINED_Test_001, TestSize.Level1)
{
    int32_t ret = AuthUserKeyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthACLInfo aclInfo = {
        .isServer = false,
        .sinkUserId = 910,
        .sourceUserId = 911,
        .sourceTokenId = 912,
        .sinkTokenId = 913,
    };
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, NODE2_UDID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, NODE1_ACCOUNT_ID));
    EXPECT_EQ(EOK, strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, NODE2_ACCOUNT_ID));
    AuthUserKeyInfo userKeyInfo = {
        .keyLen = SESSION_KEY_LENGTH,
        .time = 77777,
        .keyIndex = 30,
    };
    ret = AuthInsertUserKey(&aclInfo, &userKeyInfo, false, DP_BIND_TYPE_SAME_ACCOUNT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthUserKeyInfo resultInfo = {};
    ret = GetUserKeyInfoDiffAccount(&aclInfo, &resultInfo);
    EXPECT_EQ(ret, SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND);
    DeinitUserKeyList();
}
} // namespace OHOS