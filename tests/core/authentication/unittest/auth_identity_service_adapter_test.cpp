/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "auth_identity_service_adapter.c"
#include "auth_identity_service_adapter.h"
#include "auth_identity_service_adapter_mock.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
const uint32_t TEST_DATA_LEN = 64;
const char *TEST_CRED_LIST = "TestCredList";
int32_t g_ret = SOFTBUS_OK;

class AuthIdentityServiceAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthIdentityServiceAdapterTest::SetUpTestCase() { }

void AuthIdentityServiceAdapterTest::TearDownTestCase() { }

void AuthIdentityServiceAdapterTest::SetUp() { }

void AuthIdentityServiceAdapterTest::TearDown() { }

int32_t QueryCredentialByParams(int32_t osAccountId, const char *requestParams, char **returnData)
{
    (void)osAccountId;
    (void)requestParams;
    (void)returnData;
    AUTH_LOGI(AUTH_TEST, "QueryCredentialByParams test");
    return g_ret;
}

void DestroyInfo(char **returnData)
{
    (void)returnData;
    AUTH_LOGI(AUTH_TEST, "DestroyInfo test");
}

/*
 * @tc.name: ID_SERVICE_GENERATE_QUERY_PARAM_BY_CRED_TYPE_TEST_001
 * @tc.desc: cJSON_CreateObject fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, ID_SERVICE_GENERATE_QUERY_PARAM_BY_CRED_TYPE_TEST_001, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    SoftbusCredType credType = ACCOUNT_RELATED;
    AuthIdentityServiceAdapterInterfaceMock mock;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(nullptr));
    char *data = IdServiceGenerateQueryParamByCredType(peerUserId, udidHash, credType);
    EXPECT_EQ(data, nullptr);
}

/*
 * @tc.name: ID_SERVICE_GENERATE_QUERY_PARAM_BY_CRED_TYPE_TEST_002
 * @tc.desc: AddStringToJsonObject return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, ID_SERVICE_GENERATE_QUERY_PARAM_BY_CRED_TYPE_TEST_002, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    SoftbusCredType credType = ACCOUNT_RELATED;
    AuthIdentityServiceAdapterInterfaceMock mock;
    cJSON *msg = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    ASSERT_NE(msg, nullptr);
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillOnce(Return(false));
    EXPECT_CALL(mock, cJSON_Delete).WillRepeatedly(Return());
    char *data = IdServiceGenerateQueryParamByCredType(peerUserId, udidHash, credType);
    EXPECT_EQ(data, nullptr);
}

/*
 * @tc.name: ID_SERVICE_GENERATE_QUERY_PARAM_BY_CRED_TYPE_TEST_003
 * @tc.desc: IdServiceGenerateQueryParamByCredType fail with invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, ID_SERVICE_GENERATE_QUERY_PARAM_BY_CRED_TYPE_TEST_003, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    SoftbusCredType credType = ACCOUNT_RELATED;
    AuthIdentityServiceAdapterInterfaceMock mock;
    cJSON *msg = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    ASSERT_NE(msg, nullptr);
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(nullptr));
    EXPECT_CALL(mock, cJSON_Delete).WillRepeatedly(Return());
    char *data = IdServiceGenerateQueryParamByCredType(peerUserId, udidHash, credType);
    EXPECT_EQ(data, nullptr);
}

/*
 * @tc.name: ID_SERVICE_GENERATE_QUERY_PARAM_BY_CRED_TYPE_TEST_004
 * @tc.desc: cJSON_PrintUnformatted success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, ID_SERVICE_GENERATE_QUERY_PARAM_BY_CRED_TYPE_TEST_004, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    SoftbusCredType credType = ACCOUNT_RELATED;
    AuthIdentityServiceAdapterInterfaceMock mock;
    cJSON *msg = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    ASSERT_NE(msg, nullptr);
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    char *testData = (char *)SoftBusCalloc(TEST_DATA_LEN);
    if (testData == nullptr) {
        SoftBusFree(msg);
    }
    ASSERT_NE(testData, nullptr);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(testData));
    EXPECT_CALL(mock, cJSON_Delete).WillRepeatedly(Return());
    char *data = IdServiceGenerateQueryParamByCredType(peerUserId, udidHash, credType);
    EXPECT_NE(data, nullptr);
    SoftBusFree(data);
}

/*
 * @tc.name: IS_INVALID_CRED_LIST_TEST_001
 * @tc.desc: invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, IS_INVALID_CRED_LIST_TEST_001, TestSize.Level1)
{
    bool ret = IsInvalidCredList(nullptr);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IS_INVALID_CRED_LIST_TEST_002
 * @tc.desc: test IsInvalidCredList with invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, IS_INVALID_CRED_LIST_TEST_002, TestSize.Level1)
{
    AuthIdentityServiceAdapterInterfaceMock mock;
    EXPECT_CALL(mock, CreateJsonObjectFromString).WillOnce(Return(nullptr));
    bool ret = IsInvalidCredList(TEST_CRED_LIST);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IS_INVALID_CRED_LIST_TEST_003
 * @tc.desc: GetArrayItemNum return 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, IS_INVALID_CRED_LIST_TEST_003, TestSize.Level1)
{
    AuthIdentityServiceAdapterInterfaceMock mock;
    cJSON *credIdJson = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    ASSERT_NE(credIdJson, nullptr);
    EXPECT_CALL(mock, CreateJsonObjectFromString).WillOnce(Return(credIdJson));
    EXPECT_CALL(mock, GetArrayItemNum).WillOnce(Return(0));
    bool ret = IsInvalidCredList(TEST_CRED_LIST);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IS_INVALID_CRED_LIST_TEST_004
 * @tc.desc: GetArrayItemNum return 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, IS_INVALID_CRED_LIST_TEST_004, TestSize.Level1)
{
    AuthIdentityServiceAdapterInterfaceMock mock;
    cJSON *credIdJson = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    ASSERT_NE(credIdJson, nullptr);
    EXPECT_CALL(mock, CreateJsonObjectFromString).WillOnce(Return(credIdJson));
    EXPECT_CALL(mock, GetArrayItemNum).WillOnce(Return(1));
    bool ret = IsInvalidCredList(TEST_CRED_LIST);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_001
 * @tc.desc: invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_001, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN];
    bool isSameAccount = true;
    char *credList = nullptr;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    (void)memset_s(accountHash, SHA_256_HEX_HASH_LEN, 0, SHA_256_HEX_HASH_LEN);
    int32_t ret = AuthIdServiceQueryCredential(peerUserId, nullptr, accountHash, isSameAccount, &credList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthIdServiceQueryCredential(peerUserId, udidHash, nullptr, isSameAccount, &credList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthIdServiceQueryCredential(peerUserId, udidHash, accountHash, isSameAccount, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_002
 * @tc.desc: InitDeviceAuthService fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_002, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN];
    bool isSameAccount = true;
    char *credList = nullptr;
    AuthIdentityServiceAdapterInterfaceMock mock;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    (void)memset_s(accountHash, SHA_256_HEX_HASH_LEN, 0, SHA_256_HEX_HASH_LEN);
    EXPECT_CALL(mock, InitDeviceAuthService).WillOnce(Return(HC_ERROR));
    int32_t ret = AuthIdServiceQueryCredential(peerUserId, udidHash, accountHash, isSameAccount, &credList);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FAIL);
}

/*
 * @tc.name: AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_003
 * @tc.desc: GetCredMgrInstance return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_003, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN];
    bool isSameAccount = true;
    char *credList = nullptr;
    AuthIdentityServiceAdapterInterfaceMock mock;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    (void)memset_s(accountHash, SHA_256_HEX_HASH_LEN, 0, SHA_256_HEX_HASH_LEN);
    EXPECT_CALL(mock, InitDeviceAuthService).WillOnce(Return(HC_SUCCESS));
    EXPECT_CALL(mock, GetCredMgrInstance).WillOnce(Return(nullptr));
    int32_t ret = AuthIdServiceQueryCredential(peerUserId, udidHash, accountHash, isSameAccount, &credList);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FAIL);
}

/*
 * @tc.name: AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_004
 * @tc.desc: GetCredAuthInstance return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_004, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN];
    bool isSameAccount = true;
    char *credList = nullptr;
    AuthIdentityServiceAdapterInterfaceMock mock;
    CredManager *manager = (CredManager *)SoftBusCalloc(sizeof(CredManager));
    ASSERT_NE(manager, nullptr);
    manager->queryCredentialByParams = QueryCredentialByParams;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    (void)memset_s(accountHash, SHA_256_HEX_HASH_LEN, 0, SHA_256_HEX_HASH_LEN);
    EXPECT_CALL(mock, InitDeviceAuthService).WillOnce(Return(HC_SUCCESS));
    EXPECT_CALL(mock, GetCredMgrInstance).WillOnce(Return(manager));
    EXPECT_CALL(mock, JudgeDeviceTypeAndGetOsAccountIds).WillOnce(Return(0));
    cJSON *msg = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    if (msg == nullptr) {
        SoftBusFree(manager);
    }
    ASSERT_NE(msg, nullptr);
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    char *testData = (char *)SoftBusCalloc(TEST_DATA_LEN);
    if (testData == nullptr) {
        SoftBusFree(msg);
        SoftBusFree(manager);
    }
    ASSERT_NE(testData, nullptr);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(testData));
    EXPECT_CALL(mock, cJSON_Delete).WillRepeatedly(Return());
    int32_t ret = AuthIdServiceQueryCredential(peerUserId, udidHash, accountHash, isSameAccount, &credList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(manager);
}

/*
 * @tc.name: AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_005
 * @tc.desc: GetCredAuthInstance return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_005, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN];
    bool isSameAccount = false;
    AuthIdentityServiceAdapterInterfaceMock mock;
    CredManager *manager = (CredManager *)SoftBusCalloc(sizeof(CredManager));
    ASSERT_NE(manager, nullptr);
    cJSON *msg = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    cJSON *credId = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    char *testData = (char *)SoftBusCalloc(TEST_DATA_LEN);
    char *credList = (char *)SoftBusCalloc(TEST_DATA_LEN);
    if (msg == nullptr || credId == nullptr || testData == nullptr || credList == nullptr) {
        SoftBusFree(manager);
        SoftBusFree(msg);
        SoftBusFree(credId);
        SoftBusFree(testData);
        SoftBusFree(credList);
    }
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(credId, nullptr);
    ASSERT_NE(testData, nullptr);
    ASSERT_NE(credList, nullptr);
    manager->queryCredentialByParams = QueryCredentialByParams;
    manager->destroyInfo = DestroyInfo;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    (void)memset_s(accountHash, SHA_256_HEX_HASH_LEN, 0, SHA_256_HEX_HASH_LEN);
    EXPECT_CALL(mock, InitDeviceAuthService).WillRepeatedly(Return(HC_SUCCESS));
    EXPECT_CALL(mock, GetCredMgrInstance).WillRepeatedly(Return(manager));
    EXPECT_CALL(mock, JudgeDeviceTypeAndGetOsAccountIds).WillOnce(Return(0));
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(testData));
    EXPECT_CALL(mock, GetArrayItemNum).WillOnce(Return(1));
    EXPECT_CALL(mock, CreateJsonObjectFromString).WillOnce(Return(credId));
    EXPECT_CALL(mock, cJSON_Delete).WillRepeatedly(Return());
    int32_t ret = AuthIdServiceQueryCredential(peerUserId, udidHash, accountHash, isSameAccount, &credList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(credList);
    SoftBusFree(manager);
}

/*
 * @tc.name: AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_006
 * @tc.desc: GetCredAuthInstance return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_006, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN];
    bool isSameAccount = false;
    AuthIdentityServiceAdapterInterfaceMock mock;
    CredManager *manager = (CredManager *)SoftBusCalloc(sizeof(CredManager));
    ASSERT_NE(manager, nullptr);
    cJSON *msg = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    cJSON *msg1 = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    cJSON *credId = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    char *testData = (char *)SoftBusCalloc(TEST_DATA_LEN);
    char *testData1 = (char *)SoftBusCalloc(TEST_DATA_LEN);
    char *credList = (char *)SoftBusCalloc(TEST_DATA_LEN);
    if (msg == nullptr || msg1 == nullptr || credId == nullptr || testData == nullptr || testData1 == nullptr ||
        credList == nullptr) {
        SoftBusFree(manager);
        SoftBusFree(msg);
        SoftBusFree(msg1);
        SoftBusFree(credId);
        SoftBusFree(testData);
        SoftBusFree(testData1);
        SoftBusFree(credList);
    }
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(msg1, nullptr);
    ASSERT_NE(credId, nullptr);
    ASSERT_NE(testData, nullptr);
    ASSERT_NE(testData1, nullptr);
    ASSERT_NE(credList, nullptr);
    manager->queryCredentialByParams = QueryCredentialByParams;
    manager->destroyInfo = DestroyInfo;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    (void)memset_s(accountHash, SHA_256_HEX_HASH_LEN, 0, SHA_256_HEX_HASH_LEN);
    EXPECT_CALL(mock, InitDeviceAuthService).WillRepeatedly(Return(HC_SUCCESS));
    EXPECT_CALL(mock, GetCredMgrInstance).WillRepeatedly(Return(manager));
    EXPECT_CALL(mock, JudgeDeviceTypeAndGetOsAccountIds).WillOnce(Return(0));
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg)).WillOnce(Return(msg1));
    EXPECT_CALL(mock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(testData)).WillOnce(Return(testData1));
    EXPECT_CALL(mock, GetArrayItemNum).WillOnce(Return(0));
    EXPECT_CALL(mock, CreateJsonObjectFromString).WillOnce(Return(credId));
    EXPECT_CALL(mock, cJSON_Delete).WillRepeatedly(Return());
    int32_t ret = AuthIdServiceQueryCredential(peerUserId, udidHash, accountHash, isSameAccount, &credList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(credList);
    SoftBusFree(manager);
}

/*
 * @tc.name: AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_007
 * @tc.desc: GetCredMgrInstance return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_007, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN];
    bool isSameAccount = true;
    char *credList = nullptr;
    AuthIdentityServiceAdapterInterfaceMock mock;
    CredManager *manager = (CredManager *)SoftBusCalloc(sizeof(CredManager));
    ASSERT_NE(manager, nullptr);
    manager->queryCredentialByParams = QueryCredentialByParams;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    (void)memset_s(accountHash, SHA_256_HEX_HASH_LEN, 0, SHA_256_HEX_HASH_LEN);
    EXPECT_CALL(mock, InitDeviceAuthService).WillOnce(Return(HC_SUCCESS));
    EXPECT_CALL(mock, GetCredMgrInstance).WillOnce(Return(manager));
    EXPECT_CALL(mock, JudgeDeviceTypeAndGetOsAccountIds).WillOnce(Return(0));
    cJSON *msg = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    if (msg == nullptr) {
        SoftBusFree(manager);
    }
    ASSERT_NE(msg, nullptr);
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg));
    EXPECT_CALL(mock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    char *testData = (char *)SoftBusCalloc(TEST_DATA_LEN);
    if (testData == nullptr) {
        SoftBusFree(msg);
        SoftBusFree(manager);
    }
    ASSERT_NE(testData, nullptr);
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(testData));
    EXPECT_CALL(mock, GetSoftbusHichainAuthErrorCode).WillOnce(DoAll(SetArgPointee<1>(HC_ERROR), Return()));
    EXPECT_CALL(mock, cJSON_Delete).WillRepeatedly(Return());
    g_ret = HC_ERROR;
    int32_t ret = AuthIdServiceQueryCredential(peerUserId, udidHash, accountHash, isSameAccount, &credList);
    EXPECT_EQ(ret, HC_ERROR);
    SoftBusFree(manager);
}

/*
 * @tc.name: AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_008
 * @tc.desc: GetCredAuthInstance return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, AUTH_ID_SERVICE_QUERY_CREDENTIAL_TEST_008, TestSize.Level1)
{
    int32_t peerUserId = 0;
    char udidHash[UDID_HASH_LEN];
    char accountHash[SHA_256_HEX_HASH_LEN];
    bool isSameAccount = false;
    AuthIdentityServiceAdapterInterfaceMock mock;
    CredManager *manager = (CredManager *)SoftBusCalloc(sizeof(CredManager));
    ASSERT_NE(manager, nullptr);
    cJSON *msg = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    cJSON *msg1 = (cJSON *)SoftBusCalloc(sizeof(cJSON));
    char *testData = (char *)SoftBusCalloc(TEST_DATA_LEN);
    char *testData1 = (char *)SoftBusCalloc(TEST_DATA_LEN);
    char *credList = (char *)SoftBusCalloc(TEST_DATA_LEN);
    if (msg == nullptr || msg1 == nullptr || testData == nullptr || testData1 == nullptr || credList == nullptr) {
        SoftBusFree(manager);
        SoftBusFree(msg);
        SoftBusFree(msg1);
        SoftBusFree(testData);
        SoftBusFree(testData1);
        SoftBusFree(credList);
    }
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(msg1, nullptr);
    ASSERT_NE(testData, nullptr);
    ASSERT_NE(testData1, nullptr);
    ASSERT_NE(credList, nullptr);
    manager->queryCredentialByParams = QueryCredentialByParams;
    manager->destroyInfo = DestroyInfo;
    (void)memset_s(udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    (void)memset_s(accountHash, SHA_256_HEX_HASH_LEN, 0, SHA_256_HEX_HASH_LEN);
    EXPECT_CALL(mock, InitDeviceAuthService).WillRepeatedly(Return(HC_SUCCESS));
    EXPECT_CALL(mock, GetCredMgrInstance).WillRepeatedly(Return(manager));
    EXPECT_CALL(mock, JudgeDeviceTypeAndGetOsAccountIds).WillOnce(Return(0));
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(msg)).WillOnce(Return(msg1));
    EXPECT_CALL(mock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(testData)).WillOnce(Return(testData1));
    EXPECT_CALL(mock, cJSON_Delete).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetSoftbusHichainAuthErrorCode).WillOnce(DoAll(SetArgPointee<1>(HC_ERROR), Return()));
    int32_t ret = AuthIdServiceQueryCredential(peerUserId, udidHash, accountHash, isSameAccount, &credList);
    EXPECT_EQ(ret, HC_ERROR);
    SoftBusFree(credList);
    SoftBusFree(manager);
}

/*
 * @tc.name: ID_SERVICE_GENERATE_AUTH_PARAM_TEST_001
 * @tc.desc: hiChainParam is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthIdentityServiceAdapterTest, ID_SERVICE_GENERATE_AUTH_PARAM_TEST_001, TestSize.Level1)
{
    char *param = IdServiceGenerateAuthParam(nullptr);
    EXPECT_EQ(param, nullptr);
}
} // namespace OHOS
