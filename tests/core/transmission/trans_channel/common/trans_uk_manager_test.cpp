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

#include "gtest/gtest.h"
#include <securec.h>

#include "trans_uk_manager.h"
#include "trans_uk_manager_test_mock.h"

#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "trans_lane_common_test_mock.h"
#include "trans_session_manager.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {

class TransUkManagerTest : public testing::Test {
public:
    TransUkManagerTest() { }
    ~TransUkManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransUkManagerTest::SetUpTestCase(void) { }

void TransUkManagerTest::TearDownTestCase(void) { }

static void GenUkSuccess(uint32_t requestId, int32_t ukId)
{
    (void)requestId;
    (void)ukId;
}

static void GenUkFailed(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
}

/*
 * @tc.name: TransUkRequestMgrInitTest001
 * @tc.desc: TransUkRequestMgrInit returns OK on first init and supports reinit after deinit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestMgrInitTest001, TestSize.Level1)
{
    int32_t ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransUkRequestMgrDeinit();
    ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransUkRequestMgrDeinit();
}

/*
 * @tc.name: TransUkRequestAddItemTest001
 * @tc.desc: TransUkRequestAddItem returns NO_INIT when manager is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestAddItemTest001, TestSize.Level1)
{
    TransUkRequestMgrDeinit();
    int32_t ret = TransUkRequestAddItem(0, 0, 0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransUkRequestAddItem(100, 1, 1);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransUkRequestAddItemTest002
 * @tc.desc: TransUkRequestAddItem returns OK when manager is initialized and item is added.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestAddItemTest002, TestSize.Level1)
{
    int32_t ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUkRequestAddItem(0, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransUkRequestDeleteItem(0);
    TransUkRequestMgrDeinit();
}

/*
 * @tc.name: TransUkRequestGetRequestInfoByRequestIdTest001
 * @tc.desc: Returns INVALID_PARAM for null ukRequest and NO_INIT when not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestGetRequestInfoByRequestIdTest001, TestSize.Level1)
{
    TransUkRequestMgrDeinit();
    UkRequestNode ukRequest;
    (void)memset_s(&ukRequest, sizeof(UkRequestNode), 0, sizeof(UkRequestNode));
    int32_t ret = TransUkRequestGetRequestInfoByRequestId(0, nullptr);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransUkRequestGetRequestInfoByRequestIdTest002
 * @tc.desc: TransUkRequestGetRequestInfoByRequestId returns NOT_FIND when requestId not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestGetRequestInfoByRequestIdTest002, TestSize.Level1)
{
    int32_t ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    UkRequestNode ukRequest;
    (void)memset_s(&ukRequest, sizeof(UkRequestNode), 0, sizeof(UkRequestNode));
    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    TransUkRequestMgrDeinit();
}

/*
 * @tc.name: TransUkRequestGetRequestInfoByRequestIdTest003
 * @tc.desc: TransUkRequestGetRequestInfoByRequestId returns OK when requestId is found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestGetRequestInfoByRequestIdTest003, TestSize.Level1)
{
    int32_t ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUkRequestAddItem(0, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UkRequestNode ukRequest;
    (void)memset_s(&ukRequest, sizeof(UkRequestNode), 0, sizeof(UkRequestNode));
    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransUkRequestDeleteItem(0);
    TransUkRequestMgrDeinit();
}

/*
 * @tc.name: TransUkRequestDeleteItemTest001
 * @tc.desc: TransUkRequestDeleteItem returns NO_INIT when manager is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestDeleteItemTest001, TestSize.Level1)
{
    TransUkRequestMgrDeinit();
    int32_t ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransUkRequestDeleteItem(1);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransUkRequestDeleteItemTest002
 * @tc.desc: TransUkRequestDeleteItem returns NOT_FIND when requestId is not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestDeleteItemTest002, TestSize.Level1)
{
    int32_t ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    TransUkRequestMgrDeinit();
}

/*
 * @tc.name: TransUkRequestDeleteItemTest003
 * @tc.desc: TransUkRequestDeleteItem returns OK when requestId is found and deleted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, TransUkRequestDeleteItemTest003, TestSize.Level1)
{
    int32_t ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUkRequestAddItem(0, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransUkRequestMgrDeinit();
}

/*
 * @tc.name: GetUkPolicyTest001
 * @tc.desc: GetUkPolicy returns INVALID_PARAM for null input and NO_NEED_UK when peer does not support UK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetUkPolicyTest001, TestSize.Level1)
{
    int32_t ret = GetUkPolicy(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetUkPolicy(&appInfo);
    EXPECT_EQ(NO_NEED_UK, ret);
}

/*
 * @tc.name: IsValidUkInfoTest001
 * @tc.desc: IsValidUkInfo returns false for null input and true for valid ukIdInfo with both IDs set.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, IsValidUkInfoTest001, TestSize.Level1)
{
    bool isValidUk = IsValidUkInfo(nullptr);
    EXPECT_FALSE(isValidUk);
    UkIdInfo ukIdInfo;
    (void)memset_s(&ukIdInfo, sizeof(UkIdInfo), 0, sizeof(UkIdInfo));
    ukIdInfo.myId = 1;
    ukIdInfo.peerId = 1;
    isValidUk = IsValidUkInfo(&ukIdInfo);
    EXPECT_TRUE(isValidUk);
}

/*
 * @tc.name: GetLocalAccountUidByUserIdTest001
 * @tc.desc: GetLocalAccountUidByUserId returns INVALID_PARAM for null id or null len pointer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetLocalAccountUidByUserIdTest001, TestSize.Level0)
{
    uint32_t idLen = 20;
    uint32_t len = 0;
    int32_t userId = 1;
    char id[20] = "";
    int32_t result = GetLocalAccountUidByUserId(nullptr, idLen, &len, userId);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
    result = GetLocalAccountUidByUserId(id, idLen, nullptr, userId);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetLocalAccountUidByUserIdTest002
 * @tc.desc: GetLocalAccountUidByUserId returns OK when LnnGetLocalStrInfo succeeds.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetLocalAccountUidByUserIdTest002, TestSize.Level0)
{
    TransLaneCommonTestInterfaceMock mock;
    char mockUid[] = "local_uid";
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillOnce(DoAll(
            SetArrayArgument<1>(mockUid, mockUid + strlen(mockUid) + 1),
            Return(SOFTBUS_OK)));
    uint32_t len = 10;
    char id[10] = {0};
    int32_t result = GetLocalAccountUidByUserId(id, sizeof(id), &len, 1);
    EXPECT_EQ(result, SOFTBUS_OK);
    EXPECT_STREQ(id, "local_uid");
    EXPECT_EQ(len, strlen("local_uid"));
}

/*
 * @tc.name: GetLocalAccountUidByUserIdTest003
 * @tc.desc: GetLocalAccountUidByUserId returns INVALID_PARAM when LnnGetLocalStrInfo returns STRCPY_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetLocalAccountUidByUserIdTest003, TestSize.Level0)
{
    uint32_t len = 10;
    int32_t userId = 1;
    char id[10] = "test";
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_STRCPY_ERR));
    int32_t result = GetLocalAccountUidByUserId(id, len, &len, userId);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetLocalAccountUidByUserIdTest004
 * @tc.desc: GetLocalAccountUidByUserId returns INVALID_PARAM when LnnGetLocalStrInfo returns NETWORK_NOT_FOUND
 *          and id buffer is too short for default uid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetLocalAccountUidByUserIdTest004, TestSize.Level1)
{
    const uint32_t shortLen = 5;
    char shortId[shortLen] = {0};
    uint32_t outLen = 0;
    int32_t testUserId = 1001;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    int32_t ret = GetLocalAccountUidByUserId(shortId, shortLen, &outLen, testUserId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(outLen, 0u);
}

/*
 * @tc.name: GetLocalAccountUidByUserIdTest005
 * @tc.desc: GetLocalAccountUidByUserId returns OK and ensures null termination when LnnGetLocalStrInfo fails
 *          with pre-filled id buffer of sufficient length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetLocalAccountUidByUserIdTest005, TestSize.Level1)
{
    const uint32_t testLen = 20;
    char badId[testLen] = { 0 };
    (void)memset_s(badId, testLen, 'a', testLen - 1);
    uint32_t outLen = 0;
    int32_t testUserId = 1002;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    int32_t ret = GetLocalAccountUidByUserId(badId, testLen, &outLen, testUserId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(badId[testLen - 1], '\0');
}

/*
 * @tc.name: FillHapSinkAclInfoToAppInfoTest001
 * @tc.desc: FillHapSinkAclInfoToAppInfo does not crash for null input and fills acl info for valid HAP.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, FillHapSinkAclInfoToAppInfoTest001, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(FillHapSinkAclInfoToAppInfo(nullptr));
    AppInfo *appInfo = new AppInfo();
    appInfo->myData.tokenType = ACCESS_TOKEN_TYPE_HAP;
    (void)strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), "test_session");
    (void)strcpy_s(appInfo->myData.accountId, sizeof(appInfo->myData.accountId), "test_account");
    appInfo->myData.userId = 1001;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, TransGetAclInfoBySessionName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(FillHapSinkAclInfoToAppInfo(appInfo));
    delete appInfo;
}

/*
 * @tc.name: FillHapSinkAclInfoToAppInfoTest002
 * @tc.desc: FillHapSinkAclInfoToAppInfo does not crash for valid HAP when TransGetAclInfoBySessionName fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, FillHapSinkAclInfoToAppInfoTest002, TestSize.Level0)
{
    AppInfo *appInfo = new AppInfo();
    appInfo->myData.tokenType = ACCESS_TOKEN_TYPE_HAP;
    (void)strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), "test_session");
    (void)strcpy_s(appInfo->myData.accountId, sizeof(appInfo->myData.accountId), "test_account");
    appInfo->myData.userId = 1001;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, TransGetAclInfoBySessionName).WillOnce(Return(SOFTBUS_NO_INIT));
    EXPECT_NO_FATAL_FAILURE(FillHapSinkAclInfoToAppInfo(appInfo));
    delete appInfo;
}

/*
 * @tc.name: EncryptAndAddSinkSessionKeyTest001
 * @tc.desc: EncryptAndAddSinkSessionKey returns INVALID_PARAM for null msg or null appInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, EncryptAndAddSinkSessionKeyTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = EncryptAndAddSinkSessionKey(nullptr, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    ret = EncryptAndAddSinkSessionKey(json, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: EncryptAndAddSinkSessionKeyTest002
 * @tc.desc: EncryptAndAddSinkSessionKey returns OK when channel capability is zero.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, EncryptAndAddSinkSessionKeyTest002, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int32_t ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: EncryptAndAddSinkSessionKeyTest003
 * @tc.desc: EncryptAndAddSinkSessionKey returns OK with 0x7 capability (generate key without encrypt).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, EncryptAndAddSinkSessionKeyTest003, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0x7;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Encode).WillRepeatedly(Return(SOFTBUS_OK));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int32_t ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: EncryptAndAddSinkSessionKeyTest004
 * @tc.desc: EncryptAndAddSinkSessionKey returns ENCRYPT_ERR with 0xF capability when AuthEncryptByUkId fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, EncryptAndAddSinkSessionKeyTest004, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthEncryptByUkId).WillRepeatedly(Return(SOFTBUS_ENCRYPT_ERR));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int32_t ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: EncryptAndAddSinkSessionKeyTest005
 * @tc.desc: EncryptAndAddSinkSessionKey returns CREATE_JSON_ERR with 0xF capability when SoftBusBase64Encode
 *          fails after successful encryption.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, EncryptAndAddSinkSessionKeyTest005, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthEncryptByUkId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Encode).WillRepeatedly(Return(-1));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int32_t ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: EncryptAndAddSinkSessionKeyTest006
 * @tc.desc: EncryptAndAddSinkSessionKey returns OK with 0xF capability when encrypt and base64 encode succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, EncryptAndAddSinkSessionKeyTest006, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthEncryptByUkId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Encode).WillRepeatedly(Return(SOFTBUS_OK));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int32_t ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest001
 * @tc.desc: DecryptAndAddSinkSessionKey returns INVALID_PARAM for null msg or null appInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = DecryptAndAddSinkSessionKey(nullptr, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    ret = DecryptAndAddSinkSessionKey(json, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest002
 * @tc.desc: DecryptAndAddSinkSessionKey returns OK when channel capability is zero.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest002, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int32_t ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest003
 * @tc.desc: DecryptAndAddSinkSessionKey returns OK with 0x7 capability (generate key without encrypt).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest003, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0x7;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Decode).WillRepeatedly(Return(SOFTBUS_OK));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int32_t ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest004
 * @tc.desc: DecryptAndAddSinkSessionKey returns PARSE_JSON_ERR with 0xF capability when SESSION_KEY is missing.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest004, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Decode).WillRepeatedly(Return(SOFTBUS_OK));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int32_t ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest005
 * @tc.desc: DecryptAndAddSinkSessionKey returns not OK with 0xF capability when LnnGetLocalStrInfo fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest005, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    bool result = AddStringToJsonObject(json, "SESSION_KEY", const_cast<char *>("TestData"));
    EXPECT_TRUE(result);
    int32_t ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest006
 * @tc.desc: DecryptAndAddSinkSessionKey returns not OK with 0xF capability when AuthFindUkIdByAclInfo
 *          returns UK_NOT_FIND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest006, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    bool result = AddStringToJsonObject(json, "SESSION_KEY", const_cast<char *>("TestData"));
    EXPECT_TRUE(result);
    int32_t ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest007
 * @tc.desc: DecryptAndAddSinkSessionKey returns PARSE_JSON_ERR with 0xF capability when SoftBusBase64Decode
 *          fails after successful ACL fill and UK find.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest007, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Decode).WillRepeatedly(Return(-1));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    bool result = AddStringToJsonObject(json, "SESSION_KEY", const_cast<char *>("TestData"));
    EXPECT_TRUE(result);
    int32_t ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest008
 * @tc.desc: DecryptAndAddSinkSessionKey returns DECRYPT_ERR with 0xF capability when AuthDecryptByUkId fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest008, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Decode).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, AuthDecryptByUkId).WillRepeatedly(Return(SOFTBUS_DECRYPT_ERR));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    bool result = AddStringToJsonObject(json, "SESSION_KEY", const_cast<char *>("TestData"));
    EXPECT_TRUE(result);
    int32_t ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: DecryptAndAddSinkSessionKeyTest009
 * @tc.desc: DecryptAndAddSinkSessionKey returns OK with 0xF capability when decrypt and base64 decode succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, DecryptAndAddSinkSessionKeyTest009, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Decode).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, AuthDecryptByUkId).WillRepeatedly(Return(SOFTBUS_OK));
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    bool result = AddStringToJsonObject(json, "SESSION_KEY", const_cast<char *>("TestData"));
    EXPECT_TRUE(result);
    int32_t ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: GetUserkeyIdByAClInfoTest001
 * @tc.desc: GetUserkeyIdByAClInfo returns INVALID_PARAM for null appInfo, null userKeyId, or null callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetUserkeyIdByAClInfoTest001, TestSize.Level1)
{
    int32_t userKeyId;
    AuthGenUkCallback callBack = {
        .onGenSuccess = GenUkSuccess,
        .onGenFailed = GenUkFailed,
    };
    int32_t ret = GetUserkeyIdByAClInfo(nullptr, 0, 0, &userKeyId, &callBack);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, nullptr, &callBack);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: GetUserkeyIdByAClInfoTest002
 * @tc.desc: GetUserkeyIdByAClInfo returns not OK when LnnGetRemoteStrInfo fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetUserkeyIdByAClInfoTest002, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t userKeyId;
    AuthGenUkCallback callBack = {
        .onGenSuccess = GenUkSuccess,
        .onGenFailed = GenUkFailed,
    };
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    int32_t ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetUserkeyIdByAClInfoTest003
 * @tc.desc: GetUserkeyIdByAClInfo returns not OK when AuthFindUkIdByAclInfo returns UK_NOT_FIND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetUserkeyIdByAClInfoTest003, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t userKeyId;
    AuthGenUkCallback callBack = {
        .onGenSuccess = GenUkSuccess,
        .onGenFailed = GenUkFailed,
    };
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillOnce(Return(SOFTBUS_AUTH_UK_NOT_FIND));
    int32_t ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetUserkeyIdByAClInfoTest004
 * @tc.desc: GetUserkeyIdByAClInfo returns AUTH_ACL_NOT_FOUND when AuthFindUkIdByAclInfo returns ACL_NOT_FOUND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetUserkeyIdByAClInfoTest004, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t userKeyId;
    AuthGenUkCallback callBack = {
        .onGenSuccess = GenUkSuccess,
        .onGenFailed = GenUkFailed,
    };
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_AUTH_ACL_NOT_FOUND));
    int32_t ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_EQ(SOFTBUS_AUTH_ACL_NOT_FOUND, ret);
}

/*
 * @tc.name: GetUserkeyIdByAClInfoTest005
 * @tc.desc: GetUserkeyIdByAClInfo returns not OK when UK not found but gen requested (async UK generation).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetUserkeyIdByAClInfoTest005, TestSize.Level1)
{
    int32_t ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t userKeyId;
    AuthGenUkCallback callBack = {
        .onGenSuccess = GenUkSuccess,
        .onGenFailed = GenUkFailed,
    };
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_AUTH_UK_NOT_FIND));
    EXPECT_CALL(TransUkManagerMock, AuthGenUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransUkRequestMgrDeinit();
}

/*
 * @tc.name: GetUserkeyIdByAClInfoTest006
 * @tc.desc: GetUserkeyIdByAClInfo returns OK when AuthFindUkIdByAclInfo finds a valid UK ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, GetUserkeyIdByAClInfoTest006, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t userKeyId;
    AuthGenUkCallback callBack = {
        .onGenSuccess = GenUkSuccess,
        .onGenFailed = GenUkFailed,
    };
    NiceMock<TransLaneCommonTestInterfaceMock> transLaneCommonMock;
    EXPECT_CALL(transLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
