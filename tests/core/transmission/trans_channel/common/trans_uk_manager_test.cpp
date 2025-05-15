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

#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "trans_lane_common_test_mock.h"
#include "trans_session_manager.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {

constexpr int32_t USER_ID = 100;

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

/**
 * @tc.name: UkManagerInit001
 * @tc.desc: UkManagerInit001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, UkManagerInit001, TestSize.Level1)
{
    int32_t ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransUkRequestMgrDeinit();
}

/**
 * @tc.name: UkRequestManagerTest001
 * @tc.desc: UkRequestManagerTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, UkRequestManagerTest001, TestSize.Level1)
{
    AuthACLInfo aclInfo;
    (void)memset_s(&aclInfo, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    UkRequestNode ukRequest;
    (void)memset_s(&ukRequest, sizeof(UkRequestNode), 0, sizeof(UkRequestNode));
    AuthHandle authHandle;
    (void)memset_s(&authHandle, sizeof(AuthHandle), 0, sizeof(AuthHandle));
    int32_t ret = TransUkRequestAddItem(0, 0, 0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransUkRequestGetRequestInfoByRequestId(0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = TransUkRequestAddItem(0, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: UkGetUkPolicyTest001
 * @tc.desc: UkGetUkPolicyTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, UkGetUkPolicyTest001, TestSize.Level1)
{
    AuthACLInfo aclInfo;
    (void)memset_s(&aclInfo, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));

    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    char sessionName[SESSION_NAME_SIZE_MAX] = "testSessionName";
    int32_t ret = GetUkPolicy(&appInfo);
    EXPECT_EQ(NO_NEED_UK, ret);

    SessionServer *sessionServer = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    EXPECT_TRUE(sessionServer != nullptr);
    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), sessionName);
    if (ret != EOK) {
        SoftBusFree(sessionServer);
        return;
    }
    sessionServer->pid = 0;
    sessionServer->accessInfo.userId = USER_ID;
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransSessionMgrDeinit();

    bool isSepicalSa = SpecialSaCanUseDeviceKey(0);
    EXPECT_EQ(false, isSepicalSa);

    bool isValidUk = IsValidUkInfo(nullptr);
    EXPECT_EQ(false, isValidUk);

    UkIdInfo ukIdInfo;
    (void)memset_s(&ukIdInfo, sizeof(UkIdInfo), 0, sizeof(UkIdInfo));
    ukIdInfo.myId = 1;
    ukIdInfo.peerId = 1;
    isValidUk = IsValidUkInfo(&ukIdInfo);
    EXPECT_EQ(true, isValidUk);

    FillHapSinkAclInfoToAppInfo(&appInfo);
}

/**
 * @tc.name: UkEncryptAndAddSinkSessionKeyTest001
 * @tc.desc: UkEncryptAndAddSinkSessionKeyTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, UkEncryptAndAddSinkSessionKeyTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    int ret = EncryptAndAddSinkSessionKey(nullptr, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    appInfo.channelCapability = 0x7;
    ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    appInfo.channelCapability = 0xF;
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthEncryptByUkId).WillRepeatedly(Return(SOFTBUS_ENCRYPT_ERR));
    ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);

    EXPECT_CALL(TransUkManagerMock, AuthEncryptByUkId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Encode).WillOnce(Return(-1));
    ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Encode).WillRepeatedly(Return(SOFTBUS_OK));
    ret = EncryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    cJSON_Delete(json);
}

/**
 * @tc.name: UkDecryptAndAddSinkSessionKeyTest001
 * @tc.desc: UkDecryptAndAddSinkSessionKeyTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, UkDecryptAndAddSinkSessionKeyTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);

    int ret = DecryptAndAddSinkSessionKey(nullptr, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    appInfo.channelCapability = 0x7;
    ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    appInfo.channelCapability = 0xF;
    ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    bool result = AddStringToJsonObject(json, "SESSION_KEY", (char *)"TestData");
    EXPECT_EQ(true, result);

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Decode).WillRepeatedly(Return(-1));
    ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    EXPECT_CALL(TransUkManagerMock, SoftBusBase64Decode).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUkManagerMock, AuthDecryptByUkId).WillRepeatedly(Return(SOFTBUS_DECRYPT_ERR));
    ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);

    EXPECT_CALL(TransUkManagerMock, AuthDecryptByUkId).WillRepeatedly(Return(SOFTBUS_OK));
    ret = DecryptAndAddSinkSessionKey(json, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: UkGetUserKeyIdByAclInfoTest001
 * @tc.desc: UkGetUserKeyIdByAclInfoTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, UkGetUserKeyIdByAclInfoTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    int32_t userKeyId;

    AuthGenUkCallback callBack = {
        .onGenSuccess = GenUkSuccess,
        .onGenFailed = GenUkFailed,
    };

    int ret = GetUserkeyIdByAClInfo(nullptr, 0, 0, &userKeyId, &callBack);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_NE(SOFTBUS_OK, ret);

    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransUkManagerTestInterfaceMock> TransUkManagerMock;
    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillOnce(Return(SOFTBUS_AUTH_UK_NOT_FIND));
    ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_NE(SOFTBUS_OK, ret);

    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_AUTH_UK_NOT_FIND));
    ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);

    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_AUTH_UK_NOT_FIND));
    EXPECT_CALL(TransUkManagerMock, AuthGenUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);

    EXPECT_CALL(TransUkManagerMock, AuthFindUkIdByAclInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetUserkeyIdByAClInfo(&appInfo, 0, 0, &userKeyId, &callBack);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransUkRequestMgrDeinit();
}
} // namespace OHOS