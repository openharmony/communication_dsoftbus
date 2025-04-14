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

#include "softbus_adapter_mem.h"
#include "trans_lane_common_test_mock.h"
#include "trans_session_manager.h"
#include "trans_uk_manager.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {

constexpr char UDID_TEST[UDID_BUF_LEN] = "testudid";
constexpr int32_t USER_ID = 100;
constexpr int32_t INVALID_USER_ID = 100;
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
    int32_t channelId = 0;
    int32_t ret = TransUkRequestAddItem(0, 0, 0, 0, nullptr);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUkRequestGetTcpInfoByRequestId(0, &aclInfo, &channelId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUkRequestSetAuthHandleAndSeq(0, &authHandle, 0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUkRequestMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransUkRequestGetTcpInfoByRequestId(0, nullptr, &channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransUkRequestGetRequestInfoByRequestId(0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransUkRequestSetAuthHandleAndSeq(0, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransUkRequestGetTcpInfoByRequestId(0, &aclInfo, &channelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = TransUkRequestSetAuthHandleAndSeq(0, &authHandle, 0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = TransUkRequestAddItem(0, 0, 0, 0, &aclInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransUkRequestGetTcpInfoByRequestId(0, &aclInfo, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransUkRequestGetRequestInfoByRequestId(0, &ukRequest);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransUkRequestSetAuthHandleAndSeq(0, &authHandle, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransUkRequestDeleteItem(0);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransUkRequestMgrDeinit();
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

    char sourceUdid[UDID_BUF_LEN];
    char sindUdid[UDID_BUF_LEN];
    ret = GetSourceAndSinkUdid(nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSourceAndSinkUdid(UDID_TEST, sourceUdid, sindUdid);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = FillSinkAclInfo(nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = FillSinkAclInfo(sessionName, &aclInfo, nullptr);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

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

    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = FillSinkAclInfo(sessionName, &aclInfo, nullptr);
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
}

/**
 * @tc.name: UkPackRequestTest001
 * @tc.desc: UkPackRequestTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, UkPackRequestTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    char *requestStr = PackUkRequest(nullptr);
    EXPECT_EQ(nullptr, requestStr);

    appInfo.myData.userId = INVALID_USER_ID;
    requestStr = PackUkRequest(&appInfo);
    EXPECT_TRUE(requestStr != nullptr);

    appInfo.myData.userId = USER_ID;
    requestStr = PackUkRequest(&appInfo);
    EXPECT_TRUE(requestStr != nullptr);

    cJSON *validJson = cJSON_Parse(requestStr);
    ASSERT_NE(validJson, nullptr);

    cJSON *errJson = cJSON_CreateObject();
    ASSERT_NE(errJson, nullptr);

    AuthACLInfo aclInfo;
    (void)memset_s(&aclInfo, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));

    char sessionName[SESSION_NAME_SIZE_MAX];
    int32_t ret = UnPackUkRequest(errJson, &aclInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnPackUkRequest(errJson, &aclInfo, sessionName);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    ret = UnPackUkRequest(validJson, &aclInfo, sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (requestStr != nullptr) {
        cJSON_free(requestStr);
    }
    if (validJson != nullptr) {
        cJSON_Delete(validJson);
    }
    if (errJson != nullptr) {
        cJSON_Delete(errJson);
    }
}

/**
 * @tc.name: UkPackReplyTest001
 * @tc.desc: UkPackReplyTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUkManagerTest, UkPackReplytTest001, TestSize.Level1)
{
    AuthACLInfo aclInfo;
    (void)memset_s(&aclInfo, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));

    char *replyStr = PackUkReply(nullptr, 0);
    EXPECT_EQ(nullptr, replyStr);

    replyStr = PackUkReply(&aclInfo, 0);
    EXPECT_TRUE(replyStr != nullptr);

    int32_t ukId = 0;
    cJSON *validJson = cJSON_Parse(replyStr);
    ASSERT_NE(validJson, nullptr);

    cJSON *errJson = cJSON_CreateObject();
    ASSERT_NE(errJson, nullptr);

    int32_t ret = UnPackUkReply(errJson, &aclInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnPackUkReply(errJson, &aclInfo, &ukId);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    ret = UnPackUkReply(validJson, &aclInfo, &ukId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (replyStr != nullptr) {
        cJSON_free(replyStr);
    }
    if (validJson != nullptr) {
        cJSON_Delete(validJson);
    }
    if (errJson != nullptr) {
        cJSON_Delete(errJson);
    }
}
} // namespace OHOS