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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <cstring>
#include <sys/time.h>

#include "cJSON.h"
#include "auth_hichain_id_service_mock.h"
#include "auth_identity_service_adapter.c"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr int32_t BUF_LEN = 10;

class AuthHichainIdServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthHichainIdServiceTest::SetUpTestCase() {}

void AuthHichainIdServiceTest::TearDownTestCase() {}

void AuthHichainIdServiceTest::SetUp() {}

void AuthHichainIdServiceTest::TearDown() {}

void cleanCJSONMsgList(cJSON **msgList, int index)
{
    for (int i = 0; i < index; i++) {
        if (msgList[i] != nullptr) {
            SoftBusFree(msgList[i]);
        }
    }
    return;
}

/*
 * @tc.name: ID_SERVICE_GENERATE_QUERY_PARAM_TEST_001
 * @tc.desc: IdServiceGenerateQueryParam test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_GENERATE_QUERY_PARAM_TEST_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    char *param;
    char udidHash[BUF_LEN] = { 0 };
    char accountHash[BUF_LEN] = { 0 };
    const char *data = "1234";
    cJSON *msg[4] = { 0 };
    
    for (int i = 0; i < 4; i++) {
        msg[i] = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
        if (msg[i] == nullptr) {
            cleanCJSONMsgList(msg, i);
            return;
        }
    }

    EXPECT_CALL(IdServiceMock, cJSON_CreateObject).WillOnce(Return(nullptr)).WillOnce(Return(msg[0]))
        .WillOnce(Return(msg[1])).WillOnce(Return(msg[2])).WillOnce(Return(msg[3]));
    EXPECT_CALL(IdServiceMock, AddStringToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(IdServiceMock, AddNumberToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(IdServiceMock, cJSON_PrintUnformatted).WillOnce(Return(nullptr)).WillRepeatedly(Return((char *)data));

    param = IdServiceGenerateQueryParam(udidHash, accountHash, false);
    EXPECT_EQ(param, nullptr);

    param = IdServiceGenerateQueryParam(udidHash, accountHash, true);
    EXPECT_EQ(param, nullptr);

    param = IdServiceGenerateQueryParam(udidHash, accountHash, true);
    EXPECT_EQ(param, nullptr);

    param = IdServiceGenerateQueryParam(udidHash, accountHash, true);
    EXPECT_EQ(param, nullptr);

    param = IdServiceGenerateQueryParam(udidHash, accountHash, true);
    EXPECT_NE(param, nullptr);
}

int32_t QueryCredentialByParamsTest(int32_t osAccountId, const char *requestParams, char **returnData)
{
    (void)requestParams;
    (void)returnData;

    if (osAccountId == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

/*
 * @tc.name: ID_SERVICE_QUERY_CRED_TEST_001
 * @tc.desc: IdServiceQueryCredential test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_QUERY_CRED_TEST_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    char udidHash[BUF_LEN] = { 0 };
    char accountHash[BUF_LEN] = { 0 };
    int32_t userId = 0;
    char *credList = nullptr;
    int32_t ret;
    CredManager credManager;
    cJSON *msg[2] = { 0 };
    
    for (int i = 0; i < 2; i++) {
        msg[i] = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
        if (msg[i] == nullptr) {
            cleanCJSONMsgList(msg, i);
            return;
        }
    }

    char *data = reinterpret_cast<char *>(SoftBusCalloc(sizeof(cJSON)));
    if (data == nullptr) {
        cleanCJSONMsgList(msg, 2);
        return;
    }

    char *data1 = reinterpret_cast<char *>(SoftBusCalloc(sizeof(cJSON)));
    if (data1 == nullptr) {
        cleanCJSONMsgList(msg, 2);
        SoftBusFree(data);
        return;
    }

    EXPECT_CALL(IdServiceMock, cJSON_CreateObject).WillOnce(Return(msg[0])).WillOnce(Return(msg[1]));
    EXPECT_CALL(IdServiceMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(IdServiceMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(IdServiceMock, cJSON_PrintUnformatted).WillOnce(Return(data)).WillOnce(Return(data1));

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    credManager.queryCredentialByParams = QueryCredentialByParamsTest;
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&credManager));

    ret = IdServiceQueryCredential(userId, udidHash, accountHash, false, &credList);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FALI);

    ret = IdServiceQueryCredential(userId, udidHash, accountHash, false, &credList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    userId = 1;
    ret = IdServiceQueryCredential(userId, udidHash, accountHash, false, &credList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ID_SERVICE_GENERATE_AUTH_PARAM_001
 * @tc.desc: IdServiceGenerateAuthParam test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_GENERATE_AUTH_PARAM_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    char *param;
    const char *data = "1234";
    HiChainAuthParam hiChainParam = { 0 };
    
    cJSON *msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }

    cJSON *msg1 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg1 == nullptr) {
        SoftBusFree(msg);
        return;
    }

    cJSON *msg2 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg1 == nullptr) {
        SoftBusFree(msg);
        SoftBusFree(msg1);
        return;
    }

    EXPECT_CALL(IdServiceMock, cJSON_CreateObject).WillOnce(Return(nullptr)).WillOnce(Return(msg))
        .WillOnce(Return(msg1)).WillOnce(Return(msg2));
    EXPECT_CALL(IdServiceMock, AddStringToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(IdServiceMock, cJSON_PrintUnformatted).WillOnce(Return(nullptr)).WillRepeatedly(Return((char *)data));

    param = IdServiceGenerateAuthParam(&hiChainParam);
    EXPECT_EQ(param, nullptr);

    param = IdServiceGenerateAuthParam(&hiChainParam);
    EXPECT_EQ(param, nullptr);

    param = IdServiceGenerateAuthParam(&hiChainParam);
    EXPECT_EQ(param, nullptr);

    param = IdServiceGenerateAuthParam(&hiChainParam);
    EXPECT_NE(param, nullptr);
}

int32_t AuthCredentialTest(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    (void)osAccountId;
    (void)authParams;
    (void)gaCallback;

    if (authReqId == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

/*
 * @tc.name: ID_SERVICE_AUTH_CRED_001
 * @tc.desc: IdServiceAuthCredential test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_AUTH_CRED_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    int32_t userId = 0;
    int64_t authReqId = 0;
    const char *authParams = "abcd";
    DeviceAuthCallback cb;
    int32_t ret;
    CredAuthManager authMgr;

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    authMgr.authCredential = AuthCredentialTest;
    EXPECT_CALL(IdServiceMock, GetCredAuthInstance).WillRepeatedly(Return(&authMgr));

    ret = IdServiceAuthCredential(userId, authReqId, authParams, &cb);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FALI);

    ret = IdServiceAuthCredential(userId, authReqId, authParams, &cb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    authReqId = 1;
    ret = IdServiceAuthCredential(userId, authReqId, authParams, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

int32_t ProcessCredDataTest(int64_t authReqId, const uint8_t *data, uint32_t dataLen,
    const DeviceAuthCallback *gaCallback)
{
    (void)data;
    (void)dataLen;
    (void)gaCallback;

    if (authReqId == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

/*
 * @tc.name: ID_SERVICE_PROCESS_CRED_DATA_001
 * @tc.desc: IdServiceProcessCredData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_PROCESS_CRED_DATA_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    const char *data = "1234";
    int64_t authReqId = 0;
    DeviceAuthCallback cb;
    int32_t ret;
    CredAuthManager authMgr;

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    authMgr.processCredData = ProcessCredDataTest;
    EXPECT_CALL(IdServiceMock, GetCredAuthInstance).WillRepeatedly(Return(&authMgr));

    ret = IdServiceProcessCredData(authReqId, (unsigned char *)data, strlen(data), &cb);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FALI);

    ret = IdServiceProcessCredData(authReqId, (unsigned char *)data, strlen(data), &cb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    authReqId = 1;
    ret = IdServiceProcessCredData(authReqId, (unsigned char *)data, strlen(data), &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

int32_t g_count;
void DestroyInfoTest(char **returnData)
{
    g_count++;
    return;
}

/*
 * @tc.name: ID_SERVICE_DESTROY_CREDLIST_001
 * @tc.desc: IdServiceDestroyCredentialList test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_DESTROY_CREDLIST_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    CredManager credManager;
    char *data = nullptr;

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    credManager.destroyInfo = DestroyInfoTest;
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&credManager));

    IdServiceDestroyCredentialList(nullptr);
    EXPECT_EQ(g_count, 0);

    IdServiceDestroyCredentialList(&data);
    EXPECT_EQ(g_count, 0);

    IdServiceDestroyCredentialList(&data);
    EXPECT_EQ(g_count, 1);
}

char g_credInfo[100];
int32_t QueryCredInfoByCredId(int32_t userId, const char *credId, char **credInfo)
{
    if (userId == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    *credInfo = g_credInfo;
    return SOFTBUS_OK;
}

/*
 * @tc.name: ID_SERVICE_GET_CREDID_FROM_LIST_001
 * @tc.desc: IdServiceGetCredIdFromCredList test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_GET_CREDID_FROM_LIST_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    CredManager credManager;
    char *credId = nullptr;
    int32_t userId = 0;

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    credManager.destroyInfo = DestroyInfoTest;
    credManager.queryCredInfoByCredId = QueryCredInfoByCredId;
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&credManager));

    credId = IdServiceGetCredIdFromCredList(userId, nullptr);
    EXPECT_EQ(credId, nullptr);

    credId = IdServiceGetCredIdFromCredList(userId, "[]");
    EXPECT_EQ(credId, nullptr);

    credId = IdServiceGetCredIdFromCredList(userId, "[\"123\", \"456\"]");
    EXPECT_EQ(credId, nullptr);

    userId = 1;

    memset_s(g_credInfo, sizeof(g_credInfo), 0, sizeof(g_credInfo));
    strcpy_s(g_credInfo, sizeof(g_credInfo), "{\"credOwner\":\"DM\"}");
    credId = IdServiceGetCredIdFromCredList(userId, "[\"123\", \"456\"]");
    EXPECT_EQ(credId, nullptr);

    memset_s(g_credInfo, sizeof(g_credInfo), 0, sizeof(g_credInfo));
    strcpy_s(g_credInfo, sizeof(g_credInfo), "{\"credType\":2}");
    credId = IdServiceGetCredIdFromCredList(userId, "[\"123\", \"456\"]");
    EXPECT_EQ(credId, nullptr);

    memset_s(g_credInfo, sizeof(g_credInfo), 0, sizeof(g_credInfo));
    strcpy_s(g_credInfo, sizeof(g_credInfo), "{\"credType\":2,\"authorizedScope\":2}");
    credId = IdServiceGetCredIdFromCredList(userId, "[\"123\", \"456\"]");
    EXPECT_NE(credId, nullptr);

    SoftBusFree(credId);
}
} // namespace OHOS