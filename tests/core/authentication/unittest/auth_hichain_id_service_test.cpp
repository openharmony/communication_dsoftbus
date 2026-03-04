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
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_hichain_id_service_mock.h"
#include "auth_identity_service_adapter.c"
#include "auth_log.h"
#include "cJSON.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr int32_t BUF_LEN = 10;

#define FIELD_CRED_TYPE      "credType"
#define FIELD_DEVICE_ID      "deviceId"
#define FIELD_USER_ID        "userId"
#define FIELD_SUBJECT        "subject"
#define FIELD_DEVICE_ID_HASH "deviceIdHash"

#define ACCOUNT_RELATED   1
#define ACCOUNT_UNRELATED 2
#define ACCOUNT_SHARED     3

#define SUBJECT_MASTER_CONTROLLER 1
#define SUBJECT_ACCESSORY_DEVICE  2

#define TEST_CREDID_INFO  "123456789"
#define TEST_UDID_HASH    "1122334455667788"
#define TEST_ACCOUNT_HASH "1122"
#define TEST_UDID         "123456465421"

class AuthHichainIdServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthHichainIdServiceTest::SetUpTestCase() { }

void AuthHichainIdServiceTest::TearDownTestCase() { }

void AuthHichainIdServiceTest::SetUp() { }

void AuthHichainIdServiceTest::TearDown() { }

void cleanCJSONMsgList(cJSON **msgList, int index)
{
    for (int i = 0; i < index; i++) {
        if (msgList[i] != nullptr) {
            SoftBusFree(msgList[i]);
        }
    }
    return;
}

static char *TestAssembleCredInfo(uint8_t credType, uint8_t subject, const char *udidHash, const char *userId)
{
    JsonObj *json = JSON_CreateObject();
    if (json == nullptr) {
        AUTH_LOGE(AUTH_TEST, "create json fail");
        return nullptr;
    }
    if (!JSON_AddInt32ToObject(json, FIELD_CRED_TYPE, credType) ||
        !JSON_AddInt32ToObject(json, FIELD_SUBJECT, subject) ||
        !JSON_AddStringToObject(json, FIELD_DEVICE_ID, udidHash) ||
        !JSON_AddStringToObject(json, FIELD_USER_ID, userId)) {
        AUTH_LOGE(AUTH_TEST, "add cred info fail");
        JSON_Delete(json);
        return nullptr;
    }
    char *msg = JSON_PrintUnformatted(json);
    if (msg == nullptr) {
        AUTH_LOGE(AUTH_TEST, "JSON_PrintUnformatted fail");
        JSON_Delete(json);
        return nullptr;
    }
    JSON_Delete(json);
    return msg;
}

static CredChangeListener g_regListenerTest = {
    .onCredAdd = nullptr,
    .onCredDelete = nullptr,
    .onCredUpdate = nullptr,
};

static int32_t TestRegisterChangeListener(const char *appId, CredChangeListener *listener)
{
    (void)appId;
    AUTH_LOGI(AUTH_TEST, "********TestRegisterChangeListener enter");
    g_regListenerTest.onCredAdd = listener->onCredAdd;
    g_regListenerTest.onCredDelete = listener->onCredDelete;
    g_regListenerTest.onCredUpdate = listener->onCredUpdate;
    return SOFTBUS_OK;
}

static int32_t TestUnRegisterChangeListener(const char *appId)
{
    (void)appId;
    AUTH_LOGI(AUTH_TEST, "********TestUnRegisterChangeListener enter");
    g_regListenerTest.onCredAdd = nullptr;
    g_regListenerTest.onCredDelete = nullptr;
    g_regListenerTest.onCredUpdate = nullptr;
    return SOFTBUS_OK;
}

static int32_t TestQueryCredentialByParams(int32_t osAccountId, const char *requestParams, char **returnData)
{
    AUTH_LOGI(AUTH_TEST, "********TestQueryCredentialByParams enter");
    (void)requestParams;
    (void)returnData;

    if (osAccountId == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

/*
 * @tc.name: ID_SERVICE_GENERATE_QUERY_PARAM_TEST_001
 * @tc.desc: Verify that IdServiceGenerateQueryParam correctly generates query parameters for the
 *           Hichain ID service, handling various input scenarios and memory allocations.
 * @tc.type: FUNC
 * @tc.level: Level1
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

    EXPECT_CALL(IdServiceMock, cJSON_CreateObject)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(msg[0]))
        .WillOnce(Return(msg[1]))
        .WillOnce(Return(msg[2]))
        .WillOnce(Return(msg[3]));
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
 * @tc.desc: Verify that IdServiceQueryCredential queries credentials from the Hichain ID service,
 *           handling initialization failures and invalid parameters.
 * @tc.type: FUNC
 * @tc.level: Level1
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

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    credManager.queryCredentialByParams = QueryCredentialByParamsTest;
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&credManager));

    ret = IdServiceQueryCredential(userId, udidHash, accountHash, false, &credList);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FAIL);

    ret = IdServiceQueryCredential(userId, udidHash, accountHash, false, &credList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    userId = 1;
    ret = IdServiceQueryCredential(userId, udidHash, accountHash, false, &credList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ID_SERVICE_GENERATE_AUTH_PARAM_001
 * @tc.desc: Verify that IdServiceGenerateAuthParam correctly generates authentication parameters
 *           for the Hichain ID service, handling various input scenarios and memory allocations.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_GENERATE_AUTH_PARAM_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    char *param;
    const char *data = "1234";
    HiChainAuthParam hiChainParam = {};

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
    if (msg2 == nullptr) {
        SoftBusFree(msg);
        SoftBusFree(msg1);
        return;
    }

    EXPECT_CALL(IdServiceMock, cJSON_CreateObject)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(msg))
        .WillOnce(Return(msg1))
        .WillOnce(Return(msg2));
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

int32_t AuthCredentialTest(
    int32_t osAccountId, int64_t authReqId, const char *authParams, const DeviceAuthCallback *gaCallback)
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
 * @tc.desc: Verify that IdServiceAuthCredential authenticates credentials using the Hichain ID
 *           service, handling initialization failures and invalid parameters.
 * @tc.type: FUNC
 * @tc.level: Level1
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

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    authMgr.authCredential = AuthCredentialTest;
    EXPECT_CALL(IdServiceMock, GetCredAuthInstance).WillRepeatedly(Return(&authMgr));

    ret = IdServiceAuthCredential(userId, authReqId, authParams, &cb);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FAIL);

    ret = IdServiceAuthCredential(userId, authReqId, authParams, &cb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    authReqId = 1;
    ret = IdServiceAuthCredential(userId, authReqId, authParams, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

int32_t ProcessCredDataTest(
    int64_t authReqId, const uint8_t *data, uint32_t dataLen, const DeviceAuthCallback *gaCallback)
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
 * @tc.desc: Verify that IdServiceProcessCredData processes credential data using the Hichain ID
 *           service, handling initialization failures and invalid parameters.
 * @tc.type: FUNC
 * @tc.level: Level1
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

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    authMgr.processCredData = ProcessCredDataTest;
    EXPECT_CALL(IdServiceMock, GetCredAuthInstance).WillRepeatedly(Return(&authMgr));

    ret = IdServiceProcessCredData(authReqId, (unsigned char *)data, strlen(data), &cb);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FAIL);

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
 * @tc.name: ID_SERVICE_INIT_SERVICE_TEST_001
 * @tc.desc: Verify that IdServiceRegCredMgr successfully registers the credential manager and
 *           handles credential add/update/delete events, including local string info and trusted
 *           device info operations.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_INIT_SERVICE_TEST_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    char *msg = nullptr;
    CredManager g_testCredMgr = {
        .registerChangeListener = TestRegisterChangeListener,
        .queryCredentialByParams = TestQueryCredentialByParams,
        .unregisterChangeListener = TestUnRegisterChangeListener,
    };

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&g_testCredMgr));
    int32_t ret = IdServiceRegCredMgr();
    if (g_regListenerTest.onCredAdd != nullptr) {
        g_regListenerTest.onCredAdd(nullptr, nullptr);
    }
    if (g_regListenerTest.onCredUpdate != nullptr) {
        g_regListenerTest.onCredUpdate(nullptr, nullptr);
    }
    if (g_regListenerTest.onCredDelete != nullptr) {
        g_regListenerTest.onCredDelete(nullptr, nullptr);
    }
    msg = TestAssembleCredInfo(ACCOUNT_SHARED, SUBJECT_MASTER_CONTROLLER, TEST_UDID_HASH, TEST_ACCOUNT_HASH);
    char localUdid[UDID_BUF_LEN] = { 0 };
    EXPECT_EQ(strcpy_s(localUdid, UDID_BUF_LEN, TEST_UDID), EOK);
    EXPECT_CALL(IdServiceMock, LnnGetLocalStrInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*localUdid), Return(SOFTBUS_OK)));
    EXPECT_CALL(IdServiceMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_CALL(IdServiceMock, LnnInsertSpecificTrustedDevInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, LnnHbOnTrustedRelationIncreased).WillRepeatedly(Return());
    EXPECT_CALL(IdServiceMock, LnnDeleteSpecificTrustedDevInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, LnnHbOnTrustedRelationReduced).WillRepeatedly(Return());
    if (msg != nullptr && g_regListenerTest.onCredAdd != nullptr && g_regListenerTest.onCredDelete != nullptr) {
        g_regListenerTest.onCredAdd(TEST_CREDID_INFO, msg);
        g_regListenerTest.onCredDelete(TEST_CREDID_INFO, msg);
    }
    SoftBusFree(msg);
    IdServiceUnRegCredMgr();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ID_SERVICE_INIT_SERVICE_TEST_002
 * @tc.desc: Verify that IdServiceRegCredMgr successfully registers the credential manager and
 *           handles credential add/delete events, including scenarios where local string info is
 *           not found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_INIT_SERVICE_TEST_002, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    char *msg = nullptr;
    CredManager g_testCredMgr = {
        .registerChangeListener = TestRegisterChangeListener,
        .queryCredentialByParams = TestQueryCredentialByParams,
        .unregisterChangeListener = TestUnRegisterChangeListener,
    };

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&g_testCredMgr));
    int32_t ret = IdServiceRegCredMgr();
    msg = TestAssembleCredInfo(ACCOUNT_SHARED, SUBJECT_ACCESSORY_DEVICE, TEST_UDID_HASH, TEST_ACCOUNT_HASH);
    EXPECT_CALL(IdServiceMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_CALL(IdServiceMock, LnnDeleteSpecificTrustedDevInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, LnnHbOnTrustedRelationReduced).WillRepeatedly(Return());
    if (msg != nullptr && g_regListenerTest.onCredAdd != nullptr && g_regListenerTest.onCredDelete != nullptr) {
        g_regListenerTest.onCredAdd(TEST_CREDID_INFO, msg);
        g_regListenerTest.onCredDelete(TEST_CREDID_INFO, msg);
    }
    SoftBusFree(msg);
    IdServiceUnRegCredMgr();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ID_SERVICE_INIT_SERVICE_TEST_003
 * @tc.desc: Verify that IdServiceRegCredMgr successfully registers the credential manager and
 *           handles credential add/update events, including scenarios with different subject
 *           types and local string/number info operations.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_INIT_SERVICE_TEST_003, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    char *msg1 = nullptr;
    char *msg2 = nullptr;
    CredManager g_testCredMgr = {
        .registerChangeListener = TestRegisterChangeListener,
        .queryCredentialByParams = TestQueryCredentialByParams,
        .unregisterChangeListener = TestUnRegisterChangeListener,
    };

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&g_testCredMgr));
    int32_t ret = IdServiceRegCredMgr();
    msg1 = TestAssembleCredInfo(ACCOUNT_SHARED, SUBJECT_MASTER_CONTROLLER, TEST_UDID_HASH, TEST_ACCOUNT_HASH);
    msg2 = TestAssembleCredInfo(ACCOUNT_SHARED, SUBJECT_ACCESSORY_DEVICE, TEST_UDID_HASH, TEST_ACCOUNT_HASH);
    char localUdid[UDID_BUF_LEN] = { 0 };
    EXPECT_EQ(strcpy_s(localUdid, UDID_BUF_LEN, TEST_UDID), EOK);
    EXPECT_CALL(IdServiceMock, LnnGetLocalStrInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*localUdid), Return(SOFTBUS_OK)));
    EXPECT_CALL(IdServiceMock, LnnGetLocalNumInfo)
        .WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, LnnInsertSpecificTrustedDevInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, LnnHbOnTrustedRelationIncreased).WillRepeatedly(Return());
    if (msg1 != nullptr && msg2 != NULL && g_regListenerTest.onCredAdd != nullptr &&
        g_regListenerTest.onCredUpdate != nullptr) {
        g_regListenerTest.onCredAdd(TEST_CREDID_INFO, msg1);
        g_regListenerTest.onCredUpdate(TEST_CREDID_INFO, msg2);
    }
    SoftBusFree(msg1);
    SoftBusFree(msg2);
    IdServiceUnRegCredMgr();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ID_SERVICE_DESTROY_CREDLIST_001
 * @tc.desc: Verify that IdServiceDestroyCredentialList correctly destroys a credential list,
 *           handling null inputs and ensuring proper memory deallocation.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_DESTROY_CREDLIST_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    CredManager credManager;
    char *data = nullptr;

    EXPECT_CALL(IdServiceMock, InitDeviceAuthService)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
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
 * @tc.desc: Verify that IdServiceGetCredIdFromCredList correctly extracts a credential ID from a
 *           credential list, handling various input formats and credential properties.
 * @tc.type: FUNC
 * @tc.level: Level1
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

/*
 * @tc.name: ID_SERVICE_IS_POTENTIAL_TRUSTED_DEVICE_001
 * @tc.desc: Verify that IdServiceIsPotentialTrustedDevice correctly determines if a device is
 *           potentially trusted, handling null or invalid UDID and account ID inputs.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_IS_POTENTIAL_TRUSTED_DEVICE_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    EXPECT_CALL(IdServiceMock, GetActiveOsAccountIds).WillRepeatedly(Return(2));

    char *udid = nullptr;
    char *accountId = nullptr;
    bool isSameAccount = true;
    bool ret = IdServiceIsPotentialTrustedDevice(udid, accountId, isSameAccount);
    EXPECT_FALSE(ret);

    const char *shortUdid = "123456";
    ret = IdServiceIsPotentialTrustedDevice(shortUdid, accountId, isSameAccount);
    EXPECT_FALSE(ret);

    const char *shortAccountId = "654321";
    ret = IdServiceIsPotentialTrustedDevice(shortUdid, shortAccountId, isSameAccount);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: GET_CRED_INFO_FROM_JSON_001
 * @tc.desc: Verify that GetCredInfoFromJson successfully extracts credential information from a
 *           JSON string, handling invalid JSON and valid credential data.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, GET_CRED_INFO_FROM_JSON_001, TestSize.Level1)
{
    const char *credInfo = "{\"credOwner\":\"DM\"}";
    SoftBusCredInfo info;
    (void)memset_s(&info, sizeof(SoftBusCredInfo), 0, sizeof(SoftBusCredInfo));
    int32_t ret = GetCredInfoFromJson(credInfo, &info);
    EXPECT_NE(ret, SOFTBUS_OK);

    char *testInfo = TestAssembleCredInfo(ACCOUNT_SHARED, SUBJECT_ACCESSORY_DEVICE, TEST_UDID_HASH, TEST_ACCOUNT_HASH);
    ret = GetCredInfoFromJson(testInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(testInfo);
}

/*
 * @tc.name: IS_LOCAL_CRED_001
 * @tc.desc: Verify that IsLocalCredInfo returns false when unable to retrieve the local UDID.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, IS_LOCAL_CRED_001, TestSize.Level1)
{
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    CredManager credManager;
    credManager.destroyInfo = DestroyInfoTest;
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&credManager));

    const char *udid = "123456";
    bool ret = IsLocalCredInfo(udid);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: ID_SERVICE_REG_CRE_MGR_001
 * @tc.desc: Verify that IdServiceRegCredMgr returns an error when InitDeviceAuthService fails
 *           during credential manager registration.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_REG_CRE_MGR_001, TestSize.Level1)
{
    AUTH_LOGI(AUTH_TEST, "Start ID_SERVICE_REG_CRE_MGR_001 test.");
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    int32_t ret = IdServiceRegCredMgr();
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_CRED_INSTANCE_FAIL);
    IdServiceUnRegCredMgr();
}

/*
 * @tc.name: ID_SERVICE_REG_CRE_MGR_002
 * @tc.desc: Verify that IdServiceRegCredMgr successfully registers the credential manager when
 *           InitDeviceAuthService succeeds.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainIdServiceTest, ID_SERVICE_REG_CRE_MGR_002, TestSize.Level1)
{
    AUTH_LOGI(AUTH_TEST, "Start ID_SERVICE_REG_CRE_MGR_001 test.");
    AuthHichainIdServiceInterfaceMock IdServiceMock;
    CredManager credManager= {
        .registerChangeListener = TestRegisterChangeListener,
        .queryCredentialByParams = TestQueryCredentialByParams,
        .unregisterChangeListener = TestUnRegisterChangeListener,
        .destroyInfo = DestroyInfoTest,
    };
    EXPECT_CALL(IdServiceMock, InitDeviceAuthService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(IdServiceMock, GetCredMgrInstance).WillRepeatedly(Return(&credManager));
    int32_t ret = IdServiceRegCredMgr();
    EXPECT_EQ(ret, SOFTBUS_OK);
    IdServiceUnRegCredMgr();
}
} // namespace OHOS