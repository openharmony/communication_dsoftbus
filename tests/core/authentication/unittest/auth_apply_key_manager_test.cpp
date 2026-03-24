/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "auth_apply_key_manager.c"
#include "auth_apply_key_manager.h"
#include "auth_apply_key_manager_mock.h"
#include "auth_log.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager_struct.h"

#define TEST_KEY_001            "test_key_001"
#define TEST_KEY_002            "test_key_002"
#define TEST_KEY_003            "test_key_003"
#define TEST_KEY_004            "test_key_004"
#define TEST_KEY_005            "test_key_005"
#define TEST_KEY                "test_key"
#define TEST_KEY_NOT_EXIST      "test_key_not_exist"
#define TEST_NON_EXIST_KEY      "non_exist_key"
#define TEST_NODE_KEY           "test_node_key"
#define TEST_INVALID_JSON       "invalid json"
#define TEST_UDID_HASH          "udidHash"
#define TEST_ACCOUNT            "account"
#define TEST_PEER_ACCOUNT_HASH  "peerAccountHash"
#define TEST_JSON_KEY           "test_key"
#define TEST_APPLY_KEY_VALUE    "0102030405"
#define TEST_ACCOUNT_HASH_VALUE "aaaa"
#define TEST_TIME_VALUE         1000
namespace OHOS {
using namespace testing;
using namespace testing::ext;

class AuthApplyKeyManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static void InitApplyKeyManagerMock(AuthApplyKeyManagerMock *mock)
{
    EXPECT_CALL(*mock, LnnRetrieveDeviceDataPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*mock, LnnRegisterEventHandler).WillRepeatedly(Return(SOFTBUS_OK));
}

void AuthApplyKeyManagerTest::SetUpTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthApplyKeyManagerTest start");
    AuthApplyKeyManagerMock applyKeyMock;
    InitApplyKeyManagerMock(&applyKeyMock);
    InitApplyKeyManager();
}

void AuthApplyKeyManagerTest::TearDownTestCase()
{
    AUTH_LOGI(AUTH_CONN, "AuthApplyKeyManagerTest end");
    DeInitApplyKeyManager();
}

void AuthApplyKeyManagerTest::SetUp() { }

void AuthApplyKeyManagerTest::TearDown() { }

/*
 * @tc.name: AUTH_APPLY_KEY_MANAGER_INIT_Test_001
 * @tc.desc: Verify that AuthInsertApplyKey AuthDeleteApplyKey and GetApplyKeyByBusinessInfo return SOFTBUS_NO_INIT
 *           when ApplyKeyManager is uninitialized; non-fatal execution for recovery deinit and clear function
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_APPLY_KEY_MANAGER_INIT_Test_001, TestSize.Level1)
{
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = AuthInsertApplyKey(nullptr, nullptr, 0, 0, accountHash);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthDeleteApplyKey(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetApplyKeyByBusinessInfo(nullptr, nullptr, 0, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(AuthRecoveryApplyKey());
    EXPECT_NO_FATAL_FAILURE(DeInitApplyKeyManager());
    EXPECT_NO_FATAL_FAILURE(AuthClearAccountApplyKey());
}

/*
 * @tc.name: AUTH_APPLY_KEY_MANAGER_Test_001
 * @tc.desc: Verify successful insertion retrieval and deletion of apply keys after initializing ApplyKeyManager
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_APPLY_KEY_MANAGER_Test_001, TestSize.Level1)
{
    AuthApplyKeyManagerMock applyKeyMock;
    InitApplyKeyManagerMock(&applyKeyMock);
    InitApplyKeyManager();
    RequestBusinessInfo info;
    (void)memset_s(&info, sizeof(RequestBusinessInfo), 0, sizeof(RequestBusinessInfo));
    info.type = BUSINESS_TYPE_D2D;
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    uint8_t uk[D2D_APPLY_KEY_LEN] = { 0 };
    uint64_t currentTime = SoftBusGetSysTimeMs();
    int32_t userId = 0;
    EXPECT_CALL(applyKeyMock, JudgeDeviceTypeAndGetOsAccountIds).WillRepeatedly(Return(userId));
    int32_t ret = AuthInsertApplyKey(&info, uk, D2D_APPLY_KEY_LEN, currentTime, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t outUk[D2D_APPLY_KEY_LEN] = { 0 };
    ret = GetApplyKeyByBusinessInfo(&info, outUk, D2D_APPLY_KEY_LEN - 1, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    ret = GetApplyKeyByBusinessInfo(&info, outUk, D2D_APPLY_KEY_LEN, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AuthDeleteApplyKey(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetApplyKeyByBusinessInfo(&info, outUk, D2D_APPLY_KEY_LEN, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_NOT_FOUND);
}

/*
 * @tc.name: AUTH_APPLY_KEY_MANAGER_Test_002
 * @tc.desc: Verify that expired apply keys are handled correctly during retrieval.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_APPLY_KEY_MANAGER_Test_002, TestSize.Level1)
{
    AuthApplyKeyManagerMock applyKeyMock;
    InitApplyKeyManagerMock(&applyKeyMock);
    InitApplyKeyManager();
    RequestBusinessInfo info;
    (void)memset_s(&info, sizeof(RequestBusinessInfo), 0, sizeof(RequestBusinessInfo));
    info.type = BUSINESS_TYPE_D2D;
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    uint8_t uk[D2D_APPLY_KEY_LEN] = { 0 };
    uint64_t currentTime = 0;
    int32_t userId = 0;
    EXPECT_CALL(applyKeyMock, JudgeDeviceTypeAndGetOsAccountIds).WillRepeatedly(Return(userId));
    int32_t ret = AuthInsertApplyKey(&info, uk, D2D_APPLY_KEY_LEN, currentTime, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t outUk[D2D_APPLY_KEY_LEN] = { 0 };
    ret = GetApplyKeyByBusinessInfo(&info, outUk, D2D_APPLY_KEY_LEN, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_APPLY_KEY_MANAGER_Test_003
 * @tc.desc: Verify that AuthApplyKeyManager functions handle null parameters gracefully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_APPLY_KEY_MANAGER_Test_003, TestSize.Level1)
{
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = AuthInsertApplyKey(nullptr, nullptr, 0, 0, accountHash);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthDeleteApplyKey(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetApplyKeyByBusinessInfo(nullptr, nullptr, 0, accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_INSERT_TO_AUTH_APPLY_MAP_Test_001
 * @tc.desc: Verify successful insertion and deletion of apply keys to auth apply map.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_INSERT_TO_AUTH_APPLY_MAP_Test_001, TestSize.Level1)
{
    const char *applyMapKey = TEST_KEY_001;
    uint8_t applyKey[D2D_APPLY_KEY_LEN] = { 1 };
    int32_t userId = 0;
    uint64_t time = TEST_TIME_VALUE;
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = InsertToAuthApplyMap(applyMapKey, applyKey, userId, time, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DeleteToAuthApplyMap(applyMapKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_INSERT_TO_AUTH_APPLY_MAP_Test_002
 * @tc.desc: Verify that InsertToAuthApplyMap handles null parameters gracefully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_INSERT_TO_AUTH_APPLY_MAP_Test_002, TestSize.Level1)
{
    uint8_t applyKey[D2D_APPLY_KEY_LEN] = { 1 };
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = InsertToAuthApplyMap(nullptr, applyKey, 0, TEST_TIME_VALUE, accountHash);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InsertToAuthApplyMap(TEST_KEY, nullptr, 0, TEST_TIME_VALUE, accountHash);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InsertToAuthApplyMap(TEST_KEY, applyKey, 0, TEST_TIME_VALUE, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_GET_NODE_FROM_AUTH_APPLY_MAP_Test_001
 * @tc.desc: Verify successful retrieval of apply key node from auth apply map.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_GET_NODE_FROM_AUTH_APPLY_MAP_Test_001, TestSize.Level1)
{
    const char *applyMapKey = TEST_KEY_002;
    uint8_t applyKey[D2D_APPLY_KEY_LEN] = { 2 };
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = InsertToAuthApplyMap(applyMapKey, applyKey, 0, TEST_TIME_VALUE, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthApplyMapValue value;
    (void)memset_s(&value, sizeof(AuthApplyMapValue), 0, sizeof(AuthApplyMapValue));
    ret = GetNodeFromAuthApplyMap(applyMapKey, &value);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DeleteToAuthApplyMap(applyMapKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_GET_NODE_FROM_AUTH_APPLY_MAP_Test_002
 * @tc.desc: Verify that GetNodeFromAuthApplyMap handles null parameters and non-existent keys correctly.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_GET_NODE_FROM_AUTH_APPLY_MAP_Test_002, TestSize.Level1)
{
    AuthApplyMapValue value;
    (void)memset_s(&value, sizeof(AuthApplyMapValue), 0, sizeof(AuthApplyMapValue));
    int32_t ret = GetNodeFromAuthApplyMap(nullptr, &value);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetNodeFromAuthApplyMap(TEST_KEY_NOT_EXIST, &value);
    EXPECT_EQ(ret, SOFTBUS_AUTH_APPLY_KEY_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DELETE_TO_AUTH_APPLY_MAP_Test_001
 * @tc.desc: Verify successful deletion of apply key from auth apply map.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_DELETE_TO_AUTH_APPLY_MAP_Test_001, TestSize.Level1)
{
    const char *applyMapKey = TEST_KEY_003;
    uint8_t applyKey[D2D_APPLY_KEY_LEN] = { 3 };
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = InsertToAuthApplyMap(applyMapKey, applyKey, 0, TEST_TIME_VALUE, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DeleteToAuthApplyMap(applyMapKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_DELETE_TO_AUTH_APPLY_MAP_Test_002
 * @tc.desc: Verify that DeleteToAuthApplyMap handles null parameters and non-existent keys correctly.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_DELETE_TO_AUTH_APPLY_MAP_Test_002, TestSize.Level1)
{
    int32_t ret = DeleteToAuthApplyMap(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DeleteToAuthApplyMap(TEST_NON_EXIST_KEY);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_CLEAR_AUTH_APPLY_MAP_Test_001
 * @tc.desc: Verify successful clearing of all apply keys from auth apply map.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_CLEAR_AUTH_APPLY_MAP_Test_001, TestSize.Level1)
{
    const char *applyMapKey = TEST_KEY_004;
    uint8_t applyKey[D2D_APPLY_KEY_LEN] = { 4 };
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = InsertToAuthApplyMap(applyMapKey, applyKey, 0, TEST_TIME_VALUE, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(ClearAuthApplyMap());
}

/*
 * @tc.name: AUTH_PACK_APPLY_KEY_Test_001
 * @tc.desc: Verify successful packing of apply key into JSON object.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_PACK_APPLY_KEY_Test_001, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    char nodeKey[KEY_LEN] = TEST_NODE_KEY;
    AuthApplyMapValue value;
    (void)memset_s(&value, sizeof(AuthApplyMapValue), 0, sizeof(AuthApplyMapValue));
    value.userId = 0;
    value.time = TEST_TIME_VALUE;
    (void)memset_s(value.applyKey, D2D_APPLY_KEY_LEN, 1, D2D_APPLY_KEY_LEN);
    (void)memset_s(value.accountHash, SHA_256_HEX_HASH_LEN, 'a', SHA_256_HEX_HASH_LEN - 1);
    bool ret = AuthPackApplyKey(json, nodeKey, &value);
    EXPECT_TRUE(ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: AUTH_PACK_APPLY_KEY_Test_002
 * @tc.desc: Verify that AuthPackApplyKey handles null parameters gracefully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_PACK_APPLY_KEY_Test_002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    AuthApplyMapValue value;
    (void)memset_s(&value, sizeof(AuthApplyMapValue), 0, sizeof(AuthApplyMapValue));
    value.userId = 0;
    value.time = TEST_TIME_VALUE;
    bool ret = AuthPackApplyKey(json, nullptr, &value);
    EXPECT_FALSE(ret);
    ret = AuthPackApplyKey(nullptr, const_cast<char *>("key"), &value);
    EXPECT_FALSE(ret);
    ret = AuthPackApplyKey(json, const_cast<char *>("key"), nullptr);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: AUTH_UNPACK_APPLY_KEY_Test_001
 * @tc.desc: Verify successful unpacking of apply key from JSON object.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_UNPACK_APPLY_KEY_Test_001, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    AddStringToJsonObject(json, MAP_KEY, TEST_JSON_KEY);
    AddStringToJsonObject(json, VALUE_APPLY_KEY, TEST_APPLY_KEY_VALUE);
    AddStringToJsonObject(json, VALUE_ACCOUNT_HASH, TEST_ACCOUNT_HASH_VALUE);
    AddNumberToJsonObject(json, VALUE_USER_ID, 0);
    AddNumber64ToJsonObject(json, VALUE_TIME, TEST_TIME_VALUE);
    AuthApplyMap node;
    (void)memset_s(&node, sizeof(AuthApplyMap), 0, sizeof(AuthApplyMap));
    bool ret = AuthUnpackApplyKey(json, &node);
    EXPECT_TRUE(ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: AUTH_UNPACK_APPLY_KEY_Test_002
 * @tc.desc: Verify that AuthUnpackApplyKey handles null parameters and invalid JSON correctly.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_UNPACK_APPLY_KEY_Test_002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(json, nullptr);
    AuthApplyMap node;
    (void)memset_s(&node, sizeof(AuthApplyMap), 0, sizeof(AuthApplyMap));
    bool ret = AuthUnpackApplyKey(json, &node);
    EXPECT_FALSE(ret);
    ret = AuthUnpackApplyKey(nullptr, &node);
    EXPECT_FALSE(ret);
    ret = AuthUnpackApplyKey(json, nullptr);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/*
 * @tc.name: AUTH_PRASE_APPLY_KEY_Test_001
 * @tc.desc: Verify successful parsing of valid JSON apply key data.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_PRASE_APPLY_KEY_Test_001, TestSize.Level1)
{
    const char *validJson = "[[{\"mapKey\":\"key1\",\"applyKey\":\"01020\",\"accountHash\":\"aaaa\",\"userId\":0,"
        "\"time\":9999999999999}]]";
    int32_t len = std::strlen(validJson) + 1;
    char *key = reinterpret_cast<char *>(SoftBusCalloc(len));
    ASSERT_NE(key, nullptr);
    int32_t res = strcpy_s(key, len, validJson);
    EXPECT_EQ(res, EOK);
    bool ret = AuthPraseApplyKey(key);
    EXPECT_FALSE(ret);
    SoftBusFree(key);
}

/*
 * @tc.name: AUTH_PRASE_APPLY_KEY_Test_002
 * @tc.desc: Verify that AuthPraseApplyKey handles null and invalid JSON parameters gracefully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_PRASE_APPLY_KEY_Test_002, TestSize.Level1)
{
    bool ret = AuthPraseApplyKey(nullptr);
    EXPECT_FALSE(ret);
    ret = AuthPraseApplyKey(TEST_INVALID_JSON);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: AUTH_PACK_ALL_APPLY_KEY_Test_001
 * @tc.desc: Verify successful packing of all apply keys from auth apply map.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_PACK_ALL_APPLY_KEY_Test_001, TestSize.Level1)
{
    const char *applyMapKey = TEST_KEY_005;
    uint8_t applyKey[D2D_APPLY_KEY_LEN] = { 5 };
    char accountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t ret = InsertToAuthApplyMap(applyMapKey, applyKey, 0, TEST_TIME_VALUE, accountHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char *packedData = PackAllApplyKey();
    EXPECT_NE(packedData, nullptr);
    cJSON_free(packedData);
    ret = DeleteToAuthApplyMap(applyMapKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_PRINTF_REQUEST_BUSINESS_INFO_Test_001
 * @tc.desc: Verify that PrintfRequestBusinessInfo handles null parameters gracefully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_PRINTF_REQUEST_BUSINESS_INFO_Test_001, TestSize.Level1)
{
    RequestBusinessInfo info;
    (void)memset_s(&info, sizeof(RequestBusinessInfo), 0, sizeof(RequestBusinessInfo));
    info.type = BUSINESS_TYPE_D2D;
    int ret = strcpy_s(info.udidHash, D2D_UDID_HASH_STR_LEN, TEST_UDID_HASH);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(info.accountHash, D2D_ACCOUNT_HASH_STR_LEN, TEST_ACCOUNT);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(info.peerAccountHash, SHA_256_HEX_HASH_LEN, TEST_PEER_ACCOUNT_HASH);
    EXPECT_EQ(ret, EOK);
    EXPECT_NO_FATAL_FAILURE(PrintfRequestBusinessInfo(&info, 0));
}

/*
 * @tc.name: AUTH_ACCOUNT_STATE_CHANGE_HANDLER_Test_001
 * @tc.desc: Verify that AccountStateChangeHandler handles null and invalid event parameters gracefully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_ACCOUNT_STATE_CHANGE_HANDLER_Test_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(AccountStateChangeHandler(nullptr));
    LnnEventBasicInfo invalidEvent;
    (void)memset_s(&invalidEvent, sizeof(LnnEventBasicInfo), 0, sizeof(LnnEventBasicInfo));
    invalidEvent.event = LNN_EVENT_TYPE_MAX;
    EXPECT_NO_FATAL_FAILURE(AccountStateChangeHandler(&invalidEvent));
}

/*
 * @tc.name: AUTH_USER_SWITCHED_HANDLER_Test_001
 * @tc.desc: Verify that UserSwitchedHandler handles null and invalid event parameters gracefully.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_USER_SWITCHED_HANDLER_Test_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UserSwitchedHandler(nullptr));
    LnnEventBasicInfo invalidEvent;
    (void)memset_s(&invalidEvent, sizeof(LnnEventBasicInfo), 0, sizeof(LnnEventBasicInfo));
    invalidEvent.event = LNN_EVENT_TYPE_MAX;
    EXPECT_NO_FATAL_FAILURE(UserSwitchedHandler(&invalidEvent));
}

/*
 * @tc.name: AUTH_CLEAR_ACCOUNT_APPLY_KEY_Test_001
 * @tc.desc: Verify that AuthClearAccountApplyKey successfully clears all account-related apply keys.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthApplyKeyManagerTest, AUTH_CLEAR_ACCOUNT_APPLY_KEY_Test_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(AuthRecoveryApplyKey());
    EXPECT_NO_FATAL_FAILURE(DeInitApplyKeyManager());
    EXPECT_NO_FATAL_FAILURE(AuthClearAccountApplyKey());
}
} // namespace OHOS