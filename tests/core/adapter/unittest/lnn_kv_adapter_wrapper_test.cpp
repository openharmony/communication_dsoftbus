/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <cstring>
#include <securec.h>
#include <string>

#include "lnn_kv_adapter_wrapper.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "gtest/gtest.h"
#include "dsoftbus_enhance_interface.h"
#include "g_enhance_lnn_func.h"
#include "lnn_kv_adapter_wrapper_mock.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace {
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int32_t MIN_STRING_LEN = 1;
constexpr int32_t APP_ID_LEN = 8;
constexpr int32_t STORE_ID_LEN = 19;
constexpr int32_t MIN_DBID_COUNT = 1;
const std::string APP_ID = "dsoftbus";
const std::string STORE_ID = "dsoftbus_kv_db_test";
} // namespace
static int32_t g_dbId = 1;
class KVAdapterWrapperTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void KVAdapterWrapperTest::SetUpTestCase(void)
{
    int32_t dbID;
    LnnCreateKvAdapter(&dbID, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    g_dbId = dbID;

    LnnCreateKvAdapter(&dbID, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
}

void KVAdapterWrapperTest::TearDownTestCase(void)
{
    LnnDestroyKvAdapter(g_dbId + 1);

    LnnDestroyKvAdapter(g_dbId);
}

void KVAdapterWrapperTest::SetUp() { }

void KVAdapterWrapperTest::TearDown() { }

/*
 * @tc.name: LnnPutDBData
 * @tc.desc: LnnPutDBData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    string keyStr = "aaa";
    string valueStr = "aaa";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), 3, valueStr.c_str(), 3), SOFTBUS_OK);
    dbId++;
    EXPECT_EQ(
        LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(
        LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN + 1),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
    char *valuePtr = nullptr;
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valuePtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(
        LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN + 1, valuePtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(
        LnnPutDBData(dbId, keyStr.c_str(), MIN_STRING_LEN - 1, valuePtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnPutDBData(dbId, keyPtr, MIN_STRING_LEN - 1, valuePtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBData
 * @tc.desc: LnnDeleteDBData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDelete001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    string keyStr = "aaa";
    string valueStr = "ccc";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), 3, valueStr.c_str(), 3), SOFTBUS_OK);
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), 3), SOFTBUS_OK);
    dbId++;
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), MAX_STRING_LEN + 1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnDeleteDBData(dbId, keyPtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBDataByPrefix
 * @tc.desc: LnnDeleteDBDataByPrefix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteByPrefix001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    LnnRegisterDataChangeListener(dbId, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    LnnRegisterDataChangeListener(dbId + 1, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    dbId = g_dbId;
    LnnRegisterDataChangeListener(dbId, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    string keyStr = "aa11";
    string valueStr = "111";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), 4, valueStr.c_str(), 3), SOFTBUS_OK);
    string keyStr2 = "aa22";
    string valueStr2 = "222";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr2.c_str(), 4, valueStr2.c_str(), 3), SOFTBUS_OK);
    string keyPrefix = "aa";
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyPrefix.c_str(), 2), SOFTBUS_OK);
    dbId++;
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyStr.c_str(), MAX_STRING_LEN + 1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyStr.c_str(), MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyPtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetDBData
 * @tc.desc: LnnGetDBData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGet001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    LnnUnRegisterDataChangeListener(dbId);
    LnnUnRegisterDataChangeListener(dbId + 1);
    dbId = g_dbId;
    LnnUnRegisterDataChangeListener(dbId);
    string keyStr = "aaa";
    string valueStr = "aaa";
    char *value = nullptr;
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), 3, valueStr.c_str(), 3), SOFTBUS_OK);
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), 3, &value), SOFTBUS_OK);
    SoftBusFree(value);
    value = nullptr;
    dbId++;
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, &value), SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, &value), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), MAX_STRING_LEN + 1, &value), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), MIN_STRING_LEN - 1, &value), SOFTBUS_INVALID_PARAM);
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnGetDBData(dbId, keyPtr, MIN_STRING_LEN - 1, &value), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnSubcribeKvStoreService
 * @tc.desc: LnnSubcribeKvStoreService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnSubcribeKvStoreService001, TestSize.Level1)
{
    int32_t lnnSubcribeKvStoreRet = LnnSubcribeKvStoreService();
    EXPECT_EQ(lnnSubcribeKvStoreRet, SOFTBUS_OK);
}

/*
 * @tc.name: LnnCreateKvAdapter_InvalidDbId
 * @tc.desc: Test LnnCreateKvAdapter with dbId being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCreateKvAdapter_InvalidDbId, TestSize.Level1)
{
    int32_t *dbId = nullptr;
    const char *appId = "validAppId";
    int32_t appIdLen = strlen(appId);
    const char *storeId = "validStoreId";
    int32_t storeIdLen = strlen(storeId);
    int32_t ret = LnnCreateKvAdapter(dbId, appId, appIdLen, storeId, storeIdLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCreateKvAdapter_InvalidAppId
 * @tc.desc: Test LnnCreateKvAdapter with appId being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCreateKvAdapter_InvalidAppId, TestSize.Level1)
{
    int32_t dbId;
    const char *appId = nullptr;
    int32_t appIdLen = 10; // Valid length
    const char *storeId = "validStoreId";
    int32_t storeIdLen = strlen(storeId);
    int32_t ret = LnnCreateKvAdapter(&dbId, appId, appIdLen, storeId, storeIdLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCreateKvAdapter_InvalidAppIdLen_LessThanMin
 * @tc.desc: Test LnnCreateKvAdapter with appIdLen being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCreateKvAdapter_InvalidAppIdLen_LessThanMin, TestSize.Level1)
{
    int32_t dbId;
    const char *appId = "validAppId";
    int32_t appIdLen = MIN_STRING_LEN - 1; // Less than MIN_STRING_LEN
    const char *storeId = "validStoreId";
    int32_t storeIdLen = strlen(storeId);
    int32_t ret = LnnCreateKvAdapter(&dbId, appId, appIdLen, storeId, storeIdLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCreateKvAdapter_InvalidAppIdLen_GreaterThanMax
 * @tc.desc: Test LnnCreateKvAdapter with appIdLen being greater than MAX_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCreateKvAdapter_InvalidAppIdLen_GreaterThanMax, TestSize.Level1)
{
    int32_t dbId;
    const char *appId = "validAppId";
    int32_t appIdLen = MAX_STRING_LEN + 1; // Greater than MAX_STRING_LEN
    const char *storeId = "validStoreId";
    int32_t storeIdLen = strlen(storeId);
    int32_t ret = LnnCreateKvAdapter(&dbId, appId, appIdLen, storeId, storeIdLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCreateKvAdapter_InvalidStoreId
 * @tc.desc: Test LnnCreateKvAdapter with storeId being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCreateKvAdapter_InvalidStoreId, TestSize.Level1)
{
    int32_t dbId;
    const char *appId = "validAppId";
    int32_t appIdLen = strlen(appId);
    const char *storeId = nullptr;
    int32_t storeIdLen = 10; // Valid length
    int32_t ret = LnnCreateKvAdapter(&dbId, appId, appIdLen, storeId, storeIdLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCreateKvAdapter_InvalidStoreIdLen_LessThanMin
 * @tc.desc: Test LnnCreateKvAdapter with storeIdLen being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCreateKvAdapter_InvalidStoreIdLen_LessThanMin, TestSize.Level1)
{
    int32_t dbId;
    const char *appId = "validAppId";
    int32_t appIdLen = strlen(appId);
    const char *storeId = "validStoreId";
    int32_t storeIdLen = MIN_STRING_LEN - 1; // Less than MIN_STRING_LEN
    int32_t ret = LnnCreateKvAdapter(&dbId, appId, appIdLen, storeId, storeIdLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCreateKvAdapter_InvalidStoreIdLen_GreaterThanMax
 * @tc.desc: Test LnnCreateKvAdapter with storeIdLen being greater than MAX_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCreateKvAdapter_InvalidStoreIdLen_GreaterThanMax, TestSize.Level1)
{
    int32_t dbId;
    const char *appId = "validAppId";
    int32_t appIdLen = strlen(appId);
    const char *storeId = "validStoreId";
    int32_t storeIdLen = MAX_STRING_LEN + 1; // Greater than MAX_STRING_LEN
    int32_t ret = LnnCreateKvAdapter(&dbId, appId, appIdLen, storeId, storeIdLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPutDBData_InvalidKey
 * @tc.desc: Test LnnPutDBData with key being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData_InvalidKey, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = nullptr;
    int32_t keyLen = 10;
    const char *value = "validValue";
    int32_t valueLen = strlen(value);
    int32_t ret = LnnPutDBData(dbId, key, keyLen, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPutDBData_KeyLen_LessThanMin
 * @tc.desc: Test LnnPutDBData with keyLen being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData_KeyLen_LessThanMin, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = MIN_STRING_LEN - 1;
    const char *value = "validValue";
    int32_t valueLen = strlen(value);
    int32_t ret = LnnPutDBData(dbId, key, keyLen, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPutDBData_KeyLen_GreaterThanMax
 * @tc.desc: Test LnnPutDBData with keyLen being greater than MAX_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData_KeyLen_GreaterThanMax, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = MAX_STRING_LEN + 1;
    const char *value = "validValue";
    int32_t valueLen = strlen(value);
    int32_t ret = LnnPutDBData(dbId, key, keyLen, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPutDBData_InvalidValue
 * @tc.desc: Test LnnPutDBData with value being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData_InvalidValue, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = strlen(key);
    const char *value = nullptr;
    int32_t valueLen = 10;
    int32_t ret = LnnPutDBData(dbId, key, keyLen, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPutDBData_ValueLen_LessThanMin
 * @tc.desc: Test LnnPutDBData with valueLen being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData_ValueLen_LessThanMin, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = strlen(key);
    const char *value = "validValue";
    int32_t valueLen = MIN_STRING_LEN - 1;
    int32_t ret = LnnPutDBData(dbId, key, keyLen, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPutDBData_ValueLen_GreaterThanMax
 * @tc.desc: Test LnnPutDBData with valueLen being greater than MAX_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData_ValueLen_GreaterThanMax, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = strlen(key);
    const char *value = "validValue";
    int32_t valueLen = MAX_STRING_LEN + 1;
    int32_t ret = LnnPutDBData(dbId, key, keyLen, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnPutDBData_Dbid_LessThanMin
 * @tc.desc: Test LnnPutDBData with dbid being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    const char *key = "validKey";
    int32_t keyLen = strlen(key);
    const char *value = "validValue";
    int32_t valueLen = strlen(value);
    int32_t ret = LnnPutDBData(dbId, key, keyLen, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBData_InvalidKey
 * @tc.desc: Test LnnDeleteDBData with key being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBData_InvalidKey, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = nullptr;
    int32_t keyLen = 10;
    int32_t ret = LnnDeleteDBData(dbId, key, keyLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBData_KeyLen_LessThanMin
 * @tc.desc: Test LnnDeleteDBData with keyLen being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBData_KeyLen_LessThanMin, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = MIN_STRING_LEN - 1;
    int32_t ret = LnnDeleteDBData(dbId, key, keyLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBData_KeyLen_GreaterThanMax
 * @tc.desc: Test LnnDeleteDBData with keyLen being greater than MAX_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBData_KeyLen_GreaterThanMax, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = MAX_STRING_LEN + 1;
    int32_t ret = LnnDeleteDBData(dbId, key, keyLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBData_Dbid_LessThanMin
 * @tc.desc: Test LnnDeleteDBData with dbid being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBData_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    const char *key = "validKey";
    int32_t keyLen = strlen(key);
    int32_t ret = LnnDeleteDBData(dbId, key, keyLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetDBData_InvalidValue
 * @tc.desc: Test LnnGetDBData with value being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_InvalidValue, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = strlen(key);
    char **value = nullptr;
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetDBData_InvalidKey
 * @tc.desc: Test LnnGetDBData with key being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_InvalidKey, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = nullptr;
    int32_t keyLen = 10;
    char testValue[] = "test_value";
    char *value[] = { testValue, testValue, testValue };
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetDBData_KeyLen_LessThanMin
 * @tc.desc: Test LnnGetDBData with keyLen being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_KeyLen_LessThanMin, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = MIN_STRING_LEN - 1;
    char testValue[] = "test_value";
    char *value[] = { testValue, testValue, testValue };
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetDBData_KeyLen_GreaterThanMax
 * @tc.desc: Test LnnGetDBData return SOFTBUS_INVALID_PARAM
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_KeyLen_GreaterThanMax, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = MAX_STRING_LEN + 1;
    char testValue[] = "test_value";
    char *value[] = { testValue, testValue, testValue };
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetDBData_Dbid_LessThanMin
 * @tc.desc: Test LnnGetDBData return SOFTBUS_INVALID_PARAM
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    const char *key = "validKey";
    int32_t keyLen = strlen(key);
    char testValue[] = "test_value";
    char *value[] = { testValue, testValue, testValue };
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBDataByPrefix_InvalidKeyPrefix
 * @tc.desc: Test LnnDeleteDBDataByPrefix with keyPrefix being nullptr
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBDataByPrefix_InvalidKeyPrefix, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *keyPrefix = nullptr;
    int32_t keyPrefixLen = 10;
    int32_t ret = LnnDeleteDBDataByPrefix(dbId, keyPrefix, keyPrefixLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBDataByPrefix_KeyPrefixLen_LessThanMin
 * @tc.desc: Test LnnDeleteDBDataByPrefix with keyPrefixLen being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBDataByPrefix_KeyPrefixLen_LessThanMin, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *keyPrefix = "validKeyPrefix";
    int32_t keyPrefixLen = MIN_STRING_LEN - 1;
    int32_t ret = LnnDeleteDBDataByPrefix(dbId, keyPrefix, keyPrefixLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBDataByPrefix_KeyPrefixLen_GreaterThanMax
 * @tc.desc: Test LnnDeleteDBDataByPrefix with keyPrefixLen being greater than MAX_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBDataByPrefix_KeyPrefixLen_GreaterThanMax, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *keyPrefix = "validKeyPrefix";
    int32_t keyPrefixLen = MAX_STRING_LEN + 1;
    int32_t ret = LnnDeleteDBDataByPrefix(dbId, keyPrefix, keyPrefixLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBDataByPrefix_Dbid_LessThanMin
 * @tc.desc: Test LnnDeleteDBDataByPrefix with dbid being less than MIN_STRING_LEN
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBDataByPrefix_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    const char *keyPrefix = "validKeyPrefix";
    int32_t keyPrefixLen = strlen(keyPrefix);
    int32_t ret = LnnDeleteDBDataByPrefix(dbId, keyPrefix, keyPrefixLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCloudSync_Dbid_LessThanMin
 * @tc.desc: Test LnnCloudSync with dbId being less than MIN_DBID_COUNT
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCloudSync_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    int32_t ret = LnnCloudSync(dbId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnSetCloudAbilityInner_Dbid_LessThanMin
 * @tc.desc: Test LnnSetCloudAbilityInner with dbId being less than MIN_DBID_COUNT
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnSetCloudAbilityInner_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    const bool isEnableCloud = true;
    int32_t ret = LnnSetCloudAbilityInner(dbId, isEnableCloud);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCloudSync001
 * @tc.desc: LnnCloudSync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCloudSync001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->isCloudSyncEnabled = IsCloudSyncEnabled;
    int32_t dbId = g_dbId;
    NiceMock<LnnKvAdapterWrapperInterfaceMock> LnnKvAdapterWrapperMock;
    EXPECT_CALL(LnnKvAdapterWrapperMock, IsCloudSyncEnabled).WillOnce(Return(true));
    int32_t lnnCloudRet = LnnCloudSync(dbId);
    EXPECT_EQ(lnnCloudRet, SOFTBUS_KV_CLOUD_SYNC_FAIL);
    lnnCloudRet = LnnCloudSync(dbId + 1);
    EXPECT_EQ(lnnCloudRet, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCloudSync002
 * @tc.desc: test LnnCloudSync param invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCloudSync002, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    ASSERT_TRUE(pfnLnnEnhanceFuncList != nullptr);
    pfnLnnEnhanceFuncList->isCloudSyncEnabled = IsCloudSyncEnabled;
    int32_t dbId = g_dbId;
    constexpr int32_t idOffset = 1;
    int32_t lnnCloudRet = LnnCloudSync(dbId + idOffset);
    EXPECT_EQ(lnnCloudRet, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnCloudSync004
 * @tc.desc: LnnCloudSync cloud_disabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCloudSync004, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    int32_t createRet = LnnCreateKvAdapter(&dbId, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    EXPECT_EQ(createRet, SOFTBUS_OK);
    std::shared_ptr<KVAdapter> kvAdapter = nullptr;
    kvAdapter = std::make_shared<KVAdapter>(APP_ID, STORE_ID);
    int32_t initRet = kvAdapter->Init();
    EXPECT_EQ(initRet, SOFTBUS_OK);
    NiceMock<LnnKvAdapterWrapperInterfaceMock> LnnKvAdapterWrapperMock;
    EXPECT_CALL(LnnKvAdapterWrapperMock, FindKvStorePtr).WillRepeatedly(Return(kvAdapter));
    int32_t lnnCloudRet = LnnCloudSync(dbId);
    EXPECT_EQ(lnnCloudRet, SOFTBUS_KV_CLOUD_DISABLED);
}

/*
 * @tc.name: LnnDeleteDBDataByNull
 * @tc.desc: LnnDeleteDBData Invalid Param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBDataByNull, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *keyStr = nullptr;
    string valueStr = "ccc";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr, 3, valueStr.c_str(), 3), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetDBDataByKey
 * @tc.desc: LnnGetDBData  Invalid Param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBDataByKey, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *keyStr = nullptr;
    char *value = nullptr;
    EXPECT_EQ(LnnGetDBData(dbId, keyStr, 3, &value), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDeleteDBDataByInvalid
 * @tc.desc: LnnDeleteDBDataByPrefix  Invalid Param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteDBDataByInvalid, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyPtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS