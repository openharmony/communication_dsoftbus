/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <string>

#include "lnn_kv_adapter_wrapper.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "gtest/gtest.h"

using namespace std;
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

    LnnDestroyKvAdapter(g_dbId); // g_dbId = 1
}

void KVAdapterWrapperTest::SetUp() { }

void KVAdapterWrapperTest::TearDown() { }

/**
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

/**
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

/**
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

/**
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

/**
 * @tc.name: LnnCloudSync
 * @tc.desc: LnnCloudSync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCloudSync001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    int32_t lnnCloudRet = LnnCloudSync(dbId);
    EXPECT_EQ(lnnCloudRet, SOFTBUS_ERR);

    lnnCloudRet = LnnCloudSync(dbId + 1);
    EXPECT_EQ(lnnCloudRet, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnSubcribeKvStoreService
 * @tc.desc: LnnSubcribeKvStoreService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnSubcribeKvStoreService001, TestSize.Level1)
{
    bool lnnSubcribeKvStoreRet = LnnSubcribeKvStoreService();
    EXPECT_EQ(lnnSubcribeKvStoreRet, true);
}

/**
 * @tc.name: LnnDestroyKvAdapter
 * @tc.desc: LnnDestroyKvAdapter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDestroy001, TestSize.Level1)
{
    int32_t dbId;
    int32_t createRet = LnnCreateKvAdapter(&dbId, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    EXPECT_EQ(createRet, SOFTBUS_OK);
    EXPECT_EQ(LnnDestroyKvAdapter(dbId), SOFTBUS_OK);
}

/**
 * @tc.name: LnnCreateKvAdapter_InvalidDbId
 * @tc.desc: Test LnnCreateKvAdapter with dbId being nullptr.
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

/**
 * @tc.name: LnnCreateKvAdapter_InvalidAppId
 * @tc.desc: Test LnnCreateKvAdapter with appId being nullptr.
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

/**
 * @tc.name: LnnCreateKvAdapter_InvalidAppIdLen_LessThanMin
 * @tc.desc: Test LnnCreateKvAdapter with appIdLen being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnCreateKvAdapter_InvalidAppIdLen_GreaterThanMax
 * @tc.desc: Test LnnCreateKvAdapter with appIdLen being greater than MAX_STRING_LEN.
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

/**
 * @tc.name: LnnCreateKvAdapter_InvalidStoreId
 * @tc.desc: Test LnnCreateKvAdapter with storeId being nullptr.
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

/**
 * @tc.name: LnnCreateKvAdapter_InvalidStoreIdLen_LessThanMin
 * @tc.desc: Test LnnCreateKvAdapter with storeIdLen being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnCreateKvAdapter_InvalidStoreIdLen_GreaterThanMax
 * @tc.desc: Test LnnCreateKvAdapter with storeIdLen being greater than MAX_STRING_LEN.
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

/**
 * @tc.name: LnnDestroyKvAdapter_Dbid_LessThanMin
 * @tc.desc: Test LnnDestroyKvAdapter with dbId being less than MIN_DBID_COUNT.
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDestroyKvAdapter_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    int32_t ret = LnnDestroyKvAdapter(dbId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnPutDBData_InvalidKey
 * @tc.desc: Test LnnPutDBData with key being nullptr.
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

/**
 * @tc.name: LnnPutDBData_KeyLen_LessThanMin
 * @tc.desc: Test LnnPutDBData with keyLen being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnPutDBData_KeyLen_GreaterThanMax
 * @tc.desc: Test LnnPutDBData with keyLen being greater than MAX_STRING_LEN.
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

/**
 * @tc.name: LnnPutDBData_InvalidValue
 * @tc.desc: Test LnnPutDBData with value being nullptr.
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

/**
 * @tc.name: LnnPutDBData_ValueLen_LessThanMin
 * @tc.desc: Test LnnPutDBData with valueLen being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnPutDBData_ValueLen_GreaterThanMax
 * @tc.desc: Test LnnPutDBData with valueLen being greater than MAX_STRING_LEN.
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

/**
 * @tc.name: LnnPutDBData_Dbid_LessThanMin
 * @tc.desc: Test LnnPutDBData with dbid being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnDeleteDBData_InvalidKey
 * @tc.desc: Test LnnDeleteDBData with key being nullptr.
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

/**
 * @tc.name: LnnDeleteDBData_KeyLen_LessThanMin
 * @tc.desc: Test LnnDeleteDBData with keyLen being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnDeleteDBData_KeyLen_GreaterThanMax
 * @tc.desc: Test LnnDeleteDBData with keyLen being greater than MAX_STRING_LEN.
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

/**
 * @tc.name: LnnDeleteDBData_Dbid_LessThanMin
 * @tc.desc: Test LnnDeleteDBData with dbid being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnGetDBData_InvalidValue
 * @tc.desc: Test LnnGetDBData with value being nullptr.
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

/**
 * @tc.name: LnnGetDBData_InvalidKey
 * @tc.desc: Test LnnGetDBData with key being nullptr.
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_InvalidKey, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = nullptr;
    int32_t keyLen = 10;
    const int32_t num = 3;
    char **value = new (std::nothrow) char *[num];
    if (value == nullptr) {
        return;
    }
    std::string strValue0 = "value";
    value[0] = new (std::nothrow) char[strValue0.size() + 1];
    if (value[0] == nullptr) {
        delete[] value;
        return;
    }
    std::copy_n(strValue0.c_str(), strValue0.size(), value[0]);
    value[0][strValue0.size()] = '\0';
    std::string strValue1 = "test";
    value[1] = new (std::nothrow) char[strValue1.size() + 1];
    if (value[1] == nullptr) {
        delete[] value[0];
        delete[] value;
        return;
    }
    std::copy_n(strValue1.c_str(), strValue1.size(), value[1]);
    value[1][strValue1.size()] = '\0';
    std::string strValue2 = "char";
    value[2] = new (std::nothrow) char[strValue2.size() + 1];
    if (value[2] == nullptr) {
        delete[] value[1];
        delete[] value[0];
        delete[] value;
        return;
    }
    std::copy_n(strValue2.c_str(), strValue2.size(), value[2]);
    value[2][strValue2.size()] = '\0';
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    for (int32_t i = 0; i < num; ++i) {
        delete[] value[i];
    }
    delete[] value;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnGetDBData_KeyLen_LessThanMin
 * @tc.desc: Test LnnGetDBData with keyLen being less than MIN_STRING_LEN.
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_KeyLen_LessThanMin, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = MIN_STRING_LEN - 1;
    const int32_t num = 3;
    char **value = new (std::nothrow) char *[num];
    if (value == nullptr) {
        return;
    }
    std::string strValue0 = "value";
    value[0] = new (std::nothrow) char[strValue0.size() + 1];
    if (value[0] == nullptr) {
        delete[] value;
        return;
    }
    std::copy_n(strValue0.c_str(), strValue0.size(), value[0]);
    value[0][strValue0.size()] = '\0';
    std::string strValue1 = "test";
    value[1] = new (std::nothrow) char[strValue1.size() + 1];
    if (value[1] == nullptr) {
        delete[] value[0];
        delete[] value;
        return;
    }
    std::copy_n(strValue1.c_str(), strValue1.size(), value[1]);
    value[1][strValue1.size()] = '\0';
    std::string strValue2 = "char";
    value[2] = new (std::nothrow) char[strValue2.size() + 1];
    if (value[2] == nullptr) {
        delete[] value[1];
        delete[] value[0];
        delete[] value;
        return;
    }
    std::copy_n(strValue2.c_str(), strValue2.size(), value[2]);
    value[2][strValue2.size()] = '\0';
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    for (int32_t i = 0; i < num; ++i) {
        delete[] value[i];
    }
    delete[] value;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnGetDBData_KeyLen_GreaterThanMax
 * @tc.desc: Test LnnGetDBData with keyLen being greater than MAX_STRING_LEN.
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_KeyLen_GreaterThanMax, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    const char *key = "validKey";
    int32_t keyLen = MAX_STRING_LEN + 1;
    const int32_t num = 3;
    char **value = new (std::nothrow) char *[num];
    if (value == nullptr) {
        return;
    }
    std::string strValue0 = "value";
    value[0] = new (std::nothrow) char[strValue0.size() + 1];
    if (value[0] == nullptr) {
        delete[] value;
        return;
    }
    std::copy_n(strValue0.c_str(), strValue0.size(), value[0]);
    value[0][strValue0.size()] = '\0';
    std::string strValue1 = "test";
    value[1] = new (std::nothrow) char[strValue1.size() + 1];
    if (value[1] == nullptr) {
        delete[] value[0];
        delete[] value;
        return;
    }
    std::copy_n(strValue1.c_str(), strValue1.size(), value[1]);
    value[1][strValue1.size()] = '\0';
    std::string strValue2 = "char";
    value[2] = new (std::nothrow) char[strValue2.size() + 1];
    if (value[2] == nullptr) {
        delete[] value[1];
        delete[] value[0];
        delete[] value;
        return;
    }
    std::copy_n(strValue2.c_str(), strValue2.size(), value[2]);
    value[2][strValue2.size()] = '\0';
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    for (int32_t i = 0; i < num; ++i) {
        delete[] value[i];
    }
    delete[] value;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnGetDBData_Dbid_LessThanMin
 * @tc.desc: Test LnnGetDBData with dbid being less than MIN_STRING_LEN.
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGetDBData_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    const char *key = "validKey";
    int32_t keyLen = strlen(key);
    const int32_t num = 3;
    char **value = new (std::nothrow) char *[num];
    if (value == nullptr) {
        return;
    }
    std::string strValue0 = "value";
    value[0] = new (std::nothrow) char[strValue0.size() + 1];
    if (value[0] == nullptr) {
        delete[] value;
        return;
    }
    std::copy_n(strValue0.c_str(), strValue0.size(), value[0]);
    value[0][strValue0.size()] = '\0';
    std::string strValue1 = "test";
    value[1] = new (std::nothrow) char[strValue1.size() + 1];
    if (value[1] == nullptr) {
        delete[] value[0];
        delete[] value;
        return;
    }
    std::copy_n(strValue1.c_str(), strValue1.size(), value[1]);
    value[1][strValue1.size()] = '\0';
    std::string strValue2 = "char";
    value[2] = new (std::nothrow) char[strValue2.size() + 1];
    if (value[2] == nullptr) {
        delete[] value[1];
        delete[] value[0];
        delete[] value;
        return;
    }
    std::copy_n(strValue2.c_str(), strValue2.size(), value[2]);
    value[2][strValue2.size()] = '\0';
    int32_t ret = LnnGetDBData(dbId, key, keyLen, value);
    for (int32_t i = 0; i < num; ++i) {
        delete[] value[i];
    }
    delete[] value;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnDeleteDBDataByPrefix_InvalidKeyPrefix
 * @tc.desc: Test LnnDeleteDBDataByPrefix with keyPrefix being nullptr.
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

/**
 * @tc.name: LnnDeleteDBDataByPrefix_KeyPrefixLen_LessThanMin
 * @tc.desc: Test LnnDeleteDBDataByPrefix with keyPrefixLen being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnDeleteDBDataByPrefix_KeyPrefixLen_GreaterThanMax
 * @tc.desc: Test LnnDeleteDBDataByPrefix with keyPrefixLen being greater than MAX_STRING_LEN.
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

/**
 * @tc.name: LnnDeleteDBDataByPrefix_Dbid_LessThanMin
 * @tc.desc: Test LnnDeleteDBDataByPrefix with dbid being less than MIN_STRING_LEN.
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

/**
 * @tc.name: LnnCloudSync_Dbid_LessThanMin
 * @tc.desc: Test LnnCloudSync with dbId being less than MIN_DBID_COUNT.
 * @tc.type: Functional Test
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnCloudSync_Dbid_LessThanMin, TestSize.Level1)
{
    int32_t dbId = MIN_DBID_COUNT - 1;
    int32_t ret = LnnCloudSync(dbId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnSetCloudAbilityInner_Dbid_LessThanMin
 * @tc.desc: Test LnnSetCloudAbilityInner with dbId being less than MIN_DBID_COUNT.
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

} // namespace OHOS
