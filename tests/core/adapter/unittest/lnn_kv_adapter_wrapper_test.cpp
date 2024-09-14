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

#include "gtest/gtest.h"
#include "lnn_kv_adapter_wrapper.h"
#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include <cstdint>
#include <string>
#include <cstring>

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace {
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int32_t MIN_STRING_LEN = 1;
constexpr int32_t APP_ID_LEN = 8;
constexpr int32_t STORE_ID_LEN = 19;
const std::string APP_ID = "dsoftbus";
const std::string STORE_ID = "dsoftbus_kv_db_test";
}
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
}

void KVAdapterWrapperTest::TearDownTestCase(void)
{
    LnnDestroyKvAdapter(g_dbId);
}

void KVAdapterWrapperTest::SetUp()
{
}

void KVAdapterWrapperTest::TearDown()
{
}

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
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN),
        SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN + 1),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
    char *valuePtr = nullptr;
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valuePtr, MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN + 1, valuePtr, MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MIN_STRING_LEN - 1, valuePtr, MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
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

} // namespace OHOS
