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

#include <string>

#include "lnn_kv_adapter.h"
#include "lnn_kv_data_change_listener.h"
#include "softbus_error_code.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {

namespace {
const std::string APP_ID = "dsoftbus";
const std::string STORE_ID = "dsoftbus_kv_db_test";
shared_ptr<KVAdapter> kvStore = nullptr;
shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver = nullptr;
shared_ptr<KvDataChangeListener> kvDataChangeListener = nullptr;
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int32_t MAX_MAP_SIZE = 10000;
const std::string DATABASE_DIR = "/data/service/el1/public/database/dsoftbus";
} // namespace

class KVAdapterTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void KVAdapterTest::SetUpTestCase(void)
{
    kvStore = make_shared<KVAdapter>(APP_ID, STORE_ID);
}

void KVAdapterTest::TearDownTestCase(void) { }

void KVAdapterTest::SetUp()
{
    kvStore->Init();
}

void KVAdapterTest::TearDown()
{
    kvStore->DeInit();
}

/*
 * @tc.name: Init001
 * @tc.desc: Initialization operation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Init001, TestSize.Level1)
{
    kvStore->DeInit();
    EXPECT_EQ(SOFTBUS_OK, kvStore->Init());
}

/*
 * @tc.name: UnInit001
 * @tc.desc: Deinitialization operation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, UnInit001, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_OK, kvStore->DeInit());
}

/*
 * @tc.name: Put001
 * @tc.desc: Single key-value storage operation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Put001, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_OK, kvStore->Put("key1", "value1"));
}

/*
 * @tc.name: Put002
 * @tc.desc: Single key-value storage fails due to invalid parameters including empty key and empty value
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Put002, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->Put("", "value1"));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->Put("key1", ""));
}

/*
 * @tc.name: Put003
 * @tc.desc: Single key-value storage fails because kv database pointer is null
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Put003, TestSize.Level1)
{
    kvStore->DeInit();
    EXPECT_EQ(SOFTBUS_KV_DB_PTR_NULL, kvStore->Put("key1", "value1"));
}

/*
 * @tc.name: Put004
 * @tc.desc: Verify single key-value storage results for different key-value combinations
 *           legal combinations succeed while overlong key-value and empty value fail
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Put004, TestSize.Level1)
{
    string key = "key";
    string value = "value";
    EXPECT_EQ(SOFTBUS_OK, kvStore->Put(key, value));

    for (int32_t i = 0; i < MAX_STRING_LEN + 5; i++) {
        value += 'a';
    }
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->Put(key, value));

    value = "";
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->Put(key, value));

    for (int32_t i = 0; i < MAX_STRING_LEN + 5; i++) {
        key += 'a';
    }
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->Put(key, value));

    key = "";
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->Put(key, value));
}

/*
 * @tc.name: PutBatch001
 * @tc.desc: Batch key-value storage operation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, PutBatch001, TestSize.Level1)
{
    map<string, string> values;
    values.insert(pair<string, string>("key2", "value2"));
    values.insert(pair<string, string>("key3", "value3"));
    EXPECT_EQ(SOFTBUS_OK, kvStore->PutBatch(values));
}

/*
 * @tc.name: PutBatch002
 * @tc.desc: Batch key-value storage fails due to invalid parameters including
 *           empty map and map exceeding maximum capacity
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, PutBatch002, TestSize.Level1)
{
    map<string, string> values;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->PutBatch(values));

    for (int32_t i = 0; i < MAX_MAP_SIZE + 5; i++) {
        values[to_string(i)] = "value";
    }
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->PutBatch(values));
}

/*
 * @tc.name: PutBatch003
 * @tc.desc: Batch key-value storage fails because kv database pointer is null
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, PutBatch003, TestSize.Level1)
{
    map<string, string> values;
    values.insert(pair<string, string>("key1", "value1"));
    values.insert(pair<string, string>("key2", "value2"));
    kvStore->DeInit();
    EXPECT_EQ(SOFTBUS_KV_DB_PTR_NULL, kvStore->PutBatch(values));
}

/*
 * @tc.name: Delete001
 * @tc.desc: Single key-value deletion operation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Delete001, TestSize.Level1)
{
    kvStore->Put("key4", "value4");
    EXPECT_EQ(SOFTBUS_OK, kvStore->Delete("key4"));
}

/*
 * @tc.name: Delete002
 * @tc.desc: Single key-value deletion fails because kv database pointer is null
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Delete002, TestSize.Level1)
{
    kvStore->Put("key5", "value5");
    kvStore->DeInit();
    EXPECT_EQ(SOFTBUS_KV_DB_PTR_NULL, kvStore->Delete("key5"));
}

/*
 * @tc.name: DeleteByPrefix001
 * @tc.desc: Key-value deletion by prefix operation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteByPrefix001, TestSize.Level1)
{
    kvStore->Put("key6", "value6");
    kvStore->Put("key7", "value7");
    EXPECT_EQ(SOFTBUS_OK, kvStore->DeleteByPrefix("key"));
}

/*
 * @tc.name: DeleteByPrefix002
 * @tc.desc: Key-value deletion by prefix fails because kv database pointer is null
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteByPrefix002, TestSize.Level1)
{
    kvStore->Put("key8", "value8");
    kvStore->Put("key9", "value9");
    kvStore->DeInit();
    EXPECT_EQ(SOFTBUS_KV_DB_PTR_NULL, kvStore->DeleteByPrefix("key"));
}

/*
 * @tc.name: DeleteByPrefix003
 * @tc.desc: Key-value deletion by prefix fails because prefix string is empty
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteByPrefix003, TestSize.Level1)
{
    std::string keyPrefix = "";
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->DeleteByPrefix(keyPrefix));
}

/*
 * @tc.name: DeleteByPrefix004
 * @tc.desc: DeleteByPrefix failed, keyPrefix length exceeds MAX_STRING_LEN
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteByPrefix004, TestSize.Level1)
{
    std::string keyPrefix(MAX_STRING_LEN + 1, 'a');
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, kvStore->DeleteByPrefix(keyPrefix));
}

/*
 * @tc.name: Get001
 * @tc.desc: Single key-value query operation succeeds and verifies the correctness of returned value
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Get001, TestSize.Level1)
{
    kvStore->Put("key10", "value10");
    string value;
    EXPECT_EQ(SOFTBUS_OK, kvStore->Get("key10", value));
    EXPECT_EQ("value10", value);
}

/*
 * @tc.name: Get002
 * @tc.desc: Single key-value query fails because kv database pointer is null
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Get002, TestSize.Level1)
{
    kvStore->Put("key11", "value11");
    kvStore->DeInit();
    string value;
    EXPECT_EQ(SOFTBUS_KV_DB_PTR_NULL, kvStore->Get("key11", value));
}

/*
 * @tc.name: SetCloudAbility001
 * @tc.desc: Cloud synchronization capability setting operation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, SetCloudAbility001, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_OK, kvStore->SetCloudAbility(true));
}

/*
 * @tc.name: SetCloudAbility002
 * @tc.desc: Cloud synchronization capability setting fails because kv database pointer is null
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, SetCloudAbility002, TestSize.Level1)
{
    kvStore->DeInit();
    EXPECT_EQ(SOFTBUS_KV_DB_PTR_NULL, kvStore->SetCloudAbility(true));
}

/*
 * @tc.name: RegisterDataChangeListener001
 * @tc.desc: Data change listener registration fails because cloud synchronization function is disabled
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, RegisterDataChangeListener001, TestSize.Level1)
{
    kvStoreObserver = std::make_shared<DistributedKv::KvStoreObserver>();
    EXPECT_NE(SOFTBUS_OK, kvStore->RegisterDataChangeListener(kvStoreObserver));
}

/*
 * @tc.name: DeRegisterDataChangeListener001
 * @tc.desc: Data change listener deregistration fails because cloud synchronization function is disabled
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeRegisterDataChangeListener001, TestSize.Level1)
{
    EXPECT_NE(SOFTBUS_OK, kvStore->DeRegisterDataChangeListener());
}

/*
 * @tc.name: CloudSync001
 * @tc.desc: Cloud synchronization operation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, CloudSync001, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_KV_CLOUD_DISABLED, kvStore->CloudSync());
}

/*
 * @tc.name: CloudSyncCallback002
 * @tc.desc: Cloud synchronization callback execution fails with error status code
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, CloudSyncCallback002, TestSize.Level1)
{
    DistributedKv::ProgressDetail detail;
    detail.code = DistributedKv::Status::ERROR;
    detail.progress = DistributedKv::Progress::SYNC_FINISH;
    EXPECT_NO_FATAL_FAILURE(kvStore->CloudSyncCallback(std::move(detail)));
}

/*
 * @tc.name: DeleteDataChangeListener001
 * @tc.desc: Callbacks related to data change listener deletion execute normally without fatal errors
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteDataChangeListener001, TestSize.Level1)
{
    DistributedKv::ProgressDetail detail;
    detail.code = DistributedKv::Status::SUCCESS;
    detail.progress = DistributedKv::Progress::SYNC_FINISH;
    EXPECT_NO_FATAL_FAILURE(kvStore->CloudSyncCallback(std::move(detail)));
    detail.code = DistributedKv::Status::TIME_OUT;
    EXPECT_NO_FATAL_FAILURE(kvStore->CloudSyncCallback(std::move(detail)));
}

/*
 * @tc.name: DeleteKvStore001
 * @tc.desc: KV storage instance deletion operation returns success
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteKvStore001, TestSize.Level1)
{
    const std::string appId = "appId";
    const std::string storeId = "storeId";
    KVAdapter(appId, storeId);
    EXPECT_EQ(SOFTBUS_OK, kvStore->DeleteKvStore());
}

/*
 * @tc.name: OnChange001
 * @tc.desc: Data change callback function executes normally without fatal errors
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, OnChange001, TestSize.Level1)
{
    KvDataChangeListener::Keys changeKeys;
    changeKeys[0].push_back("opinsert");
    changeKeys[1].push_back("opupdate");
    changeKeys[2].push_back("opupdate");

    DistributedKv::DataOrigin origin;
    origin.store = "opinsert";
    std::vector<std::string> id;
    id.push_back("opinsert");
    id.push_back("opupdate");
    origin.id = id;
    const std::string appId = "appId";
    const std::string storeId = "storeId";
    KvDataChangeListener kvDataChangeListener(appId, storeId);
    EXPECT_NO_FATAL_FAILURE(kvDataChangeListener.OnChange(origin, std::move(changeKeys)));
}
} // namespace OHOS
