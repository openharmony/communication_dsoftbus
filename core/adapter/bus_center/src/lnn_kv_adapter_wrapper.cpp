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

#include <cstring>
#include <securec.h>
#include <string>

#include "lnn_kv_adapter_wrapper.h"
#include "lnn_device_info_recovery.h"
#include "lnn_kv_adapter.h"
#include "lnn_kv_data_change_listener.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "softbus_error_code.h"
#include "softbus_def.h"
#include "softbus_utils.h"
#include "iservice_registry.h"
#include "lnn_kv_store_launch_listener.h"
#include "system_ability_definition.h"

using namespace OHOS;
using namespace OHOS::DistributedKv;
namespace {
constexpr int32_t MIN_DBID_COUNT = 1;
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int32_t MIN_STRING_LEN = 1;
std::mutex g_kvAdapterWrapperMutex;
} // namespace

static int32_t g_dbId = 1;
static bool g_isSubscribed = false;
static std::map<int32_t, std::shared_ptr<OHOS::KVAdapter>> g_dbID2KvAdapter;
static std::shared_ptr<OHOS::KVAdapter> FindKvStorePtr(int32_t &dbId);

int32_t LnnCreateKvAdapter(int32_t *dbId, const char *appId, int32_t appIdLen, const char *storeId, int32_t storeIdLen)
{
    if (dbId == nullptr || appId == nullptr || appIdLen < MIN_STRING_LEN || appIdLen > MAX_STRING_LEN ||
        storeId == nullptr || storeIdLen < MIN_STRING_LEN || storeIdLen > MAX_STRING_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (!g_dbID2KvAdapter.empty()) {
            *dbId = g_dbID2KvAdapter.begin()->first;
            LNN_LOGI(LNN_LEDGER, "kvAdapter is exist, dbId=%{public}d", *dbId);
            return SOFTBUS_OK;
        }
    }
    std::string appIdStr(appId, appIdLen);
    std::string storeIdStr(storeId, storeIdLen);
    std::shared_ptr<KVAdapter> kvAdapter = nullptr;
    kvAdapter = std::make_shared<KVAdapter>(appIdStr, storeIdStr);
    int32_t initRet = kvAdapter->Init();
    if (initRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter init failed, ret=%{public}d", initRet);
        return initRet;
    }
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        *dbId = g_dbId;
        g_dbID2KvAdapter.insert(std::make_pair(g_dbId, kvAdapter));
        g_dbId++;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter init success, dbId=%{public}d", *dbId);
    return SOFTBUS_OK;
}

int32_t LnnDestroyKvAdapter(int32_t dbId)
{
    int32_t unInitRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        unInitRet = kvAdapter->DeInit();
    }
    if (unInitRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter unInit failed, ret=%{public}d", unInitRet);
        return unInitRet;
    }
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        g_dbID2KvAdapter.erase(dbId);
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter unInit success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

static std::shared_ptr<KVAdapter> FindKvStorePtr(int32_t &dbId)
{
    auto iter = g_dbID2KvAdapter.find(dbId);
    if (iter == g_dbID2KvAdapter.end()) {
        LNN_LOGE(LNN_LEDGER, "dbID is not exist, dbId=%{public}d", dbId);
        return nullptr;
    }
    return iter->second;
}

int32_t LnnPutDBData(int32_t dbId, const char *key, int32_t keyLen, const char *value, int32_t valueLen)
{
    int32_t putRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (key == nullptr || keyLen < MIN_STRING_LEN || keyLen > MAX_STRING_LEN || value == nullptr ||
            valueLen < MIN_STRING_LEN || valueLen > MAX_STRING_LEN || dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param, dbId=%{public}d", dbId);
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        std::string valueStr(value, valueLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        putRet = kvAdapter->Put(keyStr, valueStr);
    }
    if (putRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter put failed, ret=%{public}d", putRet);
        return putRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter put success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnDeleteDBData(int32_t dbId, const char *key, int32_t keyLen)
{
    int32_t deleteRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (key == nullptr || keyLen < MIN_STRING_LEN || keyLen > MAX_STRING_LEN || dbId < MIN_DBID_COUNT ||
            dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        deleteRet = kvAdapter->Delete(keyStr);
    }
    if (deleteRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter delete failed, ret=%{public}d", deleteRet);
        return deleteRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter delete success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnGetDBData(int32_t dbId, const char *key, int32_t keyLen, char **value)
{
    std::string valueStr;
    int32_t getRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (value == nullptr || key == nullptr || keyLen < MIN_STRING_LEN || keyLen > MAX_STRING_LEN ||
            dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        getRet = kvAdapter->Get(keyStr, valueStr);
    }
    if (getRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter get failed, ret=%{public}d", getRet);
        return getRet;
    }
    *value = strdup(valueStr.c_str());
    if (*value == nullptr) {
        LNN_LOGE(LNN_LEDGER, "strdup failed");
        return SOFTBUS_MALLOC_ERR;
    }
    LNN_LOGD(LNN_LEDGER, "kvAdapter get success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnDeleteDBDataByPrefix(int32_t dbId, const char *keyPrefix, int32_t keyPrefixLen)
{
    int32_t deleteRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (keyPrefix == nullptr || keyPrefixLen < MIN_STRING_LEN || keyPrefixLen > MAX_STRING_LEN ||
            dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyPrefixStr(keyPrefix, keyPrefixLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        deleteRet = kvAdapter->DeleteByPrefix(keyPrefixStr);
    }
    if (deleteRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter delete failed, ret=%{public}d", deleteRet);
        return deleteRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter delete success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnCloudSync(int32_t dbId)
{
    std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
    if (dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
        LNN_LOGE(LNN_LEDGER, "Invalid dbId ");
        return SOFTBUS_INVALID_PARAM;
    }
    auto kvAdapter = FindKvStorePtr(dbId);
    if (kvAdapter == nullptr) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
        return SOFTBUS_NOT_FIND;
    }
    return (kvAdapter->CloudSync());
}

void LnnRegisterDataChangeListener(int32_t dbId, const char *appId, int32_t appIdLen, const char *storeId,
    int32_t storeIdLen)
{
    std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
    if (dbId < MIN_DBID_COUNT || dbId >= g_dbId || appId == nullptr || appIdLen < MIN_STRING_LEN ||
        appIdLen > MAX_STRING_LEN || storeId == nullptr || storeIdLen < MIN_STRING_LEN ||
        storeIdLen > MAX_STRING_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return;
    }
    if (g_isSubscribed) {
        LNN_LOGI(LNN_LEDGER, "DataChangeListener is already registered");
        return;
    }
    std::string appIdStr(appId, appIdLen);
    std::string storeIdStr(storeId, storeIdLen);
    auto kvAdapter = FindKvStorePtr(dbId);
    if (kvAdapter == nullptr) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
        return;
    }
    int32_t status = kvAdapter->RegisterDataChangeListener(std::make_shared<KvDataChangeListener>(appIdStr,
        storeIdStr));
    if (status != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "RegisterDataChangeListener failed");
        return;
    }
    g_isSubscribed = true;
    LNN_LOGI(LNN_LEDGER, "RegisterDataChangeListener success");
}

void LnnUnRegisterDataChangeListener(int32_t dbId)
{
    std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
    if (dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
        LNN_LOGE(LNN_LEDGER, "Invalid dbId ");
        return;
    }
    auto kvAdapter = FindKvStorePtr(dbId);
    if (kvAdapter == nullptr) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
        return;
    }
    if (kvAdapter->DeRegisterDataChangeListener() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "DeRegisterDataChangeListener failed");
        return;
    }
    g_isSubscribed = false;
    LNN_LOGI(LNN_LEDGER, "DeRegisterDataChangeListener success");
}

bool LnnSubcribeKvStoreService(void)
{
    auto abilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityManager == nullptr) {
        LNN_LOGE(LNN_LEDGER, "abilityManager is nullptr");
        return false;
    }
    sptr<KvStoreStatusChangeListener> listener = new (std::nothrow) KvStoreStatusChangeListener();
    if (listener == nullptr) {
        LNN_LOGE(LNN_LEDGER, "failed to create listener");
        return false;
    }
    int32_t ret = abilityManager->SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, listener);
    if (ret != ERR_OK) {
        LNN_LOGE(LNN_LEDGER, "subscribe system ability failed, ret=%{public}d", ret);
        return false;
    }
    LNN_LOGI(LNN_LEDGER, "subscribe kv store service success");
    return true;
}

int32_t LnnSetCloudAbilityInner(int32_t dbId, const bool isEnableCloud)
{
    std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
    if (dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
        LNN_LOGE(LNN_LEDGER, "Invalid dbId ");
        return SOFTBUS_INVALID_PARAM;
    }
    auto kvAdapter = FindKvStorePtr(dbId);
    if (kvAdapter == nullptr) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
        return SOFTBUS_NOT_FIND;
    }
    return (kvAdapter->SetCloudAbility(isEnableCloud));
}
