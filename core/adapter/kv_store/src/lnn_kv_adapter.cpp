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

#include <cinttypes>
#include <functional>
#include <mutex>
#include <unistd.h>
#include <vector>

#include "anonymizer.h"
#include "lnn_kv_adapter.h"
#include "lnn_log.h"
#include "lnn_parameter_utils.h"
#include "softbus_error_code.h"

#include "datetime_ex.h"
namespace OHOS {
using namespace OHOS::DistributedKv;
namespace {
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int32_t MAX_INIT_RETRY_TIMES = 3;
constexpr int32_t INIT_RETRY_SLEEP_INTERVAL = 100 * 1000; // 100ms
constexpr int32_t MAX_MAP_SIZE = 10000;
const char *DATABASE_DIR = "/data/service/el1/public/database/dsoftbus";
} // namespace

KVAdapter::KVAdapter(const std::string &appId, const std::string &storeId)
{
    this->appId_.appId = appId;
    this->storeId_.storeId = storeId;
    LNN_LOGI(LNN_LEDGER, "KVAdapter Constructor Success, appId: %{public}s, storeId: %{public}s", appId.c_str(),
        storeId.c_str());
}

KVAdapter::~KVAdapter()
{
    LNN_LOGI(LNN_LEDGER, "KVAdapter Destruction!");
}

int32_t KVAdapter::Init()
{
    LNN_LOGI(LNN_LEDGER, "Init kvAdapter, storeId: %{public}s", storeId_.storeId.c_str());
    int32_t tryTimes = MAX_INIT_RETRY_TIMES;
    int64_t beginTime = GetTickCount();
    while (tryTimes > 0) {
        DistributedKv::Status status = GetKvStorePtr();
        if (kvStorePtr_ && status == DistributedKv::Status::SUCCESS) {
            int64_t endTime = GetTickCount();
            LNN_LOGI(LNN_LEDGER, "Init KvStorePtr Success, spend %{public}" PRId64 " ms", endTime - beginTime);
            return SOFTBUS_OK;
        }
        LNN_LOGI(LNN_LEDGER, "CheckKvStore, left times: %{public}d, status: %{public}d", tryTimes, status);
        if (status == DistributedKv::Status::SECURITY_LEVEL_ERROR) {
            LNN_LOGE(LNN_LEDGER, "This db security level error, remove and rebuild it");
            DeleteKvStore();
        }
        if (status == DistributedKv::Status::STORE_META_CHANGED) {
            LNN_LOGE(LNN_LEDGER, "This db meta changed, remove and rebuild it");
            DeleteKvStore();
        }
        usleep(INIT_RETRY_SLEEP_INTERVAL);
        tryTimes--;
    }
    return SOFTBUS_KV_DB_INIT_FAIL;
}

int32_t KVAdapter::DeInit()
{
    LNN_LOGI(LNN_LEDGER, "DBAdapter DeInit");
    DeleteKvStorePtr();
    return SOFTBUS_OK;
}

int32_t KVAdapter::RegisterDataChangeListener(
    const std::shared_ptr<DistributedKv::KvStoreObserver> &dataChangeListener)
{
    LNN_LOGI(LNN_LEDGER, "Register db data change listener");
    if (!IsCloudSyncEnabled()) {
        LNN_LOGW(LNN_LEDGER, "not support cloud sync");
        return SOFTBUS_KV_CLOUD_DISABLED;
    }
    if (dataChangeListener == nullptr) {
        LNN_LOGE(LNN_LEDGER, "dataChangeListener is null");
        return SOFTBUS_INVALID_PARAM;
    }
    this->dataChangeListener_ = dataChangeListener;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvStoragePtr_ is null");
            return SOFTBUS_KV_DB_PTR_NULL;
        }
        DistributedKv::Status status =
            kvStorePtr_->SubscribeKvStore(DistributedKv::SubscribeType::SUBSCRIBE_TYPE_CLOUD, dataChangeListener_);
        if (status != DistributedKv::Status::SUCCESS) {
            LNN_LOGE(LNN_LEDGER, "Register db data change listener failed, ret=%{public}d", status);
            return SOFTBUS_KV_REGISTER_DATA_LISTENER_FAILED;
        }
    }
    return SOFTBUS_OK;
}

int32_t KVAdapter::UnRegisterDataChangeListener()
{
    LNN_LOGI(LNN_LEDGER, "UnRegister db data change listener");
    if (!IsCloudSyncEnabled()) {
        LNN_LOGW(LNN_LEDGER, "not support cloud sync");
        return SOFTBUS_KV_CLOUD_DISABLED;
    }
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvStoragePtr_ is null");
            return SOFTBUS_KV_DB_PTR_NULL;
        }
        DistributedKv::Status status =
            kvStorePtr_->UnSubscribeKvStore(DistributedKv::SubscribeType::SUBSCRIBE_TYPE_CLOUD, dataChangeListener_);
        if (status != DistributedKv::Status::SUCCESS) {
            LNN_LOGE(LNN_LEDGER, "UnRegister db data change listener failed, ret=%{public}d", status);
            return SOFTBUS_KV_UNREGISTER_DATA_LISTENER_FAILED;
        }
    }
    return SOFTBUS_OK;
}

int32_t KVAdapter::DeleteDataChangeListener()
{
    LNN_LOGI(LNN_LEDGER, "Delete DataChangeListener!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        dataChangeListener_ = nullptr;
    }
    return SOFTBUS_OK;
}

int32_t KVAdapter::Put(const std::string &key, const std::string &value)
{
    if (key.empty() || key.size() > MAX_STRING_LEN || value.empty() || value.size() > MAX_STRING_LEN) {
        LNN_LOGE(LNN_LEDGER, "Param is invalid!");
        return SOFTBUS_INVALID_PARAM;
    }
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvDBPtr is null!");
            return SOFTBUS_KV_DB_PTR_NULL;
        }
        DistributedKv::Key kvKey(key);
        DistributedKv::Value oldV;
        if (kvStorePtr_->Get(kvKey, oldV) == DistributedKv::Status::SUCCESS && oldV.ToString() == value) {
            LNN_LOGI(LNN_LEDGER, "The key-value pair already exists.");
            return SOFTBUS_OK;
        }
        DistributedKv::Value kvValue(value);
        status = kvStorePtr_->Put(kvKey, kvValue);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "Put kv to db failed, ret=%{public}d", status);
        return SOFTBUS_KV_PUT_DB_FAIL;
    }
    LNN_LOGI(LNN_LEDGER, "KVAdapter Put succeed");
    return SOFTBUS_OK;
}

int32_t KVAdapter::PutBatch(const std::map<std::string, std::string> &values)
{
    if (values.empty() || values.size() > MAX_MAP_SIZE) {
        LNN_LOGE(LNN_LEDGER, "Param is invalid!");
        return SOFTBUS_INVALID_PARAM;
    }
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvDBPtr is null!");
            return SOFTBUS_KV_DB_PTR_NULL;
        }
        std::vector<DistributedKv::Entry> entries;
        DistributedKv::Value oldV;
        DistributedKv::Key kvKey;
        for (auto item : values) {
            kvKey = item.first;
            if (kvStorePtr_->Get(kvKey, oldV) == DistributedKv::Status::SUCCESS && oldV.ToString() == item.second) {
                continue;
            }
            Entry entry;
            entry.key = kvKey;
            entry.value = item.second;
            entries.emplace_back(entry);
        }
        if (entries.empty()) {
            LNN_LOGI(LNN_LEDGER, "All key-value pair already exists.");
            return SOFTBUS_OK;
        }
        status = kvStorePtr_->PutBatch(entries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "PutBatch kv to db failed, ret=%{public}d", status);
        return SOFTBUS_KV_PUT_DB_FAIL;
    }
    LNN_LOGI(LNN_LEDGER, "KVAdapter PutBatch succeed");
    return SOFTBUS_OK;
}

int32_t KVAdapter::Delete(const std::string &key)
{
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvDBPtr is null!");
            return SOFTBUS_KV_DB_PTR_NULL;
        }
        DistributedKv::Key kvKey(key);
        status = kvStorePtr_->Delete(kvKey);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "Delete kv by key failed!");
        return SOFTBUS_KV_DEL_DB_FAIL;
    }
    LNN_LOGI(LNN_LEDGER, "Delete kv by key success!");
    return SOFTBUS_OK;
}

int32_t KVAdapter::DeleteByPrefix(const std::string &keyPrefix)
{
    LNN_LOGI(LNN_LEDGER, "call");
    if (keyPrefix.empty() || keyPrefix.size() > MAX_STRING_LEN) {
        LNN_LOGE(LNN_LEDGER, "Param is invalid!");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(kvAdapterMutex_);
    if (kvStorePtr_ == nullptr) {
        LNN_LOGE(LNN_LEDGER, "kvStoragePtr_ is null");
        return SOFTBUS_KV_DB_PTR_NULL;
    }
    // if prefix is empty, get all entries.
    DistributedKv::Key allEntryKeyPrefix(keyPrefix);
    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != DistributedKv::Status::SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "GetEntries failed, ret=%{public}d", status);
        return SOFTBUS_KV_DEL_DB_FAIL;
    }
    std::vector<DistributedKv::Key> keys;
    for (auto item : allEntries) {
        keys.push_back(item.key);
    }
    status = kvStorePtr_->DeleteBatch(keys);
    if (status != DistributedKv::Status::SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "DeleteBatch failed, ret=%{public}d", status);
        return SOFTBUS_KV_DEL_DB_FAIL;
    }
    LNN_LOGI(LNN_LEDGER, "DeleteByPrefix succeed");
    return SOFTBUS_OK;
}

int32_t KVAdapter::Get(const std::string &key, std::string &value)
{
    char *anonyKey = nullptr;
    Anonymize(key.c_str(), &anonyKey);
    LNN_LOGI(LNN_LEDGER, "Get data by key: %{public}s", AnonymizeWrapper(anonyKey));
    AnonymizeFree(anonyKey);
    DistributedKv::Key kvKey(key);
    DistributedKv::Value kvValue;
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvStoragePtr_ is null");
            return SOFTBUS_KV_DB_PTR_NULL;
        }
        status = kvStorePtr_->Get(kvKey, kvValue);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        anonyKey = nullptr;
        Anonymize(key.c_str(), &anonyKey);
        LNN_LOGE(LNN_LEDGER, "Get data from kv failed, key=%{public}s", AnonymizeWrapper(anonyKey));
        AnonymizeFree(anonyKey);
        return SOFTBUS_KV_GET_DB_FAIL;
    }
    value = kvValue.ToString();
    LNN_LOGD(LNN_LEDGER, "Get succeed");
    return SOFTBUS_OK;
}

DistributedKv::Status KVAdapter::GetKvStorePtr()
{
    LNN_LOGI(LNN_LEDGER, "called");
    DistributedKv::Options options = {
        .encrypt = true,
        .autoSync = false,
        .isPublic = true,
        .securityLevel = DistributedKv::SecurityLevel::S1,
        .area = 1,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .baseDir = DATABASE_DIR,
        .cloudConfig = { .enableCloud = false, .autoSync = true }
    };
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        status = kvDataMgr_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    }
    return status;
}

int32_t KVAdapter::DeleteKvStore()
{
    LNN_LOGI(LNN_LEDGER, "Delete KvStore!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        kvDataMgr_.CloseKvStore(appId_, storeId_);
        kvDataMgr_.DeleteKvStore(appId_, storeId_, DATABASE_DIR);
    }
    return SOFTBUS_OK;
}

int32_t KVAdapter::DeleteKvStorePtr()
{
    LNN_LOGI(LNN_LEDGER, "Delete KvStore Ptr!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        kvStorePtr_ = nullptr;
    }
    return SOFTBUS_OK;
}

int32_t KVAdapter::CloudSync()
{
    LNN_LOGI(LNN_LEDGER, "call!");
    if (!IsCloudSyncEnabled()) {
        LNN_LOGW(LNN_LEDGER, "not support cloud sync");
        return SOFTBUS_KV_CLOUD_DISABLED;
    }
    std::function<void(DistributedKv::ProgressDetail &&)> callback = CloudSyncCallback;
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvDBPtr is null!");
            return SOFTBUS_KV_DB_PTR_NULL;
        }
        status = kvStorePtr_->CloudSync(callback);
    }
    if (status == DistributedKv::Status::CLOUD_DISABLED) {
        LNN_LOGE(LNN_LEDGER, "cloud sync disabled, ret=%{public}d", status);
        return SOFTBUS_KV_CLOUD_DISABLED;
    }
    if (status != DistributedKv::Status::SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "cloud sync failed, ret=%{public}d", status);
        return SOFTBUS_KV_CLOUD_SYNC_FAIL;
    }
    LNN_LOGI(LNN_LEDGER, "cloud sync ok, ret=%{public}d", status);
    return SOFTBUS_OK;
}

void KVAdapter::CloudSyncCallback(DistributedKv::ProgressDetail &&detail)
{
    auto code = detail.code;
    auto progress = detail.progress;
    if (progress == DistributedKv::Progress::SYNC_FINISH && code == DistributedKv::Status::SUCCESS) {
        LNN_LOGI(LNN_LEDGER,
            "cloud sync succeed, upload.total=%{public}u, upload.success=%{public}u, "
            "upload.failed=%{public}u, upload.untreated=%{public}u, download.total=%{public}u, "
            "download.success=%{public}u, download.failed=%{public}u, download.untreated=%{public}u",
            detail.details.upload.total, detail.details.upload.success, detail.details.upload.failed,
            detail.details.upload.untreated, detail.details.download.total, detail.details.download.success,
            detail.details.download.failed, detail.details.download.untreated);
    }
    if (progress == DistributedKv::Progress::SYNC_FINISH && code != DistributedKv::Status::SUCCESS) {
        LNN_LOGI(LNN_LEDGER,
            "cloud sync failed, code=%{public}d, upload.total=%{public}u, upload.success=%{public}u, "
            "upload.failed=%{public}u, upload.untreated=%{public}u, download.total=%{public}u, "
            "download.success=%{public}u, download.failed=%{public}u, download.untreated=%{public}u",
            code, detail.details.upload.total, detail.details.upload.success, detail.details.upload.failed,
            detail.details.upload.untreated, detail.details.download.total, detail.details.download.success,
            detail.details.download.failed, detail.details.download.untreated);
    }
}

int32_t KVAdapter::DeRegisterDataChangeListener()
{
    LNN_LOGI(LNN_LEDGER, "call!");
    int32_t ret = UnRegisterDataChangeListener();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "UnRegisterDataChangeListener failed, ret=%{public}d", ret);
        return ret;
    }
    DeleteDataChangeListener();
    LNN_LOGI(LNN_LEDGER, "DeRegisterDataChangeListener success");
    return SOFTBUS_OK;
}

int32_t KVAdapter::SetCloudAbility(const bool isEnableCloud)
{
    LNN_LOGI(LNN_LEDGER, "call! isEnableCloud=%{public}d", isEnableCloud);
    DistributedKv::CloudConfig cloudConfig = {
        .enableCloud = isEnableCloud,
        .autoSync = true
    };
    DistributedKv::StoreConfig storeConfig = {
        .cloudConfig = cloudConfig
    };
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvDBPtr is null!");
            return SOFTBUS_KV_DB_PTR_NULL;
        }
        status = kvStorePtr_->SetConfig(storeConfig);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "SetCloudAbility failed, ret=%{public}d", status);
        return SOFTBUS_KV_SET_CLOUD_ABILITY_FAILED;
    }
    LNN_LOGI(LNN_LEDGER, "SetCloudAbility success, isEnableCloud=%{public}d", isEnableCloud);
    return SOFTBUS_OK;
}
} // namespace OHOS
