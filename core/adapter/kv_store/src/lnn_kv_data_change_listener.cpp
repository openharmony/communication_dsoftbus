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

#include "lnn_kv_data_change_listener.h"

#include <cinttypes>
#include <cstring>
#include <thread>

#include "anonymizer.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_kv_adapter_wrapper.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"

namespace OHOS {
namespace {
constexpr int32_t MAX_DB_RECORD_SIZE = 10000;
} // namespace

KvDataChangeListener::KvDataChangeListener(const std::string &appId, const std::string &storeId)
{
    LNN_LOGI(LNN_LEDGER, "construct!");
    this->appId_ = appId;
    this->storeId_ = storeId;
}

KvDataChangeListener::~KvDataChangeListener()
{
    LNN_LOGI(LNN_LEDGER, "destruct!");
}

void KvDataChangeListener::OnChange(const DistributedKv::DataOrigin &origin, Keys &&keys)
{
    auto autoSyncTask = [this, origin, keys]() {
        LNN_LOGI(LNN_LEDGER, "Cloud data change.store=%{public}s", origin.store.c_str());
        std::vector<DistributedKv::Entry> insertRecords = ConvertCloudChangeDataToEntries(keys[ChangeOp::OP_INSERT]);
        if (!insertRecords.empty() && insertRecords.size() <= MAX_DB_RECORD_SIZE) {
            SelectChangeType(insertRecords);
        }

        std::vector<DistributedKv::Entry> updateRecords = ConvertCloudChangeDataToEntries(keys[ChangeOp::OP_UPDATE]);
        if (!updateRecords.empty() && updateRecords.size() <= MAX_DB_RECORD_SIZE) {
            SelectChangeType(updateRecords);
        }

        std::vector<std::string> delKeys = keys[ChangeOp::OP_DELETE];
        if (!delKeys.empty() && delKeys.size() <= MAX_DB_RECORD_SIZE) {
            std::vector<DistributedKv::Entry> deleteRecords;
            for (const auto &key : delKeys) {
                DistributedKv::Entry entry;
                DistributedKv::Key kvKey(key);
                entry.key = kvKey;
                deleteRecords.emplace_back(entry);
            }
            HandleDeleteChange(deleteRecords);
        }
    };
    std::thread(autoSyncTask).detach();
}

std::vector<DistributedKv::Entry> KvDataChangeListener::ConvertCloudChangeDataToEntries(
    const std::vector<std::string> &keys)
{
    int32_t dbId = 0;
    char *anonyKey = nullptr;
    LnnCreateKvAdapter(&dbId, appId_.c_str(), appId_.length(), storeId_.c_str(), storeId_.length());
    LNN_LOGI(LNN_LEDGER, "call! dbId=%{public}d", dbId);
    std::vector<DistributedKv::Entry> entries;
    if (keys.empty()) {
        LNN_LOGE(LNN_LEDGER, "keys empty");
        LnnDestroyKvAdapter(dbId);
        return entries;
    }
    for (const auto &key : keys) {
        char *value = nullptr;
        if (LnnGetDBData(dbId, key.c_str(), key.length(), &value) != SOFTBUS_OK) {
            anonyKey = nullptr;
            Anonymize(key.c_str(), &anonyKey);
            LNN_LOGE(LNN_LEDGER, "get value failed, key = %{public}s", anonyKey);
            AnonymizeFree(anonyKey);
            continue;
        }
        DistributedKv::Entry entry;
        entry.key = key;
        entry.value = value;
        entries.emplace_back(entry);
        SoftBusFree(value);
    }
    LnnDestroyKvAdapter(dbId);
    return entries;
}

void KvDataChangeListener::HandleAddChange(const std::vector<DistributedKv::Entry> &insertRecords)
{
    int32_t insertSize = static_cast<int32_t>(insertRecords.size());
    LNN_LOGI(LNN_LEDGER, "Handle kv data add change! insertSize=%{public}d", insertSize);
    char **keys = (char **)SoftBusCalloc(insertSize * sizeof(char *));
    if (keys == nullptr) {
        LNN_LOGE(LNN_LEDGER, "keys malloc failed");
        return;
    }
    char **values = (char **)SoftBusCalloc(insertSize * sizeof(char *));
    if (values == nullptr) {
        LNN_LOGE(LNN_LEDGER, "values malloc failed");
        SoftBusFree(keys);
        return;
    }

    int32_t i = 0;
    for (const auto &item : insertRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        keys[i] = strdup(dbKey.c_str());
        values[i] = strdup(dbValue.c_str());
        ++i;
    }
    LnnDBDataAddChangeSyncToCache(const_cast<const char **>(keys), const_cast<const char **>(values), insertSize);
}

void KvDataChangeListener::HandleUpdateChange(const std::vector<DistributedKv::Entry> &updateRecords)
{
    LNN_LOGI(LNN_LEDGER, "Handle kv data update change! updateSize=%{public}zu", updateRecords.size());
    for (const auto &item : updateRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        LnnDBDataChangeSyncToCache(dbKey.c_str(), dbValue.c_str(), ChangeType::DB_UPDATE);
    }
}

void KvDataChangeListener::HandleDeleteChange(const std::vector<DistributedKv::Entry> &deleteRecords)
{
    LNN_LOGI(LNN_LEDGER, "Handle kv data delete change! deleteSize=%{public}zu", deleteRecords.size());
    for (const auto &item : deleteRecords) {
        std::string dbKey = item.key.ToString();
        char *dbValue = nullptr;
        LnnDBDataChangeSyncToCache(dbKey.c_str(), dbValue, ChangeType::DB_DELETE);
    }
}

void KvDataChangeListener::SelectChangeType(const std::vector<DistributedKv::Entry>& records)
{
    LNN_LOGI(LNN_LEDGER, "call! recordsSize=%{public}zu", records.size());
    auto innerRecords(records);
    while (!innerRecords.empty()) {
        std::vector<DistributedKv::Entry> entries;
        entries.emplace_back(innerRecords.front());
        std::string keyPrefix = GetKeyPrefix(innerRecords.front().key.ToString());
        innerRecords.erase(innerRecords.begin());
        for (auto iter = innerRecords.begin(); iter != innerRecords.end(); ++iter) {
            if (keyPrefix == GetKeyPrefix(iter->key.ToString())) {
                entries.emplace_back(*iter);
                innerRecords.erase(iter);
                --iter;
            }
        }
        if (entries.size() == CLOUD_SYNC_INFO_SIZE) {
            LNN_LOGI(LNN_LEDGER, "add! entriesSize=%{public}zu", entries.size());
            HandleAddChange(entries);
        } else {
            LNN_LOGI(LNN_LEDGER, "update! entriesSize=%{public}zu", entries.size());
            HandleUpdateChange(entries);
        }
    }
}

std::string KvDataChangeListener::GetKeyPrefix(const std::string& key)
{
    std::size_t pos1 = key.find('#');
    if (pos1 == std::string::npos) {
        return "";
    }
    std::size_t pos2 = key.find('#', pos1 + 1);
    if (pos2 == std::string::npos) {
        return "";
    }
    return key.substr(0, pos2);
}
} // namespace OHOS
