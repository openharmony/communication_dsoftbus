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

#include "softbus_errcode.h"
#include "anonymizer.h"
#include "lnn_log.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_kv_adapter_wrapper.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
namespace {
    const std::string APP_ID = "dsoftbus";
    const std::string STORE_ID = "dsoftbus_kv_db";
    constexpr int32_t APP_ID_LEN = 8;
    constexpr int32_t STORE_ID_LEN = 14;
    constexpr int32_t MAX_DB_RECORD_SIZE = 10000;
}

KvDataChangeListener::KvDataChangeListener()
{
    LNN_LOGI(LNN_LEDGER, "construct!");
}

KvDataChangeListener::~KvDataChangeListener()
{
    LNN_LOGI(LNN_LEDGER, "destruct!");
}

void KvDataChangeListener::OnChange(const DistributedKv::DataOrigin &origin, Keys &&keys)
{
    LNN_LOGI(LNN_LEDGER, "Cloud data change.store=%{public}s", origin.store.c_str());
    std::vector<DistributedKv::Entry> insertRecords = ConvertCloudChangeDataToEntries(keys[ChangeOp::OP_INSERT]);
    if (!insertRecords.empty() && insertRecords.size() <= MAX_DB_RECORD_SIZE) {
        HandleAddChange(insertRecords);
    }

    std::vector<DistributedKv::Entry> updateRecords = ConvertCloudChangeDataToEntries(keys[ChangeOp::OP_UPDATE]);
    if (!updateRecords.empty() && updateRecords.size() <= MAX_DB_RECORD_SIZE) {
        HandleUpdateChange(updateRecords);
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
}

std::vector<DistributedKv::Entry> KvDataChangeListener::ConvertCloudChangeDataToEntries(
    const std::vector<std::string> &keys)
{
    LNN_LOGI(LNN_LEDGER, "call!");
    int32_t dbId = 0;
    char *anonyKey = nullptr;
    LnnCreateKvAdapter(&dbId, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    std::vector<DistributedKv::Entry> entries;
    if (keys.empty()) {
        LNN_LOGE(LNN_LEDGER, "keys empty");
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

void KvDataChangeListener::HandleAddChange(const std::vector<DistributedKv::Entry>& insertRecords)
{
    LNN_LOGI(LNN_LEDGER, "Handle kv data add change!");
    int32_t insertSize = insertRecords.size();
    char **keys = (char **)SoftBusCalloc(insertSize * sizeof(char *));
    if (keys == nullptr) {
        LNN_LOGE(LNN_LEDGER, "malloc failed");
        return;
    }
    char **values = (char **)SoftBusCalloc(insertSize * sizeof(char *));
    if (values == nullptr) {
        LNN_LOGE(LNN_LEDGER, "malloc failed");
        SoftBusFree(keys);
        return;
    }
    
    for (int32_t i = 0; i < insertSize; ++i) {
        std::string dbKey = insertRecords[i].key.ToString();
        std::string dbValue = insertRecords[i].value.ToString();
        keys[i] = strdup(dbKey.c_str());
        values[i] = strdup(dbValue.c_str());
    }
    LnnDBDataAddChangeSyncToCache(const_cast<const char**>(keys), const_cast<const char**>(values), insertSize);
}

void KvDataChangeListener::HandleUpdateChange(const std::vector<DistributedKv::Entry>& updateRecords)
{
    LNN_LOGI(LNN_LEDGER, "Handle kv data update change!");
    for (const auto& item : updateRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        LnnDBDataChangeSyncToCache(dbKey.c_str(), dbValue.c_str(), ChangeType::DB_UPDATE);
    }
}

void KvDataChangeListener::HandleDeleteChange(const std::vector<DistributedKv::Entry>& deleteRecords)
{
    LNN_LOGI(LNN_LEDGER, "Handle kv data delete change!");
    for (const auto& item : deleteRecords) {
        std::string dbKey = item.key.ToString();
        char *dbValue = nullptr;
        LnnDBDataChangeSyncToCache(dbKey.c_str(), dbValue, ChangeType::DB_DELETE);
    }
}
} // namespace OHOS
