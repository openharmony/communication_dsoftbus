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
#include "softbus_error_code.h"

namespace OHOS {
namespace {
std::mutex g_LnnKvDataChangeListenerMutex;
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
        LNN_LOGI(LNN_LEDGER, "Cloud data change.store=%{public}s, update size=%{public}zu, add size=%{public}zu",
            origin.store.c_str(), keys[ChangeOp::OP_UPDATE].size(), keys[ChangeOp::OP_INSERT].size());
        std::vector<std::string> changeKeys;
        changeKeys.insert(changeKeys.end(), keys[ChangeOp::OP_INSERT].begin(), keys[ChangeOp::OP_INSERT].end());
        changeKeys.insert(changeKeys.end(), keys[ChangeOp::OP_UPDATE].begin(), keys[ChangeOp::OP_UPDATE].end());
        std::vector<DistributedKv::Entry> changeRecords = ConvertCloudChangeDataToEntries(changeKeys);

        LNN_LOGI(LNN_LEDGER, "Handle kv data change! changeRecords=%{public}zu", changeRecords.size());
        for (const auto &item : changeRecords) {
            std::string dbKey = item.key.ToString();
            std::string dbValue = item.value.ToString();
            LnnDBDataChangeSyncToCacheInner(dbKey.c_str(), dbValue.c_str());
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
        return entries;
    }
    for (const auto &key : keys) {
        char *value = nullptr;
        if (LnnGetDBData(dbId, key.c_str(), key.length(), &value) != SOFTBUS_OK) {
            anonyKey = nullptr;
            Anonymize(key.c_str(), &anonyKey);
            LNN_LOGE(LNN_LEDGER, "get value failed, key = %{public}s", AnonymizeWrapper(anonyKey));
            AnonymizeFree(anonyKey);
            continue;
        }
        DistributedKv::Entry entry;
        entry.key = key;
        entry.value = value;
        entries.emplace_back(entry);
        SoftBusFree(value);
    }
    return entries;
}

} // namespace OHOS
