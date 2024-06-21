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

#ifndef LNN_KV_ADAPTER_H
#define LNN_KV_ADAPTER_H

#include <map>
#include <memory>
#include <string>

#include "distributed_kv_data_manager.h"
#include "kvstore_observer.h"

namespace OHOS {
class KVAdapter {
public:
    KVAdapter(const std::string &appId, const std::string &storeId);
    virtual ~KVAdapter();

    int32_t Init();
    int32_t DeInit();
    int32_t Put(const std::string &key, const std::string &value);
    int32_t PutBatch(const std::map<std::string, std::string> &values);
    int32_t Delete(const std::string &key);
    int32_t DeleteByPrefix(const std::string &keyPrefix);
    int32_t Get(const std::string &key, std::string &value);
    int32_t DeleteKvStore();
    int32_t CloudSync();
    int32_t SetCloudAbility(const bool isEnableCloud);
    int32_t RegisterDataChangeListener(const std::shared_ptr<DistributedKv::KvStoreObserver> &dataChangeListener);
    int32_t DeRegisterDataChangeListener();
    static void CloudSyncCallback(DistributedKv::ProgressDetail &&detail);

private:
    DistributedKv::Status GetKvStorePtr();
    int32_t DeleteKvStorePtr();
    int32_t UnRegisterDataChangeListener();
    int32_t DeleteDataChangeListener();

private:
    DistributedKv::AppId appId_;
    DistributedKv::StoreId storeId_;
    DistributedKv::DistributedKvDataManager kvDataMgr_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreObserver> dataChangeListener_ = nullptr;
    std::mutex kvAdapterMutex_;
};

} // namespace OHOS

#endif // LNN_KV_ADAPTER_H
