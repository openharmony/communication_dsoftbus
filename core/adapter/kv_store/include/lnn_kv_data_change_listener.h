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

#ifndef LNN_KV_DATA_CHANGE_LISTENER_H
#define LNN_KV_DATA_CHANGE_LISTENER_H

#include <vector>

#include "kvstore_observer.h"

namespace OHOS {
class KvDataChangeListener : public DistributedKv::KvStoreObserver {
public:
    KvDataChangeListener();
    ~KvDataChangeListener();

    void OnChange(const DistributedKv::DataOrigin& origin, Keys &&keys) override;

private:
    std::vector<DistributedKv::Entry> ConvertCloudChangeDataToEntries(const std::vector<std::string> &keys);
    void HandleAddChange(const std::vector<DistributedKv::Entry> &insertRecords);
    void HandleUpdateChange(const std::vector<DistributedKv::Entry> &updateRecords);
    void HandleDeleteChange(const std::vector<DistributedKv::Entry> &deleteRecords);
};
} // namespace OHOS
#endif // LNN_KV_DATA_CHANGE_LISTENER_H
