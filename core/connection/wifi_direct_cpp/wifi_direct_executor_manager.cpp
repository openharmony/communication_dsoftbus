/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "wifi_direct_executor_manager.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
std::shared_ptr<WifiDirectExecutor> WifiDirectExecutorManager::Find(const std::string &remoteId)
{
    for (const auto &node : executors_) {
        if (remoteId == node.remoteDeviceId_ || remoteId == node.remoteMac_) {
            CONN_LOGI(CONN_WIFI_DIRECT, "find remoteId=%{public}s, remoteDeviceId=%{public}s, remoteMac=%{public}s",
                GetDumpString(remoteId).c_str(), WifiDirectAnonymizeDeviceId(node.remoteDeviceId_).c_str(),
                WifiDirectAnonymizeMac(node.remoteMac_).c_str());
            return node.executor_;
        }
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "not find remoteId=%{public}s", GetDumpString(remoteId).c_str());
    return nullptr;
}

void WifiDirectExecutorManager::Insert(const std::string &remoteId, const std::shared_ptr<WifiDirectExecutor> &executor)
{
    std::string remoteDeviceId;
    std::string remoteMac;
    if (WifiDirectUtils::IsDeviceId(remoteId)) {
        remoteDeviceId = remoteId;
        remoteMac = WifiDirectUtils::RemoteDeviceIdToMac(remoteId);
    } else {
        remoteDeviceId = WifiDirectUtils::RemoteMacToDeviceId(remoteId);
        remoteMac = remoteId;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteId=%{public}s, remoteDeviceId=%{public}s, remoteMac=%{public}s",
        GetDumpString(remoteId).c_str(), WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str(),
        WifiDirectAnonymizeMac(remoteMac).c_str());
    executors_.push_back({remoteDeviceId, remoteMac, executor});
}

void WifiDirectExecutorManager::Erase(const std::string &remoteId)
{
    for (auto it = executors_.begin(); it != executors_.end();) {
        if (remoteId == it->remoteDeviceId_ || remoteId == it->remoteMac_) {
            CONN_LOGI(CONN_WIFI_DIRECT, "erase remoteId=%{public}s, remoteDeviceId=%{public}s, remoteMac=%{public}s",
                GetDumpString(remoteId).c_str(), WifiDirectAnonymizeDeviceId(it->remoteDeviceId_).c_str(),
                WifiDirectAnonymizeMac(it->remoteMac_).c_str());
            it = executors_.erase(it);
        } else {
            it++;
        }
    }
}

size_t WifiDirectExecutorManager::Size()
{
    return executors_.size();
}

std::string WifiDirectExecutorManager::GetDumpString(const std::string &remoteId)
{
    if (WifiDirectUtils::IsDeviceId(remoteId)) {
        return WifiDirectAnonymizeDeviceId(remoteId);
    }
    return WifiDirectAnonymizeMac(remoteId);
}

void WifiDirectExecutorManager::Dump(std::list<std::shared_ptr<ProcessorSnapshot>> &snapshots)
{
    for (const auto &node : executors_) {
        if (node.executor_ != nullptr) {
            node.executor_->Dump(snapshots);
        }
    }
}
}
