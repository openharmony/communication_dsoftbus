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

#ifndef WIFI_DIRECT_EXECUTOR_MANAGER_H
#define WIFI_DIRECT_EXECUTOR_MANAGER_H

#include <list>
#include <mutex>
#include <tuple>
#include <memory>

#include "wifi_direct_executor.h"

namespace OHOS::SoftBus {
class WifiDirectExecutorManager {
public:
    WifiDirectExecutorManager() = default;
    ~WifiDirectExecutorManager() = default;

    std::shared_ptr<WifiDirectExecutor> Find(const std::string &remoteId);
    void Insert(const std::string &remoteId, const std::shared_ptr<WifiDirectExecutor> &executor);
    void Erase(const std::string &remoteId);
    size_t Size();
    void Dump(std::list<std::shared_ptr<ProcessorSnapshot>> &snapshots);

private:
    static std::string GetDumpString(const std::string &remoteId);

    struct Node {
        std::string remoteDeviceId_;
        std::string remoteMac_;
        std::shared_ptr<WifiDirectExecutor> executor_;
    };
    std::list<Node> executors_;
};
}
#endif
