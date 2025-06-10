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

#include "wifi_direct_executor_factory.h"

#include "conn_log.h"
namespace OHOS::SoftBus {
WifiDirectExecutorFactory& WifiDirectExecutorFactory::GetInstance()
{
    static WifiDirectExecutorFactory instance;
    return instance;
}

std::shared_ptr<WifiDirectExecutor> WifiDirectExecutorFactory::NewExecutor(const std::string &remoteDeviceId,
    WifiDirectScheduler &scheduler, std::shared_ptr<WifiDirectProcessor> &processor, bool active)
{
    std::shared_ptr<WifiDirectExecutor> executor = (executorGenerator_ == nullptr) ?
        std::make_shared<WifiDirectExecutor>(remoteDeviceId, scheduler, processor, active) :
        executorGenerator_(remoteDeviceId, scheduler, processor, active);
    executor->Start();
    return executor;
}

void WifiDirectExecutorFactory::Register(ExecutorGenerator generator)
{
    executorGenerator_ = std::move(generator);
}
} // namespace OHOS::SoftBus