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

#include "wifi_direct_scheduler_factory.h"
#include "conn_log.h"

namespace OHOS::SoftBus {
WifiDirectSchedulerFactory& WifiDirectSchedulerFactory::GetInstance()
{
    static WifiDirectSchedulerFactory instance;
    return instance;
}

WifiDirectScheduler& WifiDirectSchedulerFactory::GetScheduler()
{
    if (scheduler_ == nullptr) {
        return WifiDirectScheduler::GetInstance();
    }
    return *scheduler_;
}

void WifiDirectSchedulerFactory::Register(const std::shared_ptr<WifiDirectScheduler> &scheduler)
{
    scheduler_ = scheduler;
}
}