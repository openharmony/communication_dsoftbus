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

#ifndef WIFI_DIRECT_SCHEDULER_FACTORY_H
#define WIFI_DIRECT_SCHEDULER_FACTORY_H

#include <memory>
#include <wifi_direct_scheduler.h>

namespace OHOS::SoftBus {
class WifiDirectScheduler;
class WifiDirectSchedulerFactory {
public:
    static WifiDirectSchedulerFactory& GetInstance()
    {
        static WifiDirectSchedulerFactory instance;
        return instance;
    }

    WifiDirectScheduler& GetScheduler()
    {
        if (scheduler_ == nullptr) {
            return WifiDirectScheduler::GetInstance();
        }
        return *scheduler_;
    }

    void Register(const std::shared_ptr<WifiDirectScheduler> &scheduler)
    {
        scheduler_ = scheduler;
    }

private:
    std::shared_ptr<WifiDirectScheduler> scheduler_ = nullptr;
};
}
#endif
