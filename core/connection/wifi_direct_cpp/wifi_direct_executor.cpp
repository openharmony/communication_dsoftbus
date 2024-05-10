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
#include "wifi_direct_executor.h"

#include <utility>

#include "wifi_direct_scheduler.h"
#include "data/link_manager.h"
#include "event/wifi_direct_event_dispatcher.h"
#include "conn_log.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
WifiDirectExecutor::WifiDirectExecutor(const std::string &remoteDeviceId, WifiDirectScheduler &scheduler,
                                       std::shared_ptr<WifiDirectProcessor> &processor, bool active)
    : remoteDeviceId_(remoteDeviceId), scheduler_(scheduler), processor_(processor), active_(active)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s, active=%{public}d",
              WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str(), active_);
    std::thread thread(&WifiDirectExecutor::Run, this, processor_);
    thread_.swap(thread);
    thread_.detach();
}

WifiDirectExecutor::~WifiDirectExecutor()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str());
}

void WifiDirectExecutor::Run(std::shared_ptr<WifiDirectProcessor> processor)
{
    processor_ = std::move(processor);
    do {
        if (IsActive()) {
            trace_ = std::make_shared<WifiDirectTrace>(WifiDirectUtils::GetLocalUuid(), remoteDeviceId_);
        } else {
            trace_ = std::make_shared<WifiDirectTrace>(remoteDeviceId_, WifiDirectUtils::GetLocalUuid());
        }
        trace_->StartTrace();

        processor_->BindExecutor(this);
        try {
            CONN_LOGI(CONN_WIFI_DIRECT, "processor run");
            processor_->Run();
        } catch (const ProcessorTerminate &) {
            LinkManager::GetInstance().Dump();
            CONN_LOGI(CONN_WIFI_DIRECT, "processor terminate");
        }

        trace_->StopTrace();
        trace_ = nullptr;
        std::lock_guard lock(processorLock_);
        processor_ = nullptr;
    } while (scheduler_.ProcessNextCommand(this, processor_));

    CONN_LOGI(CONN_WIFI_DIRECT, "executor terminate");
}

std::string WifiDirectExecutor::GetRemoteDeviceId()
{
    return remoteDeviceId_;
}

void WifiDirectExecutor::SetRemoteDeviceId(const std::string &remoteDeviceId)
{
    remoteDeviceId_ = remoteDeviceId;
}

bool WifiDirectExecutor::IsActive() const
{
    return active_;
}

void WifiDirectExecutor::SetActive(bool active)
{
    active_ = active;
}

bool WifiDirectExecutor::CanAcceptNegotiateData()
{
    std::lock_guard lock(processorLock_);
    if (processor_ == nullptr) {
        return false;
    }
    return processor_->CanAcceptNegotiateData();
}

WifiDirectEventDispatcher WifiDirectExecutor::WaitEvent()
{
    return receiver_.Wait();
}
}
