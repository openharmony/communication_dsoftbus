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
#ifndef WIFI_DIRECT_EXECUTOR_H
#define WIFI_DIRECT_EXECUTOR_H

#include <condition_variable>
#include <memory>
#include <queue>
#include <thread>

#include "processor/wifi_direct_processor.h"
#include "event/wifi_direct_event_receiver.h"
#include "event/wifi_direct_event_sender.h"
#include "utils/wifi_direct_trace.h"

namespace OHOS::SoftBus {
class WifiDirectScheduler;
class WifiDirectExecutor {
public:
    explicit WifiDirectExecutor(const std::string &remoteDeviceId, WifiDirectScheduler &scheduler,
                                std::shared_ptr<WifiDirectProcessor> &processor, bool active);
    ~WifiDirectExecutor();

    void Run(std::shared_ptr<WifiDirectProcessor> processor);
    std::string GetRemoteDeviceId();
    void SetRemoteDeviceId(const std::string &remoteDeviceId);
    bool IsActive() const;
    void SetActive(bool active);
    bool CanAcceptNegotiateData();

    template<typename Content>
    void SendEvent(const Content &content)
    {
        GetSender().Send(content);
    }

    WifiDirectEventDispatcher WaitEvent();

private:
    WifiDirectEventSender GetSender() { return receiver_; }

    std::string remoteDeviceId_;
    WifiDirectEventReceiver receiver_;
    WifiDirectScheduler &scheduler_;
    std::recursive_mutex processorLock_;
    std::shared_ptr<WifiDirectProcessor> processor_;
    std::thread thread_;

    bool active_;
    std::shared_ptr<WifiDirectTrace> trace_;
};
}
#endif
