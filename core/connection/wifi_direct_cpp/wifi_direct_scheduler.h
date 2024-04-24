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
#ifndef WIFI_DIRECT_SCHEDULER_H
#define WIFI_DIRECT_SCHEDULER_H

#include <list>
#include <map>
#include <mutex>
#include <memory>
#include <string>
#include <thread>
#include "wifi_direct_types.h"
#include "wifi_direct_executor.h"
#include "command/wifi_direct_command.h"
#include "command/connect_command.h"
#include "event/wifi_direct_event_wrapper.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
class WifiDirectSchedulerFactory;
class WifiDirectScheduler {
public:
    virtual ~WifiDirectScheduler() = default;

    int ConnectDevice(const WifiDirectConnectInfo &info, const WifiDirectConnectCallback &callback,
                      bool markRetried = false);
    int ConnectDevice(const std::shared_ptr<ConnectCommand> &command, bool markRetried = false);
    int DisconnectDevice(WifiDirectDisconnectInfo &info, WifiDirectDisconnectCallback &callback);

    template<typename Command>
    void ProcessNegotiateData(const std::string &remoteDeviceId, Command &command)
    {
        CONN_LOGD(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s",
                  WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
        std::lock_guard executorLock(executorLock_);
        auto it = executors_.find(remoteDeviceId);
        if (it != executors_.end()) {
            if (it->second->CanAcceptNegotiateData()) {
                CONN_LOGI(CONN_WIFI_DIRECT, "send data to executor=%{public}s",
                          WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
                it->second->SendEvent(std::make_shared<Command>(command));
                return;
            }
            std::lock_guard commandLock(commandLock_);
            CONN_LOGI(CONN_WIFI_DIRECT, "push data to list");
            commandList_.push_back(std::make_shared<Command>(command));
            return;
        }

        if (executors_.size() == MAX_EXECUTOR) {
            CONN_LOGI(CONN_WIFI_DIRECT, "push data to list");
            std::lock_guard commandLock(commandLock_);
            commandList_.push_back(std::make_shared<Command>(command));
            return;
        }

        auto processor = command.GetProcessor();
        if (processor == nullptr) {
            CONN_LOGE(CONN_WIFI_DIRECT, "get processor failed");
            return;
        }
        CONN_LOGI(CONN_WIFI_DIRECT, "create executor=%{public}s",
                  WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
        auto executor = std::make_shared<WifiDirectExecutor>(remoteDeviceId, *this, processor, false);
        if (executor == nullptr) {
            return;
        }
        executors_.insert({ remoteDeviceId, executor });
        executor->SendEvent(std::make_shared<Command>(command));
    }

    template<typename Event>
    void ProcessEvent(const std::string &remoteDeviceId, const Event &event)
    {
        std::lock_guard lock(executorLock_);
        auto it = executors_.find(remoteDeviceId);
        if (it == executors_.end()) {
            return;
        }

        CONN_LOGI(CONN_WIFI_DIRECT, "send event to executor=%{public}s",
                  WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
        auto content = std::make_shared<Event>(event);
        it->second->SendEvent(content);
    }

    template<typename Command>
    void QueueCommand(Command &command)
    {
        std::lock_guard commandLock(commandLock_);
        CONN_LOGI(CONN_WIFI_DIRECT, "push data to list");
        commandList_.push_back(std::make_shared<Command>(command));
    }

    template<typename Command>
    void FetchAndDispatchCommand(const std::string &remoteDeviceId)
    {
        std::lock_guard executorLock(executorLock_);
        auto eit = executors_.find(remoteDeviceId);
        if (eit == executors_.end()) {
            return;
        }

        std::lock_guard commandLock(commandLock_);
        for (auto cit = commandList_.begin(); cit != commandList_.end(); cit++) {
            auto &command = *cit;
            if (command->GetRemoteDeviceId() != remoteDeviceId) {
                continue;
            }
            auto cmd = std::dynamic_pointer_cast<Command>(command);
            if (cmd != nullptr) {
                CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d", static_cast<int>(command->GetType()));
                eit->second->SendEvent(cmd);
                commandList_.erase(cit);
                return;
            }
        }
    }

    virtual bool ProcessNextCommand(WifiDirectExecutor *executor, std::shared_ptr<WifiDirectProcessor> &processor);

protected:
    int ScheduleActiveCommand(const std::shared_ptr<WifiDirectCommand> &command,
                              std::shared_ptr<WifiDirectExecutor> &executor);

    static constexpr int MAX_EXECUTOR = 8;
    std::recursive_mutex executorLock_;
    std::map<std::string, std::shared_ptr<WifiDirectExecutor>> executors_;
    std::recursive_mutex commandLock_;
    std::list<std::shared_ptr<WifiDirectCommand>> commandList_;

private:
    friend WifiDirectSchedulerFactory;
    static WifiDirectScheduler& GetInstance()
    {
        static WifiDirectScheduler instance;
        return instance;
    }
};
}
#endif
