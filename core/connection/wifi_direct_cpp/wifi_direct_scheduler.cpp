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
#include "wifi_direct_scheduler.h"
#include <thread>
#include "softbus_error_code.h"
#include "conn_log.h"
#include "command/connect_command.h"
#include "command/command_factory.h"
#include "command/disconnect_command.h"
#include "command/negotiate_command.h"

namespace OHOS::SoftBus {
int WifiDirectScheduler::ConnectDevice(const WifiDirectConnectInfo &info, const WifiDirectConnectCallback &callback,
                                       bool markRetried)
{
    CONN_LOGI(CONN_WIFI_DIRECT,
              "requestId=%{public}d, pid=%{public}d, type=%{public}d, networkId=%{public}s, remoteUuid=%{public}s, "
              "expectRole=0x%{public}x, bw=%{public}d, ipaddrType=%{public}d",
              info.requestId, info.pid, info.connectType, WifiDirectAnonymizeDeviceId(info.remoteNetworkId).c_str(),
              WifiDirectAnonymizeDeviceId(WifiDirectUtils::NetworkIdToUuid(info.remoteNetworkId)).c_str(),
              info.expectApiRole, info.bandWidth, info.ipAddrType);
    DumpNegotiateChannel(info.negoChannel);

    auto command = CommandFactory::GetInstance().CreateConnectCommand(info, callback);
    command->SetRetried(markRetried);
    std::shared_ptr<WifiDirectExecutor> executor;
    std::lock_guard executorLock(executorLock_);
    auto ret = ScheduleActiveCommand(command, executor);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "schedule active command failed");
    if (executor != nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
        executor->SendEvent(command);
    }
    return ret;
}

int WifiDirectScheduler::CancelConnectDevice(const WifiDirectConnectInfo &info)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, pid=%{public}d", info.requestId, info.pid);

    std::lock_guard commandLock(commandLock_);
    for (auto itc = commandList_.begin(); itc != commandList_.end(); itc++) {
        auto connectCommand = std::dynamic_pointer_cast<ConnectCommand>(*itc);
        if (connectCommand != nullptr && connectCommand->IsSameCommand(info)) {
            commandList_.erase(itc);
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_NOT_FIND;
}

int WifiDirectScheduler::ConnectDevice(const std::shared_ptr<ConnectCommand> &command, bool markRetried)
{
    return ConnectDevice(command->GetConnectInfo().info_, command->GetConnectCallback(), markRetried);
}

int WifiDirectScheduler::DisconnectDevice(WifiDirectDisconnectInfo &info, WifiDirectDisconnectCallback &callback)
{
    auto command = CommandFactory::GetInstance().CreateDisconnectCommand(info, callback);
    CONN_LOGI(CONN_WIFI_DIRECT,
              "requestId=%{public}d, pid=%{public}d, linkId=%{public}d, networkId=%{public}s, remoteUuid=%{public}s",
              info.requestId, info.pid, info.linkId,
              WifiDirectAnonymizeDeviceId(WifiDirectUtils::UuidToNetworkId(command->GetRemoteDeviceId())).c_str(),
              WifiDirectAnonymizeDeviceId(command->GetRemoteDeviceId()).c_str());

    std::shared_ptr<WifiDirectExecutor> executor;
    std::lock_guard executorLock(executorLock_);
    auto ret = ScheduleActiveCommand(command, executor);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "schedule active command failed");
    if (executor != nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
        executor->SendEvent(command);
    }
    return ret;
}

int WifiDirectScheduler::ForceDisconnectDevice(
    WifiDirectForceDisconnectInfo &info, WifiDirectDisconnectCallback &callback)
{
    auto command = CommandFactory::GetInstance().CreateForceDisconnectCommand(info, callback);
    CONN_LOGI(CONN_WIFI_DIRECT,
              "requestId=%{public}d pid=%{public}d networkId=%{public}s remoteUuid=%{public}s linktype=%{public}d",
              info.requestId, info.pid,
              WifiDirectAnonymizeDeviceId(WifiDirectUtils::UuidToNetworkId(command->GetRemoteDeviceId())).c_str(),
              WifiDirectAnonymizeDeviceId(command->GetRemoteDeviceId()).c_str(), info.linkType);
    std::shared_ptr<WifiDirectExecutor> executor;
    std::lock_guard executorLock(executorLock_);
    auto ret = ScheduleActiveCommand(command, executor);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "schedule active command failed, ret=%{public}d", ret);
    if (executor != nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
        executor->SendEvent(command);
    }
    return ret;
}

bool WifiDirectScheduler::ProcessNextCommand(WifiDirectExecutor *executor,
                                             std::shared_ptr<WifiDirectProcessor> &processor)
{
    auto executorDeviceId = executor->GetRemoteDeviceId();
    std::lock_guard executorLock(executorLock_);
    auto ite = executors_.find(executorDeviceId);
    if (ite == executors_.end()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not find executor=%{public}s",
                  WifiDirectAnonymizeDeviceId(executorDeviceId).c_str());
        return false;
    }

    auto executorCopy = ite->second;
    executors_.erase(ite);
    CONN_LOGI(CONN_WIFI_DIRECT, "remove executor=%{public}s", WifiDirectAnonymizeDeviceId(executorDeviceId).c_str());

    std::lock_guard commandLock(commandLock_);
    for (auto itc = commandList_.begin(); itc != commandList_.end(); itc++) {
        auto command = *itc;
        std::string commandDeviceId = command->GetRemoteDeviceId();
        if (commandDeviceId == executorDeviceId || executors_.find(commandDeviceId) == executors_.end()) {
            CONN_LOGI(CONN_WIFI_DIRECT, "commandDeviceId=%{public}s",
                      WifiDirectAnonymizeDeviceId(commandDeviceId).c_str());
            commandList_.erase(itc);
            processor = command->GetProcessor();
            executors_.insert({commandDeviceId, executorCopy});
            CONN_LOGI(CONN_WIFI_DIRECT, "add executor=%{public}s, commandId=%{public}u",
                      WifiDirectAnonymizeDeviceId(commandDeviceId).c_str(), command->GetId());
            executor->SetRemoteDeviceId(commandDeviceId);
            if (command->GetType() == CommandType::CONNECT_COMMAND) {
                executor->SetActive(true);
                executor->SendEvent(std::dynamic_pointer_cast<ConnectCommand>(command));
            } else if (command->GetType() == CommandType::DISCONNECT_COMMAND) {
                executor->SetActive(true);
                executor->SendEvent(std::dynamic_pointer_cast<DisconnectCommand>(command));
            } else if (command->GetType() == CommandType::NEGOTIATE_COMMAND) {
                auto negotiateCommand = std::dynamic_pointer_cast<NegotiateCommand>(command);
                CONN_LOGI(CONN_WIFI_DIRECT, "msgType=%{public}s",
                          negotiateCommand->GetNegotiateMessage().MessageTypeToString().c_str());
                executor->SetActive(false);
                executor->SendEvent(negotiateCommand);
            }
            return true;
        }
    }

    return false;
}

int WifiDirectScheduler::ScheduleActiveCommand(const std::shared_ptr<WifiDirectCommand> &command,
                                               std::shared_ptr<WifiDirectExecutor> &executor)
{
    auto remoteDeviceId = command->GetRemoteDeviceId();
    if (remoteDeviceId.empty()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "remoteDeviceId emtpy");
        return SOFTBUS_CONN_REMOTE_DEVICE_ID_EMPTY;
    }

    std::lock_guard executorLock(executorLock_);
    auto it = executors_.find(remoteDeviceId);
    if (it != executors_.end() || executors_.size() == MAX_EXECUTOR) {
        CONN_LOGI(CONN_WIFI_DIRECT, "push command to list, commandId=%{public}u", command->GetId());
        std::lock_guard commandLock(commandLock_);
        commandList_.push_back(command);
        return SOFTBUS_OK;
    }

    auto processor = command->GetProcessor();
    if (processor == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get processor failed");
        return SOFTBUS_CONN_GET_PROCESSOR_FAILED;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "create executor=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
    executor = WifiDirectExecutorFactory::GetInstance().NewExecutor(remoteDeviceId, *this, processor, true);
    if (executor == nullptr) {
        return SOFTBUS_MALLOC_ERR;
    }

    executors_.insert({ remoteDeviceId, executor });
    return SOFTBUS_OK;
}

void WifiDirectScheduler::DumpNegotiateChannel(const WifiDirectNegotiateChannel &channel)
{
    switch (channel.type) {
        case NEGO_CHANNEL_NULL:
            CONN_LOGI(CONN_WIFI_DIRECT, "NEGO_CHANNEL_NULL");
            break;
        case NEGO_CHANNEL_AUTH:
            CONN_LOGI(CONN_WIFI_DIRECT, "NEGO_CHANNEL_AUTH, type=%{public}d, authId=%{public}" PRId64,
                      channel.handle.authHandle.type, channel.handle.authHandle.authId);
            break;
        case NEGO_CHANNEL_COC:
            CONN_LOGI(CONN_WIFI_DIRECT, "NEGO_CHANNEL_COC");
            break;
        case NEGO_CHANNEL_ACTION:
            CONN_LOGI(CONN_WIFI_DIRECT, "NEGO_CHANNEL_ACTION, actionAddr=%{public}d",
                      channel.handle.actionAddr);
            break;
        case NEGO_CHANNEL_SHARE:
            CONN_LOGI(CONN_WIFI_DIRECT, "NEGO_CHANNEL_COC, channelId=%{public}d", channel.handle.channelId);
            break;
        default:
            CONN_LOGW(CONN_WIFI_DIRECT, "not support type=%{public}d", channel.type);
    }
}

void WifiDirectScheduler::Dump(std::list<std::shared_ptr<ProcessorSnapshot>> &snapshots)
{
    std::lock_guard executorLock(executorLock_);
    for (const auto &executor : executors_) {
        if (executor.second != nullptr) {
            executor.second->Dump(snapshots);
        }
    }
}
}
