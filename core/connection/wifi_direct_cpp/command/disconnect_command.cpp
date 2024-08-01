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
#include "disconnect_command.h"
#include "channel/dummy_negotiate_channel.h"
#include "channel/proxy_negotiate_channel.h"
#include "conn_log.h"
#include "data/link_manager.h"
#include "processor_selector_factory.h"

namespace OHOS::SoftBus {
DisconnectCommand::DisconnectCommand(const WifiDirectDisconnectInfo &info, const WifiDirectDisconnectCallback &callback)
    : callback_(callback)
{
    info_.info_ = info;
    auto innerLink = LinkManager::GetInstance().GetLinkById(info_.info_.linkId);
    if (innerLink == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find inner link, prefer input null channel");
        info_.channel_ = std::make_shared<DummyNegotiateChannel>();
        return;
    }

    if (innerLink->GetNegotiateChannel() == nullptr) {
        if (info.negoChannel.type == NEGO_CHANNEL_AUTH) {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input auth channel");
            info_.channel_ = std::make_shared<AuthNegotiateChannel>(info.negoChannel.handle.authHandle);
        } else if (info.negoChannel.type == NEGO_CHANNEL_COC) {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input proxy channel");
            info_.channel_ = std::make_shared<CoCProxyNegotiateChannel>(info.negoChannel.handle.channelId);
        } else {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input null channel");
            info_.channel_ = std::make_shared<DummyNegotiateChannel>();
        }
        return;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "prefer inner channel");
    info_.channel_ = innerLink->GetNegotiateChannel();
}

std::string DisconnectCommand::GetRemoteDeviceId() const
{
    if (!remoteDeviceId_.empty()) {
        return remoteDeviceId_;
    }

    auto innerLink = LinkManager::GetInstance().GetLinkById(info_.info_.linkId);
    if (innerLink == nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "innerLink is nullptr");
        return remoteDeviceId_;
    }
    remoteDeviceId_ = innerLink->GetRemoteDeviceId();
    return remoteDeviceId_;
}

std::shared_ptr<WifiDirectProcessor> DisconnectCommand::GetProcessor()
{
    auto selector = ProcessorSelectorFactory::GetInstance().NewSelector();
    if (selector == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "selector is null");
        return nullptr;
    }
    return (*selector)(info_.info_);
}

DisconnectInfo DisconnectCommand::GetDisconnectInfo() const
{
    return info_;
}

std::shared_ptr<NegotiateChannel> DisconnectCommand::GetNegotiateChannel() const
{
    return info_.channel_;
}

void DisconnectCommand::OnSuccess() const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}u", info_.info_.requestId);
    callback_.onDisconnectSuccess(info_.info_.requestId);
}

void DisconnectCommand::OnFailure(int32_t reason) const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}u, reason=%{public}d", info_.info_.requestId, reason);
    callback_.onDisconnectFailure(info_.info_.requestId, reason);
}
} // namespace OHOS::SoftBus
