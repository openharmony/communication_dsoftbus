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

#include <cstring>
#include "connect_command.h"
#include "channel/auth_negotiate_channel.h"
#include "channel/dummy_negotiate_channel.h"
#include "channel/proxy_negotiate_channel.h"
#include "conn_log.h"
#include "data/link_manager.h"
#include "dfx/wifi_direct_dfx.h"
#include "event/wifi_direct_event_dispatcher.h"
#include "processor_selector_factory.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_scheduler_factory.h"

namespace OHOS::SoftBus {
ConnectCommand::ConnectCommand(const WifiDirectConnectInfo &info, const WifiDirectConnectCallback &callback)
    : callback_(callback)
{
    info_.info_ = info;
    if (strlen(info.remoteNetworkId) != 0) {
        remoteDeviceId_ = WifiDirectUtils::NetworkIdToUuid(info_.info_.remoteNetworkId);
        return;
    }
    CONN_LOGE(CONN_WIFI_DIRECT, "remoteNetworkId empty!!");
}

std::string ConnectCommand::GetRemoteDeviceId() const
{
    if (!remoteDeviceId_.empty()) {
        return remoteDeviceId_;
    }
    remoteDeviceId_ = WifiDirectUtils::NetworkIdToUuid(info_.info_.remoteNetworkId);
    return remoteDeviceId_;
}

std::shared_ptr<WifiDirectProcessor> ConnectCommand::GetProcessor()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    auto selector = ProcessorSelectorFactory::GetInstance().NewSelector();
    if (selector == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "selector is null");
        return nullptr;
    }
    return (*selector)(info_.info_);
}

ConnectInfo &ConnectCommand::GetConnectInfo()
{
    return info_;
}

WifiDirectConnectCallback ConnectCommand::GetConnectCallback() const
{
    return callback_;
}

void ConnectCommand::SetSuccessCallback(const SuccessCallback &callback)
{
    successCallback_ = callback;
}

void ConnectCommand::SetFailureCallback(const FailureCallback &callback)
{
    failureCallback_ = callback;
}

void ConnectCommand::OnSuccess(const WifiDirectLink &link) const
{
    CONN_LOGI(CONN_WIFI_DIRECT,
        "requestId=%{public}u, linkId=%{public}d, localIp=%{public}s, remoteIp=%{public}s, remotePort=%{public}d, "
        "linkType=%{public}d, isReuse=%{public}d, bw=%{public}d, channelId=%{public}d, remoteDeviceId=%{public}s",
        info_.info_.requestId, link.linkId, WifiDirectAnonymizeIp(link.localIp).c_str(),
        WifiDirectAnonymizeIp(link.remoteIp).c_str(), link.remotePort, link.linkType, link.isReuse, link.bandWidth,
        link.channelId, WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str());
    if (successCallback_ != nullptr) {
        successCallback_(link);
        return;
    }
    WifiDirectDfx::GetInstance().DfxRecord(true, SOFTBUS_OK, info_.info_);
    if (callback_.onConnectSuccess != nullptr) {
        callback_.onConnectSuccess(info_.info_.requestId, &link);
    }
}

void ConnectCommand::OnFailure(int32_t reason) const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}u, reason=%{public}d, remoteDeviceId=%{public}s",
        info_.info_.requestId, reason, WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str());
    if (reason == SOFTBUS_CONN_NEED_RENEGOTIATE && !HasRetried()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "retry");
        WifiDirectSchedulerFactory::GetInstance().GetScheduler().ConnectDevice(info_.info_, callback_, true);
        return;
    }
    if (failureCallback_ != nullptr) {
        failureCallback_(reason);
        return;
    }
    WifiDirectDfx::GetInstance().DfxRecord(false, reason, info_.info_);
    if (callback_.onConnectFailure != nullptr) {
        callback_.onConnectFailure(info_.info_.requestId, reason);
    }
}

void ConnectCommand::PreferNegotiateChannel()
{
    auto innerLink = LinkManager::GetInstance().GetReuseLink(info_.info_.connectType, remoteDeviceId_);
    if (remoteDeviceId_.length() != (UUID_BUF_LEN - 1) && innerLink == nullptr) {
        innerLink = LinkManager::GetInstance().GetReuseLink(remoteDeviceId_);
    }
    if (innerLink == nullptr || innerLink->GetNegotiateChannel() == nullptr) {
        if (info_.info_.negoChannel.type == NEGO_CHANNEL_AUTH) {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input auth channel");
            info_.channel_ = std::make_shared<AuthNegotiateChannel>(info_.info_.negoChannel.handle.authHandle);
        } else if (info_.info_.negoChannel.type == NEGO_CHANNEL_COC) {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input proxy channel");
            info_.channel_ = std::make_shared<CoCProxyNegotiateChannel>(info_.info_.negoChannel.handle.channelId);
        } else {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input null channel");
            info_.channel_ = std::make_shared<DummyNegotiateChannel>();
        }
        return;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "prefer inner channel");
    info_.channel_ = innerLink->GetNegotiateChannel();
}

bool ConnectCommand::IsSameCommand(const WifiDirectConnectInfo &info) const
{
    return (info.requestId == info_.info_.requestId) && (info.pid == info_.info_.pid);
}

void ConnectCommand::ResetConnectType(WifiDirectConnectType connectType)
{
    auto oldConnectType = info_.info_.connectType;
    CONN_LOGI(
        CONN_WIFI_DIRECT, "old connect type=%{public}d, new connect type=%{public}d", oldConnectType, connectType);
    info_.info_.connectType = connectType;
}
} // namespace OHOS::SoftBus
