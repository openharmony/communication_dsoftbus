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
#include "connect_command.h"

#include <cstring>

#include "conn_log.h"

#include "channel/auth_negotiate_channel.h"
#include "channel/proxy_negotiate_channel.h"
#include "channel/null_negotiate_channel.h"
#include "data/link_manager.h"
#include "processor_selector_factory.h"
#include "utils/duration_statistic.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

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

void ConnectCommand::OnSuccess(const WifiDirectLink &link) const
{
    CONN_LOGI(CONN_WIFI_DIRECT,
        "requestId=%{public}u linkId=%{public}d, localIp=%{public}s, remoteIp=%{public}s, remotePort=%{public}d, "
        "linkType=%{public}d",
        info_.info_.requestId, link.linkId, WifiDirectAnonymizeIp(link.localIp).c_str(),
        WifiDirectAnonymizeIp(link.remoteIp).c_str(), link.remotePort, link.linkType);
    DfxRecord(true, OK);
    callback_.onConnectSuccess(info_.info_.requestId, &link);
}

void ConnectCommand::OnFailure(WifiDirectErrorCode reason) const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}u, reason=%{public}d", info_.info_.requestId, reason);
    DfxRecord(false, reason);
    callback_.onConnectFailure(info_.info_.requestId, reason);
}

void ConnectCommand::PreferNegotiateChannel()
{
    auto innerLink = LinkManager::GetInstance().GetReuseLink(info_.info_.connectType, remoteDeviceId_);
    if (innerLink == nullptr || innerLink->GetNegotiateChannel() == nullptr) {
        if (info_.info_.negoChannel.type == NEGO_CHANNEL_AUTH) {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input auth channel");
            info_.channel_ = std::make_shared<AuthNegotiateChannel>(info_.info_.negoChannel.handle.authHandle);
        } else if (info_.info_.negoChannel.type == NEGO_CHANNEL_COC) {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input proxy channel");
            info_.channel_ = std::make_shared<CoCProxyNegotiateChannel>(info_.info_.negoChannel.handle.channelId);
        } else {
            CONN_LOGI(CONN_WIFI_DIRECT, "prefer input null channel");
            info_.channel_ = std::make_shared<NullNeotiateChannel>();
        }
        return;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "prefer inner channel");
    info_.channel_ = innerLink->GetNegotiateChannel();
}

void ConnectCommand::DfxRecord(bool isSuccess, WifiDirectErrorCode reason) const
{
    if (isSuccess) {
        DurationStatistic::GetInstance().Record(info_.info_.requestId, TotalEnd);
        DurationStatistic::GetInstance().End(info_.info_.requestId);
        DurationStatistic::GetInstance().Clear(info_.info_.requestId);

        ConnEventExtra extra = {
            .result = EVENT_STAGE_RESULT_OK,
            .requestId = static_cast<int32_t>(info_.info_.requestId),
        };
        FillConnEventExtra(extra);
        CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
    } else {
        DurationStatistic::GetInstance().Clear(info_.info_.requestId);
        ConnEventExtra extra = {
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = static_cast<int32_t>(reason),
            .requestId = static_cast<int32_t>(info_.info_.requestId),
        };
        FillConnEventExtra(extra);
        CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
    }
}

void ConnectCommand::FillConnEventExtra(ConnEventExtra &extra) const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "FillConnEventExtra enter");
    extra.peerIp = nullptr;
    extra.peerBleMac = nullptr;
    extra.peerBrMac = nullptr;
    extra.peerWifiMac = nullptr;
    extra.peerPort = nullptr;
    extra.peerNetworkId = nullptr;
    extra.localNetworkId = nullptr;
    extra.calleePkg = nullptr;
    extra.callerPkg = nullptr;
    extra.lnnType = nullptr;
    extra.challengeCode = nullptr;

    enum StatisticLinkType type = info_.info_.linkType;
    if (type == STATISTIC_P2P) {
        extra.linkType = CONNECT_P2P;
    } else if (type == STATISTIC_HML) {
        extra.linkType = CONNECT_HML;
    } else {
        extra.linkType = CONNECT_TRIGGER_HML;
    }

    extra.bootLinkType = info_.info_.bootLinkType;
    extra.isRenegotiate = info_.info_.renegotiate;
    extra.isReuse = info_.info_.reuse;
    DurationStatistic instance = DurationStatistic::GetInstance();
    std::map<DurationStatisticEvent, uint64_t> map = instance.stateTimeMap[info_.info_.requestId];
    uint64_t startTime = map[TotalStart];
    uint64_t endTime = map[TotalEnd];
    if (startTime != 0 && endTime != 0) {
        extra.costTime = int32_t(endTime - startTime);
        extra.negotiateTime = int32_t(endTime - startTime);
    }
}
} // namespace OHOS::SoftBus
