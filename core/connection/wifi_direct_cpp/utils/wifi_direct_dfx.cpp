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

#include "wifi_direct_dfx.h"
#include "conn_log.h"
#include "duration_statistic.h"
#include "wifi_direct_utils.h"
#include "adapter/p2p_adapter.h"

namespace OHOS::SoftBus {

void WifiDirectDfx::DfxRecord(bool success, int32_t reason, WifiDirectConnectInfo &connectInfo)
{
    if (success) {
        DurationStatistic::GetInstance().Record(connectInfo.requestId, TOTAL_END);
        DurationStatistic::GetInstance().End(connectInfo.requestId);
        ConnEventExtra extra = {
            .result = EVENT_STAGE_RESULT_OK,
            .requestId = static_cast<int32_t>(connectInfo.requestId),
            .frequency = connectInfo.dfxInfo.frequency,
        };
        ReportConnEventExtra(extra, connectInfo);
        DurationStatistic::GetInstance().Clear(connectInfo.requestId);
        WifiDirectDfx::GetInstance().Clear(connectInfo.requestId);
    } else {
        ConnEventExtra extra = {
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = reason,
            .requestId = static_cast<int32_t>(connectInfo.requestId),
            .frequency = connectInfo.dfxInfo.frequency,
        };
        ReportConnEventExtra(extra, connectInfo);
        DurationStatistic::GetInstance().Clear(connectInfo.requestId);
        WifiDirectDfx::GetInstance().Clear(connectInfo.requestId);
    }
}

void WifiDirectDfx::Record(uint32_t requestId, uint16_t challengeCode)
{
    std::lock_guard lock(mutex_);
    challengeCodeMap_.insert(std::make_pair(requestId, challengeCode));
}

void WifiDirectDfx::Clear(uint32_t requestId)
{
    std::lock_guard lock(mutex_);
    challengeCodeMap_.erase(requestId);
    reuseFlagMap_.erase(requestId);
}

void WifiDirectDfx::ReportConnEventExtra(ConnEventExtra &extra, WifiDirectConnectInfo &wifiDirectConnectInfo)
{
    SetLinkType(wifiDirectConnectInfo);
    enum StatisticLinkType type = wifiDirectConnectInfo.dfxInfo.linkType;
    if (type == STATISTIC_P2P) {
        extra.linkType = CONNECT_P2P;
    } else if (type == STATISTIC_HML) {
        extra.linkType = CONNECT_HML;
    } else {
        extra.linkType = CONNECT_TRIGGER_HML;
    }

    auto requestId = wifiDirectConnectInfo.requestId;
    auto challengeCodeStr = GetChallengeCode(requestId);
    extra.challengeCode = challengeCodeStr.c_str();
    auto stateMapElement = DurationStatistic::GetInstance().GetStateTimeMapElement(requestId);
    uint64_t startTime = stateMapElement[TOTAL_START];
    uint64_t endTime = stateMapElement[TOTAL_END];
    if (startTime != 0 && endTime != 0) {
        extra.costTime = int32_t(endTime - startTime);
        extra.negotiateTime = endTime - startTime > 0 ? endTime - startTime : 0;
    }
    auto dfxInfo = wifiDirectConnectInfo.dfxInfo;
    extra.bootLinkType = dfxInfo.bootLinkType;
    extra.peerNetworkId = wifiDirectConnectInfo.remoteNetworkId;
    auto localNetworkId = WifiDirectUtils::GetLocalNetworkId();
    extra.localNetworkId = localNetworkId.c_str();
    extra.osType = WifiDirectUtils::GetOsType(wifiDirectConnectInfo.remoteNetworkId);
    auto localDeviceType = WifiDirectUtils::GetDeviceType();
    auto localDeviceTypeStr = std::to_string(localDeviceType);
    extra.localDeviceType = localDeviceTypeStr.c_str();
    auto remoteDeviceType = WifiDirectUtils::GetDeviceType(wifiDirectConnectInfo.remoteNetworkId);
    auto remoteDeviceTypeStr = std::to_string(remoteDeviceType);
    extra.remoteDeviceType = remoteDeviceTypeStr.c_str();
    extra.isRenegotiate = DurationStatistic::GetInstance().ReNegotiateFlag(requestId);
    extra.staChannel = dfxInfo.staChannel;
    extra.hmlChannel = dfxInfo.hmlChannel;
    extra.p2pChannel = dfxInfo.p2pChannel;
    extra.apChannel = dfxInfo.apChannel;
    CONN_LOGI(CONN_WIFI_DIRECT, "sta=%{public}d, p2p=%{public}d, hml=%{public}d, ap=%{public}d", extra.staChannel,
        extra.p2pChannel, extra.hmlChannel, extra.apChannel);
    auto remoteOsVersion = WifiDirectUtils::GetRemoteOsVersion(wifiDirectConnectInfo.remoteNetworkId);
    extra.peerDevVer = remoteOsVersion.c_str();
    extra.remoteScreenStatus = WifiDirectUtils::GetRemoteScreenStatus(wifiDirectConnectInfo.remoteNetworkId);
    extra.isReuse = IsReuse(requestId);
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
}

void WifiDirectDfx::SetLinkType(WifiDirectConnectInfo &connectInfo)
{
    if (connectInfo.connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P) {
        connectInfo.dfxInfo.linkType = STATISTIC_P2P;
    } else if (connectInfo.connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML) {
        connectInfo.dfxInfo.linkType = STATISTIC_HML;
    } else {
        connectInfo.dfxInfo.linkType = STATISTIC_TRIGGER_HML;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "link type %{public}d", connectInfo.dfxInfo.linkType);
}

void WifiDirectDfx::SetReuseFlag(uint32_t requestId)
{
    std::lock_guard lock(mutex_);
    reuseFlagMap_.insert(std::make_pair(requestId, true));
}

bool WifiDirectDfx::IsReuse(uint32_t requestId)
{
    std::lock_guard lock(mutex_);
    return reuseFlagMap_.find(requestId) != reuseFlagMap_.end();
}

std::string WifiDirectDfx::GetChallengeCode(uint32_t requestId)
{
    std::lock_guard lock(mutex_);
    std::string challengeCodeStr;
    if (challengeCodeMap_.find(requestId) != challengeCodeMap_.end()) {
        challengeCodeStr = std::to_string(challengeCodeMap_[requestId]);
        return challengeCodeStr;
    }
    return "";
}

void WifiDirectDfx::ReportReceiveAuthLinkMsg(const NegotiateMessage &msg, const std::string &remoteDeviceId)
{
    if (msg.GetMessageType() == NegotiateMessageType::CMD_TRIGGER_REQ ||
        msg.GetMessageType() == NegotiateMessageType::CMD_CONN_V2_REQ_3 ||
        msg.GetMessageType() == NegotiateMessageType::CMD_CONN_V2_REQ_1) {
        auto challengeCodeStr = std::to_string(msg.GetChallengeCode());
        auto localNetworkId = WifiDirectUtils::GetLocalNetworkId();
        auto remoteNetworkId = WifiDirectUtils::UuidToNetworkId(remoteDeviceId);
        ConnEventExtra extra = {
            .requestId = (int32_t)msg.GetSessionId(),
            .challengeCode = challengeCodeStr.c_str(),
            .peerNetworkId = remoteNetworkId.c_str(),
            .localNetworkId = localNetworkId.c_str(),
        };
        CONN_EVENT(EVENT_SCENE_PASSIVE_CONNECT, EVENT_STAGE_CONNECT_START, extra);
    }
}
} // namespace OHOS::SoftBus
