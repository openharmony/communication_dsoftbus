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

#include "inner_link.h"

#include "securec.h"

#include "nlohmann/json.hpp"

#include "conn_log.h"
#include "softbus_adapter_timer.h"

#include "channel/auth_negotiate_channel.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_ip_manager.h"

namespace OHOS::SoftBus {
InnerLink::InnerLink(const std::string &remoteMac)
{
    SetRemoteBaseMac(remoteMac);
}

InnerLink::InnerLink(LinkType type, const std::string &remoteDeviceId)
{
    SetLinkType(type);
    SetRemoteDeviceId(remoteDeviceId);
}

InnerLink::~InnerLink()
{
    auto listenerModuleId = GetListenerModule();
    bool hasAnotherUsed = false;
    LinkManager::GetInstance().ForEach([&hasAnotherUsed, this](InnerLink &innerLink) {
        if (innerLink.GetLinkType() == InnerLink::LinkType::P2P && innerLink.GetLocalIpv4() == this->GetLocalIpv4() &&
            innerLink.GetRemoteDeviceId() != this->GetRemoteDeviceId()) {
                hasAnotherUsed = true;
            }
        return false;
    });
    CONN_LOGI(CONN_WIFI_DIRECT, "hasAnotherUsed=%{public}d", hasAnotherUsed);
    if (listenerModuleId != UNUSE_BUTT) {
        CONN_LOGI(CONN_WIFI_DIRECT, "stop auth listening");
        if (GetLinkType() == LinkType::HML) {
            AuthNegotiateChannel::StopListening(AUTH_LINK_TYPE_ENHANCED_P2P, listenerModuleId);
            StopCustomListen(GetLocalCustomPort());
        } else {
            if (!hasAnotherUsed) {
                AuthNegotiateChannel::StopListening(AUTH_LINK_TYPE_P2P, listenerModuleId);
            }
        }
    }
    if (!GetLocalIpv4().empty() && !GetRemoteIpv4().empty() && !GetRemoteBaseMac().empty() && !hasAnotherUsed &&
        !GetLegacyReused()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "release ip");
        WifiDirectIpManager::GetInstance().ReleaseIpv4(
            GetLocalInterface(), Ipv4Info(GetLocalIpv4()), Ipv4Info(GetRemoteIpv4()), GetRemoteBaseMac());
    }
}

InnerLink::LinkType InnerLink::GetLinkType() const
{
    return Get(InnerLinKey::LINK_TYPE, LinkType::INVALID_TYPE);
}

void InnerLink::SetLinkType(InnerLink::LinkType type)
{
    Set(InnerLinKey::LINK_TYPE, type);
}

InnerLink::LinkState InnerLink::GetState() const
{
    return Get(InnerLinKey::STATE, LinkState::INVALID_STATE);
}

void InnerLink::SetState(LinkState newState)
{
    LinkState oldState = GetState();
    if (oldState != newState) {
        uint64_t changeTime = SoftBusGetSysTimeMs();
        Set(InnerLinKey::STATE_CHANGE_TIME, changeTime);
        Set(InnerLinKey::STATE, newState);
    }
}

std::string InnerLink::GetLocalInterface() const
{
    return Get(InnerLinKey::LOCAL_INTERFACE, std::string(""));
}

void InnerLink::SetLocalInterface(const std::string &interface)
{
    Set(InnerLinKey::LOCAL_INTERFACE, interface);
}

std::string InnerLink::GetLocalBaseMac() const
{
    return Get(InnerLinKey::LOCAL_BASE_MAC, std::string(""));
}

void InnerLink::SetLocalBaseMac(const std::string &mac)
{
    Set(InnerLinKey::LOCAL_BASE_MAC, mac);
}

std::string InnerLink::GetLocalDynamicMac() const
{
    return Get(InnerLinKey::LOCAL_DYNAMIC_MAC, std::string(""));
}

void InnerLink::SetLocalDynamicMac(const std::string &mac)
{
    Set(InnerLinKey::LOCAL_DYNAMIC_MAC, mac);
}

std::string InnerLink::GetLocalIpv4() const
{
    return Get(InnerLinKey::LOCAL_IPV4, std::string(""));
}

void InnerLink::SetLocalIpv4(const std::string &ip)
{
    Set(InnerLinKey::LOCAL_IPV4, ip);
}

std::string InnerLink::GetRemoteInterface() const
{
    return Get(InnerLinKey::REMOTE_INTERFACE, std::string(""));
}

void InnerLink::SetRemoteInterface(const std::string &interface)
{
    Set(InnerLinKey::REMOTE_INTERFACE, interface);
}

std::string InnerLink::GetRemoteBaseMac() const
{
    return Get(InnerLinKey::REMOTE_BASE_MAC, std::string(""));
}

void InnerLink::SetRemoteBaseMac(const std::string &mac)
{
    Set(InnerLinKey::REMOTE_BASE_MAC, mac);
}

std::string InnerLink::GetRemoteDynamicMac() const
{
    return Get(InnerLinKey::REMOTE_DYNAMIC_MAC, std::string(""));
}

void InnerLink::SetRemoteDynamicMac(const std::string &mac)
{
    Set(InnerLinKey::REMOTE_DYNAMIC_MAC, mac);
}

std::string InnerLink::GetRemoteIpv4() const
{
    return Get(InnerLinKey::REMOTE_IPV4, std::string(""));
}

void InnerLink::SetRemoteIpv4(const std::string &ip)
{
    Set(InnerLinKey::REMOTE_IPV4, ip);
}

bool InnerLink::IsBeingUsedByLocal() const
{
    return !linkIds_.empty();
}

bool InnerLink::IsBeingUsedByRemote() const
{
    return Get(InnerLinKey::IS_BEING_USED_BY_REMOTE, false);
}

void InnerLink::SetBeingUsedByRemote(bool value)
{
    Set(InnerLinKey::IS_BEING_USED_BY_REMOTE, value);
}

int InnerLink::GetFrequency() const
{
    return Get(InnerLinKey::FREQUENCY, -1);
}

void InnerLink::SetFrequency(int frequency)
{
    Set(InnerLinKey::FREQUENCY, frequency);
}

std::string InnerLink::GetRemoteDeviceId() const
{
    return Get(InnerLinKey::REMOTE_DEVICE_ID, std::string(""));
}

void InnerLink::SetRemoteDeviceId(const std::string &deviceId)
{
    Set(InnerLinKey::REMOTE_DEVICE_ID, deviceId);
}

std::shared_ptr<NegotiateChannel> InnerLink::GetNegotiateChannel() const
{
    return channel_;
}

void InnerLink::SetNegotiateChannel(const std::shared_ptr<NegotiateChannel> &channel)
{
    channel_ = channel;
}

int InnerLink::GetLocalPort() const
{
    return Get(InnerLinKey::LOCAL_PORT, -1);
}

void InnerLink::SetLocalPort(int port)
{
    Set(InnerLinKey::LOCAL_PORT, port);
}

ListenerModule InnerLink::GetListenerModule() const
{
    return Get(InnerLinKey::LISTENER_MODULE_ID, static_cast<ListenerModule>(UNUSE_BUTT));
}

void InnerLink::SetListenerModule(ListenerModule module)
{
    Set(InnerLinKey::LISTENER_MODULE_ID, module);
}

std::string InnerLink::GetLocalIpv6() const
{
    return Get(InnerLinKey::LOCAL_IPV6, std::string());
}

void InnerLink::SetLocalIpv6(const std::string &value)
{
    Set(InnerLinKey::LOCAL_IPV6, value);
}

std::string InnerLink::GetRemoteIpv6() const
{
    return Get(InnerLinKey::REMOTE_IPV6, std::string());
}

void InnerLink::SetRemoteIpv6(const std::string &value)
{
    Set(InnerLinKey::REMOTE_IPV6, value);
}

bool InnerLink::HasPtk() const
{
    return Get(InnerLinKey::HAS_PTK, false);
}

void InnerLink::SetPtk(bool value)
{
    Set(InnerLinKey::HAS_PTK, value);
}

int32_t InnerLink::GetLocalCustomPort() const
{
    return Get(InnerLinKey::LOCAL_CUSTOM_PORT, 0);
}

void InnerLink::SetLocalCustomPort(int32_t value)
{
    Set(InnerLinKey::LOCAL_CUSTOM_PORT, value);
}

int32_t InnerLink::GetRemoteCustomPort() const
{
    return Get(InnerLinKey::REMOTE_CUSTOM_PORT, 0);
}

void InnerLink::StopCustomListen(int32_t localCustomPort)
{
    CONN_CHECK_AND_RETURN_LOGE(localCustomPort > 0, CONN_WIFI_DIRECT, "loacl custom port is zero");
    bool hasMoreLocalCustomPort = false;
    LinkManager::GetInstance().ForEach([&hasMoreLocalCustomPort] (InnerLink &link) {
        if (link.GetLocalCustomPort() > 0) {
            hasMoreLocalCustomPort = true;
            return true;
        }
        return false;
    });
    if (!hasMoreLocalCustomPort) {
        CONN_LOGI(CONN_WIFI_DIRECT, "localCustomPort=%{public}d, stop custom listening", localCustomPort);
        AuthNegotiateChannel::StopCustomListening();
    }
}

void InnerLink::SetRemoteCustomPort(int32_t value)
{
    Set(InnerLinKey::REMOTE_CUSTOM_PORT, value);
}

bool InnerLink::GetNewPtkFrame() const
{
    return Get(InnerLinKey::NEW_PTK_FRAME, false);
}

void InnerLink::SetNewPtkFrame(bool value)
{
    Set(InnerLinKey::NEW_PTK_FRAME, value);
}

bool InnerLink::GetLegacyReused() const
{
    return Get(InnerLinKey::IS_LEGACY_REUSED, false);
}

void InnerLink::SetLegacyReused(bool value)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "set legacy reused=%{public}d", value);
    Set(InnerLinKey::IS_LEGACY_REUSED, value);
}

void InnerLink::GenerateLink(uint32_t requestId, int pid, WifiDirectLink &link, bool ipv4)
{
    link.linkId = LinkManager::GetInstance().AllocateLinkId();
    AddId(link.linkId, requestId, pid);
    switch (GetLinkType()) {
        case LinkType::HML:
            link.linkType = WIFI_DIRECT_LINK_TYPE_HML;
            break;
        case LinkType::P2P:
            link.linkType = WIFI_DIRECT_LINK_TYPE_P2P;
            break;
        default:
            link.linkType = WIFI_DIRECT_LINK_TYPE_INVALID;
            break;
    }
    std::string localIp;
    std::string remoteIp;
    if (ipv4 || GetLocalIpv6().empty()) {
        localIp = GetLocalIpv4();
        remoteIp = GetRemoteIpv4();
    } else {
        localIp = GetLocalIpv6();
        remoteIp = GetRemoteIpv6();
    }
    if (strcpy_s(link.localIp, IP_STR_MAX_LEN, localIp.c_str()) != EOK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "local ip cpy failed, link id=%{public}d", link.linkId);
        // fall-through
    }
    if (strcpy_s(link.remoteIp, IP_STR_MAX_LEN, remoteIp.c_str()) != EOK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remote ip cpy failed, link id=%{public}d", link.linkId);
        // fall-through
    }
    link.remotePort = GetRemoteCustomPort();
}

void InnerLink::AddId(int linkId, uint32_t requestId, int pid)
{
    auto item = std::make_shared<LinkIdStruct>();
    item->id = linkId;
    item->requestId = requestId;
    item->pid = pid;
    linkIds_[linkId] = item;
}

void InnerLink::RemoveId(int linkId)
{
    if (linkIds_.find(linkId) == linkIds_.end()) {
        return;
    }
    linkIds_.erase(linkId);
}

bool InnerLink::IsContainId(int linkId) const
{
    return linkIds_.find(linkId) != linkIds_.end();
}

size_t InnerLink::GetReference() const
{
    return linkIds_.size();
}

bool InnerLink::IsProtected() const
{
    LinkState state = Get(InnerLinKey::STATE, LinkState::INVALID_STATE);
    if (state != LinkState::CONNECTED) {
        CONN_LOGI(CONN_WIFI_DIRECT, "state=%{public}d", static_cast<int>(state));
        return false;
    }

    uint64_t currentTime = SoftBusGetSysTimeMs();
    uint64_t changeTime = Get(InnerLinKey::STATE_CHANGE_TIME, uint64_t(0));
    if (currentTime && currentTime - PROTECT_DURATION_MS < changeTime) {
        return true;
    }
    return false;
}

void InnerLink::Dump() const
{
    nlohmann::json object;
    object["LINK_TYPE"] = GetLinkType();
    object["STATE"] = GetState();
    object["LOCAL_INTERFACE"] = GetLocalInterface();
    object["LOCAL_BASE_MAC"] = WifiDirectAnonymizeMac(GetLocalBaseMac());
    object["REMOTE_BASE_MAC"] = WifiDirectAnonymizeMac(GetRemoteBaseMac());
    object["LOCAL_IPV4"] = WifiDirectAnonymizeIp(GetLocalIpv4());
    object["REMOTE_IPV4"] = WifiDirectAnonymizeIp(GetRemoteIpv4());
    object["LOCAL_IPV6"] = WifiDirectAnonymizeIp(GetLocalIpv6());
    object["REMOTE_IPV6"] = WifiDirectAnonymizeIp(GetRemoteIpv6());
    object["IS_BEING_USED_BY_LOCAL"] = IsBeingUsedByLocal();
    object["IS_BEING_USED_BY_REMOTE"] = IsBeingUsedByRemote();
    object["FREQUENCY"] = GetFrequency();
    object["REMOTE_DEVICE_ID"] = WifiDirectAnonymizeDeviceId(GetRemoteDeviceId());
    object["LOCAL_PORT"] = GetLocalPort();
    object["LISTENER_MODULE_ID"] = GetListenerModule();
    object["NEGOTIATION_CHANNEL"] = channel_ != nullptr;
    object["LOCAL_CUSTOM_PORT"] = GetLocalCustomPort();
    object["REMOTE_CUSTOM_PORT"] = GetRemoteCustomPort();

    auto linkIdArrayObject = nlohmann::json::array();
    for (const auto &[key, value] : linkIds_) {
        nlohmann::json linkIdObject;
        linkIdObject["LinkId"] = key;
        linkIdObject["RequestId"] = value->requestId;
        linkIdObject["Pid"] = value->pid;
        linkIdArrayObject.push_back(linkIdObject);
    }
    object["LINKS"] = linkIdArrayObject;
    CONN_LOGI(CONN_WIFI_DIRECT, "%{public}s", object.dump().c_str());
}

std::string InnerLink::ToString(InnerLink::LinkType type)
{
    switch (type) {
        case LinkType::INVALID_TYPE:
            return "INVALID_TYPE";
        case LinkType::P2P:
            return "P2P";
        case LinkType::HML:
            return "HML";
        default:
            return "UNKNOWN_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

std::string InnerLink::ToString(InnerLink::LinkState state)
{
    switch (state) {
        case LinkState::INVALID_STATE:
            return "INVALID_STATE";
        case LinkState::DISCONNECTED:
            return "DISCONNECTED";
        case LinkState::CONNECTED:
            return "CONNECTED";
        case LinkState::CONNECTING:
            return "CONNECTING";
        case LinkState::DISCONNECTING:
            return "DISCONNECTING";
        default:
            return "UNKNOWN_STATE(" + std::to_string(static_cast<int>(state)) + ")";
    }
}
} // namespace OHOS::SoftBus
