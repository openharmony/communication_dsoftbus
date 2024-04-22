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
    if (listenerModuleId != UNUSE_BUTT) {
        CONN_LOGI(CONN_WIFI_DIRECT, "stop auth listening");
        if (GetLinkType() == LinkType::HML) {
            AuthNegotiateChannel::StopListening(AUTH_LINK_TYPE_ENHANCED_P2P, listenerModuleId);
        } else {
            AuthNegotiateChannel::StopListening(AUTH_LINK_TYPE_P2P, listenerModuleId);
        }
    }
    if (!GetLocalIpv4().empty() && !GetRemoteIpv4().empty() && !GetRemoteBaseMac().empty()) {
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

void InnerLink::GenerateLink(uint32_t requestId, int pid, WifiDirectLink &link)
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
    auto localIpv4 = GetLocalIpv4();
    if (strcpy_s(link.localIp, IP_STR_MAX_LEN, localIpv4.c_str()) != EOK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "local ip cpy failed, link id=%{public}d", link.linkId);
        // fall-through
    }
    auto remoteIpv4 = GetRemoteIpv4();
    if (strcpy_s(link.remoteIp, IP_STR_MAX_LEN, remoteIpv4.c_str()) != EOK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remote ip cpy failed, link id=%{public}d", link.linkId);
        // fall-through
    }
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
    object["LOCAL_IPV6"] = GetLocalIpv6();
    object["REMOTE_IPV6"] = GetRemoteIpv6();
    object["IS_BEING_USED_BY_LOCAL"] = IsBeingUsedByLocal();
    object["IS_BEING_USED_BY_REMOTE"] = IsBeingUsedByRemote();
    object["FREQUENCY"] = GetFrequency();
    object["REMOTE_DEVICE_ID"] = WifiDirectAnonymizeDeviceId(GetRemoteDeviceId());
    object["LOCAL_PORT"] = GetLocalPort();
    object["LISTENER_MODULE_ID"] = GetListenerModule();
    object["NEGOTIATION_CHANNEL"] = channel_ != nullptr;

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
} // namespace OHOS::SoftBus
