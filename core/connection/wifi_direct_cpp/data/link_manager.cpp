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

#include "link_manager.h"

#include "conn_log.h"

#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_manager.h"

namespace OHOS::SoftBus {
int LinkManager::AllocateLinkId()
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    if (currentLinkId_ < 0) {
        currentLinkId_ = 0;
    }
    auto newId = currentLinkId_++;
    while (GetLinkById(newId) != nullptr) {
        newId = currentLinkId_++;
    }
    return newId;
}

std::shared_ptr<InnerLink> LinkManager::GetLinkById(int linkId)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    for (const auto &link : links_) {
        if (link.second->IsContainId(linkId)) {
            return link.second;
        }
    }
    return nullptr;
}

void LinkManager::ForEach(const Checker &checker)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    for (auto &[key, link] : links_) {
        if (checker(*link)) {
            break;
        }
    }
}

bool LinkManager::ProcessIfPresent(InnerLink::LinkType type, const std::string &remoteDeviceId, const Handler &handler)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    auto iterator = links_.find({ type, remoteDeviceId });
    if (iterator == links_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "type=%{public}d remoteDeviceId=%{public}s not found", static_cast<int>(type),
            WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
        return false;
    }

    handler(*iterator->second);
    return true;
}

bool LinkManager::ProcessIfAbsent(InnerLink::LinkType type, const std::string &remoteDeviceId, const Handler &handler)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    auto iterator = links_.find({ type, remoteDeviceId });
    if (iterator != links_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "type=%{public}d remoteDeviceId=%{public}s already exist", static_cast<int>(type),
            WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
        return false;
    }

    auto link = std::make_shared<InnerLink>(type, remoteDeviceId);
    links_.insert({
        { type, remoteDeviceId },
        link
    });
    handler(*link);
    return true;
}

bool LinkManager::ProcessIfPresent(const std::string &remoteMac, const Handler &handler)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    auto iterator = std::find_if(links_.begin(), links_.end(), [&remoteMac](const auto &link) {
        return link.second->GetRemoteBaseMac() == remoteMac;
    });
    if (iterator == links_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "remoteMac=%{public}s not found", WifiDirectAnonymizeMac(remoteMac).c_str());
        return false;
    }

    handler(*iterator->second);
    return true;
}

bool LinkManager::ProcessIfAbsent(const std::string &remoteMac, const Handler &handler)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    auto iterator = std::find_if(links_.begin(), links_.end(), [&remoteMac](const auto &link) {
        return link.second->GetRemoteBaseMac() == remoteMac;
    });
    if (iterator != links_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "remoteMac=%{public}s already exist", WifiDirectAnonymizeMac(remoteMac).c_str());
        return false;
    }

    auto link = std::make_shared<InnerLink>(remoteMac);
    handler(*link);
    auto type = link->GetLinkType();
    auto remoteDeviceId = link->GetRemoteDeviceId();
    links_.insert({
        { type, remoteDeviceId },
        link
    });
    return true;
}

bool LinkManager::ProcessIfPresent(int linkId, const Handler &handler)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    auto iterator = std::find_if(links_.begin(), links_.end(), [&linkId](const auto &link) {
        return link.second->IsContainId(linkId);
    });
    if (iterator == links_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "link id=%{public}d not found", linkId);
        return false;
    }

    handler(*iterator->second);
    return true;
}

void LinkManager::RemoveLink(InnerLink::LinkType type, const std::string &remoteDeviceId)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::shared_ptr<InnerLink> link;
    {
        std::lock_guard lock(lock_);
        auto it = links_.find({type, remoteDeviceId});
        if (it == links_.end()) {
            CONN_LOGE(CONN_WIFI_DIRECT, "not find remoteDeviceId=%{public}s",
                      WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
            return;
        }
        link = it->second;
        links_.erase(it);
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "find remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
    if (link != nullptr && link->GetState() == InnerLink::LinkState::CONNECTED) {
        GetWifiDirectManager()->notifyOffline(link->GetRemoteBaseMac().c_str(), link->GetRemoteIpv4().c_str(),
                                              link->GetRemoteDeviceId().c_str(), link->GetLocalIpv4().c_str());
    }
}

void LinkManager::RemoveLink(const std::string &remoteMac)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::shared_ptr<InnerLink> link;
    {
        std::lock_guard lock(lock_);
        for (const auto &[key, value] : links_) {
            if (!remoteMac.empty() && remoteMac == value->GetRemoteBaseMac()) {
                CONN_LOGI(CONN_WIFI_DIRECT, "find remoteMac=%{public}s", WifiDirectAnonymizeMac(remoteMac).c_str());
                link = value;
                links_.erase(key);
                break;
            }
        }
    }
    if (link == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find remoteMac=%{public}s", WifiDirectAnonymizeMac(remoteMac).c_str());
        return;
    }
    if (link->GetState() == InnerLink::LinkState::CONNECTED) {
        GetWifiDirectManager()->notifyOffline(link->GetRemoteBaseMac().c_str(), link->GetRemoteIpv4().c_str(),
                                              link->GetRemoteDeviceId().c_str(), link->GetLocalIpv4().c_str());
    }
}

void LinkManager::RemoveLinks(InnerLink::LinkType type, bool onlyRemoveConnected)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::vector<std::shared_ptr<InnerLink>> links;
    {
        std::lock_guard lock(lock_);
        auto it = links_.begin();
        while (it != links_.end()) {
            auto condition = onlyRemoveConnected ?
                (it->first.first == type && it->second->GetState() == InnerLink::LinkState::CONNECTED) :
                it->first.first == type;
            if (condition) {
                CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s",
                          WifiDirectAnonymizeDeviceId(it->second->GetRemoteDeviceId()).c_str());
                links.push_back(it->second);
                it = links_.erase(it);
            } else {
                it++;
            }
        }
    }

    for (const auto &link : links) {
        if (link->GetState() == InnerLink::LinkState::CONNECTED) {
            GetWifiDirectManager()->notifyOffline(link->GetRemoteBaseMac().c_str(), link->GetRemoteIpv4().c_str(),
                                                  link->GetRemoteDeviceId().c_str(), link->GetLocalIpv4().c_str());
        }
    }
}

void LinkManager::GetAllLinksBasicInfo(std::vector<InnerLinkBasicInfo> &infos)
{
    std::lock_guard lock(lock_);
    for (const auto &[key, value] : links_) {
        InnerLinkBasicInfo info = { 0 };
        info.isBeingUsedByRemote = value->IsBeingUsedByRemote();
        info.state = value->GetState();
        info.linkType = value->GetLinkType();
        info.freq = value->GetFrequency();
        info.remoteDeviceId = value->GetRemoteDeviceId();
        info.remoteIpv4 = value->GetRemoteIpv4();
        info.remoteBaseMac = value->GetRemoteBaseMac();
        infos.push_back(info);
    }
}

std::shared_ptr<InnerLink> LinkManager::GetReuseLink(const std::string &remoteMac)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    for (const auto &[key, link] : links_) {
        if (link->GetRemoteBaseMac() == remoteMac && link->GetState() == InnerLink::LinkState::CONNECTED) {
            return link;
        }
    }
    CONN_LOGE(CONN_WIFI_DIRECT, "not find remoteMac=%{public}s", WifiDirectAnonymizeMac(remoteMac).c_str());
    return nullptr;
}

std::shared_ptr<InnerLink> LinkManager::GetReuseLink(
    WifiDirectConnectType connectType, const std::string &remoteDeviceId)
{
    WifiDirectLinkType linkType = WIFI_DIRECT_LINK_TYPE_P2P;
    if (connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML ||
        connectType == WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML ||
        connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML ||
        connectType == WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML) {
        linkType = WIFI_DIRECT_LINK_TYPE_HML;
    }

    return GetReuseLink(linkType, remoteDeviceId);
}

std::shared_ptr<InnerLink> LinkManager::GetReuseLink(
    WifiDirectLinkType wifiDirectLinkType, const std::string &remoteDeviceId)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    InnerLink::LinkType linkType { InnerLink::LinkType::INVALID_TYPE };
    if (wifiDirectLinkType == WIFI_DIRECT_LINK_TYPE_HML) {
        linkType = InnerLink::LinkType::HML;
    }
    if (wifiDirectLinkType == WIFI_DIRECT_LINK_TYPE_P2P) {
        linkType = InnerLink::LinkType::P2P;
    }
    std::lock_guard lock(lock_);
    auto iterator = links_.find({linkType, remoteDeviceId});
    if (iterator == links_.end() || iterator->second->GetState() != InnerLink::LinkState::CONNECTED) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find remoteDeviceId=%{public}s",
                  WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
        return nullptr;
    }
    return iterator->second;
}

void LinkManager::RefreshRelationShip(const std::string &remoteDeviceId, const std::string &remoteMac)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s, remoteMac=%{public}s",
              WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str(), WifiDirectAnonymizeMac(remoteMac).c_str());
    std::lock_guard lock(lock_);
    auto it = links_.find({ InnerLink::LinkType::HML, remoteMac });
    if (it == links_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find %{public}s as device id", WifiDirectAnonymizeMac(remoteMac).c_str());
        return;
    }
    auto link = it->second;
    links_.erase(it);

    link->SetRemoteDeviceId(remoteDeviceId);
    auto result = links_.insert({{ InnerLink::LinkType::HML, remoteDeviceId }, link });
    if (!result.second) {
        CONN_LOGE(CONN_WIFI_DIRECT, "insert by remoteDeviceId failed, use remoteMac");
        links_.insert({{ InnerLink::LinkType::HML, remoteMac }, link });
    }
}

void LinkManager::Dump() const
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(lock_);
    for (const auto &[key, value] : links_) {
        value->Dump();
    }
    if (links_.empty()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "no inner link");
    }
}

void LinkManager::Dump(std::list<std::shared_ptr<LinkSnapshot>> &snapshots)
{
    LinkManager::GetInstance().ForEach([&snapshots](const InnerLink &link) {
        snapshots.push_back(std::make_shared<LinkSnapshot>(link));
        return true;
    });
}
} // namespace OHOS::SoftBus
