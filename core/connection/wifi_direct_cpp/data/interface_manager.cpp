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

#include "interface_manager.h"

#include "adapter/p2p_adapter.h"
#include "conn_log.h"
#include "data/interface_info.h"
#include "link_info.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
int InterfaceManager::UpdateInterface(InterfaceInfo::InterfaceType type, const Updater &updater)
{
    std::unique_lock lock(lock_);
    return updater(interfaces_[static_cast<int>(type)]);
}

int InterfaceManager::ReadInterface(InterfaceInfo::InterfaceType type, const Reader &reader)
{
    std::shared_lock lock(lock_);
    return reader(interfaces_[static_cast<int>(type)]);
}

bool InterfaceManager::IsInterfaceAvailable(InterfaceInfo::InterfaceType type, bool forShare) const
{
    std::shared_lock lock(lock_);
    auto info = interfaces_[static_cast<int>(type)];
    if (!info.IsEnable()) {
        CONN_LOGW(CONN_WIFI_DIRECT, "isEnable=0, interface type=%{public}d", static_cast<int>(type));
        return false;
    }

    if (info.GetRole() == LinkInfo::LinkMode::GC) {
        CONN_LOGW(CONN_WIFI_DIRECT, "already gc");
        return false;
    }

    (void)forShare;
    return true;
}

void InterfaceManager::LockInterface(InterfaceInfo::InterfaceType type, const std::string &owner)
{
    // ATTENTION: MUST NOT access interface lock under interface manager lock, otherwise deadlock will happen
    CONN_LOGI(CONN_WIFI_DIRECT, "current owner=%{public}s",
        WifiDirectAnonymizeDeviceId(exclusives_[static_cast<int>(type)].owner_).c_str());
    exclusives_[static_cast<int>(type)].lock_.lock();
    exclusives_[static_cast<int>(type)].owner_ = owner;
    CONN_LOGI(CONN_WIFI_DIRECT, "success owner=%{public}s",
        WifiDirectAnonymizeDeviceId(exclusives_[static_cast<int>(type)].owner_).c_str());
}

void InterfaceManager::UnlockInterface(InterfaceInfo::InterfaceType type)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "current owner=%{public}s",
        WifiDirectAnonymizeDeviceId(exclusives_[static_cast<int>(type)].owner_).c_str());
    // ATTENTION: MUST NOT access interface lock under interface manager lock, otherwise deadlock will happen
    exclusives_[static_cast<int>(type)].lock_.unlock();
    exclusives_[static_cast<int>(type)].owner_ = "";
}

void InterfaceManager::InitInterface(InterfaceInfo::InterfaceType type)
{
    std::string name;
    int32_t capability = 0;
    if (type == InterfaceInfo::InterfaceType::P2P) {
        name = IF_NAME_P2P;
        capability = static_cast<int32_t>(LinkInfo::LinkMode::GO) | static_cast<uint32_t>(LinkInfo::LinkMode::GC);
    }
    if (type == InterfaceInfo::InterfaceType::HML) {
        name = IF_NAME_HML;
        capability = static_cast<int32_t>(LinkInfo::LinkMode::HML);
    }
    interfaces_[type].SetRole(LinkInfo::LinkMode::NONE);
    interfaces_[type].SetName(name);
    interfaces_[type].SetIsEnable(P2pAdapter::IsWifiP2pEnabled());
    interfaces_[type].SetBaseMac(WifiDirectUtils::MacArrayToString(WifiDirectUtils::GetInterfaceMacAddr(name)));
    interfaces_[type].SetCapability(capability);
}

void InterfaceManager::Init()
{
    GetInstance().InitInterface(InterfaceInfo::InterfaceType::P2P);
    GetInstance().InitInterface(InterfaceInfo::InterfaceType::HML);
}

void InterfaceManager::Dump(std::list<std::shared_ptr<InterfaceSnapshot>> &snapshots)
{
    std::shared_lock lock(lock_);
    for (const auto &interface : interfaces_) {
        snapshots.push_back(std::make_shared<InterfaceSnapshot>(interface));
    }
}
} // namespace OHOS::SoftBus