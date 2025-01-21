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

#ifndef LINK_MANAGER_H
#define LINK_MANAGER_H

#include <atomic>
#include <list>
#include <map>
#include <mutex>
#include <functional>
#include "dfx/link_snapshot.h"
#include "inner_link.h"
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
class LinkManager {
public:
    static LinkManager& GetInstance()
    {
        static LinkManager instance;
        return instance;
    }

    using Handler = std::function<void(InnerLink &)>;
    using Checker = std::function<bool(InnerLink &)>;

    int AllocateLinkId();
    std::shared_ptr<InnerLink> GetLinkById(int linkId);

    void ForEach(const Checker &checker);
    bool ProcessIfPresent(InnerLink::LinkType type, const std::string &remoteDeviceId, const Handler &handler);
    bool ProcessIfAbsent(InnerLink::LinkType type, const std::string &remoteDeviceId, const Handler &handler);

    bool ProcessIfPresent(const std::string &remoteMac, const Handler &handler);
    bool ProcessIfAbsent(const std::string &remoteMac, const Handler &handler);

    bool ProcessIfPresent(int linkId, const Handler &handler);
    void RemoveLink(InnerLink::LinkType type, const std::string &remoteDeviceId);
    void RemoveLink(const std::string &remoteMac);
    void RemoveLinks(InnerLink::LinkType type, bool onlyRemoveConnected = false);

    void GetAllLinksBasicInfo(std::vector<InnerLinkBasicInfo> &infos);

    std::shared_ptr<InnerLink> GetReuseLink(const std::string &remoteMac);
    std::shared_ptr<InnerLink> GetReuseLink(WifiDirectConnectType connectType, const std::string &remoteDeviceId);
    std::shared_ptr<InnerLink> GetReuseLink(WifiDirectLinkType linkType, const std::string &remoteDeviceId);
    void RefreshRelationShip(const std::string &remoteDeviceId, const std::string &remoteMac);

    void Dump() const;
    
    void Dump(std::list<std::shared_ptr<LinkSnapshot>> &snapshots);

private:
    mutable std::recursive_mutex lock_;
    /* key = {LinkType, RemoteDeviceId} */
    std::map<std::pair<InnerLink::LinkType, std::string>, std::shared_ptr<InnerLink>> links_;
    std::atomic<int> currentLinkId_ = 0;
};
}
#endif
