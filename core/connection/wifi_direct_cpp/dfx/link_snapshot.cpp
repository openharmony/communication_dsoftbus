/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "link_snapshot.h"
#include "utils/wifi_direct_anonymous.h"

namespace OHOS::SoftBus {
LinkSnapshot::LinkSnapshot(const InnerLink &link)
{
    linkType_ = InnerLink::ToString(link.GetLinkType());
    linkState_ = InnerLink::ToString(link.GetState());
    localMac_ = WifiDirectAnonymize(link.GetLocalBaseMac());
    remoteMac_ = WifiDirectAnonymize(link.GetRemoteBaseMac());
    localIpv4_ = WifiDirectAnonymize(link.GetLocalIpv4());
    remoteIpv4_ = WifiDirectAnonymize(link.GetRemoteIpv4());
    localIpv6_ = WifiDirectAnonymize(link.GetLocalIpv6());
    remoteIpv6_ = WifiDirectAnonymize(link.GetRemoteIpv6());
    isBeingUsedByLocal_ = link.IsBeingUsedByLocal();
    isBeingUsedByRemote_ = link.IsBeingUsedByRemote();
    localInterface_ = link.GetLocalInterface();
    localDynamicMac_ = WifiDirectAnonymize(link.GetLocalDynamicMac());
    remoteInterface_ = link.GetRemoteInterface();
    remoteBaseMac_ = WifiDirectAnonymize(link.GetRemoteBaseMac());
    frequency_ = link.GetFrequency();
    remoteDeviceId_ = WifiDirectAnonymize(link.GetRemoteDeviceId());
    localPort_ = link.GetLocalPort();
    hasPtk_ = link.HasPtk();
    localCustomPort_ = link.GetLocalCustomPort();
    remoteCustomPort_ = link.GetRemoteCustomPort();
    legacyReused_ = link.GetLegacyReused();
}

void LinkSnapshot::Marshalling(nlohmann::json &output)
{
    nlohmann::json json;
    json["dumpType"] = "link";
    json["linkType"] = linkType_;
    json["linkStatus"] = linkState_;
    json["localMac"] = localMac_;
    json["remoteMac"] = remoteMac_;
    json["localIpv4"] = localIpv4_;
    json["remoteIpv4"] = remoteIpv4_;
    json["localIpv6"] = localIpv6_;
    json["remoteIpv6"] = remoteIpv6_;
    json["isBeingUsedByLocal"] = isBeingUsedByLocal_;
    json["isBeingUsedByRemote"] = isBeingUsedByRemote_;
    json["localInterface"] = localInterface_;
    json["localDynamicMac"] = localDynamicMac_;
    json["remoteInterface"] = remoteInterface_;
    json["remoteBaseMac"] = remoteBaseMac_;
    json["frequency"] = frequency_;
    json["remoteDeviceId"] = remoteDeviceId_;
    json["localPort"] = localPort_;
    json["hasPtk"] = hasPtk_;
    json["localCustomPort"] = localCustomPort_;
    json["remoteCustomPort"] = remoteCustomPort_;
    json["legacyReused"] = legacyReused_;
    output.push_back(json);
}
} // namespace OHOS::SoftBus