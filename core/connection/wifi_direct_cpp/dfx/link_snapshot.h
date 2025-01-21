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

#ifndef LINK_SNAPSHOT_H
#define LINK_SNAPSHOT_H

#include <nlohmann/json.hpp>
#include <string>

#include "data/inner_link.h"
#include "wifi_direct_snapshot.h"

namespace OHOS::SoftBus {
class LinkSnapshot : public WifiDirectSnapshot {
public:
    explicit LinkSnapshot(const InnerLink &link);
    void Marshalling(nlohmann::json &output) override;

private:
    std::string linkType_;
    std::string linkState_;
    std::string localMac_;
    std::string remoteMac_;
    std::string localIpv4_;
    std::string remoteIpv4_;
    std::string localIpv6_;
    std::string remoteIpv6_;
    bool isBeingUsedByLocal_;
    bool isBeingUsedByRemote_;
    std::string localInterface_;
    std::string localDynamicMac_;
    std::string remoteInterface_;
    std::string remoteBaseMac_;
    int frequency_;
    std::string remoteDeviceId_;
    int localPort_;
    bool hasPtk_;
    int localCustomPort_;
    int remoteCustomPort_;
    int legacyReused_;
};
} // namespace OHOS::SoftBus
#endif