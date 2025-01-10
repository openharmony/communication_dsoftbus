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

#ifndef INTERFACE_SNAPSHOT_H
#define INTERFACE_SNAPSHOT_H

#include <list>
#include <nlohmann/json.hpp>
#include <string>

#include "data/interface_info.h"
#include "wifi_direct_snapshot.h"

namespace OHOS::SoftBus {
class InterfaceSnapshot : public WifiDirectSnapshot {
public:
    explicit InterfaceSnapshot(const InterfaceInfo &info);
    void Marshalling(nlohmann::json &output) override;

private:
    std::string name_;
    std::string ip_;
    std::string role_;
    int bandWidth_;
    int enableState_;
    std::string ssid_;
    int p2pListenPort_;
    int p2pListenModule_;
    std::string p2pGroupConfig_;
    std::string baseMac_;
    std::string dynamicMac_;
    std::string psk_;
    int center20M_;
    int connectedDeviceCount_;
    int capability_;
    int reuseCount_;
    int isAvailable_;
    int physicalRate_;
};
} // namespace OHOS::SoftBus

#endif