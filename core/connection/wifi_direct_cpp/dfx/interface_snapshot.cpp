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

#include "interface_snapshot.h"
#include "utils/wifi_direct_anonymous.h"

namespace OHOS::SoftBus {
InterfaceSnapshot::InterfaceSnapshot(const InterfaceInfo &info)
{
    name_ = info.GetName();
    ip_ = WifiDirectAnonymize(info.GetIpString().ToIpString());
    role_ = LinkInfo::ToString(info.GetRole());
    bandWidth_ = info.GetBandWidth();
    enableState_ = info.IsEnable();
    ssid_ = info.GetSsid();
    p2pListenPort_ = info.GetP2pListenPort();
    p2pListenModule_ = info.GetP2pListenModule();
    p2pGroupConfig_ = info.GetP2pGroupConfig();
    baseMac_ = WifiDirectAnonymize(info.GetBaseMac());
    dynamicMac_ = WifiDirectAnonymize(info.GetDynamicMac());
    psk_ = info.GetPsk();
    center20M_ = info.GetCenter20M();
    connectedDeviceCount_ = info.GetConnectedDeviceCount();
    capability_ = info.GetCapability();
    reuseCount_ = info.GetReuseCount();
    isAvailable_ = info.IsAvailable();
    physicalRate_ = info.GetPhysicalRate();
}

void InterfaceSnapshot::Marshalling(nlohmann::json &output)
{
    nlohmann::json json;
    json["dumpType"] = "interface";
    json["name"] = name_;
    json["ip"] = ip_;
    json["role"] = role_;
    json["bandWidth"] = bandWidth_;
    json["enableState"] = enableState_;
    json["ssid"] = ssid_;
    json["p2pListenPort"] = p2pListenPort_;
    json["p2pListenModule"] = p2pListenModule_;
    json["p2pGroupConfig"] = p2pGroupConfig_;
    json["baseMac"] = baseMac_;
    json["dynamicMac"] = dynamicMac_;
    json["psk"] = psk_;
    json["center20M"] = center20M_;
    json["connectedDeviceCount"] = connectedDeviceCount_;
    json["capability"] = capability_;
    json["reuseCount"] = reuseCount_;
    json["isAvailable"] = isAvailable_;
    json["physicalRate"] = physicalRate_;
    output.push_back(json);
}
} // namespace OHOS::SoftBus