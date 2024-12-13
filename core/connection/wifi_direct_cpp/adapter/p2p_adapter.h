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

#ifndef P2P_ADAPTER_H
#define P2P_ADAPTER_H

#include "data/interface_info.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_types.h"
#include <sstream>
#include <string>
#include <vector>

namespace OHOS::SoftBus {
class P2pAdapter {
public:
    enum ConnectionState {
        P2P_DISCONNECTED = 0,
        P2P_CONNECTED,
    };

    struct CreateGroupParam {
        int32_t frequency;
        bool isWideBandSupported;
    };

    struct ConnectParam {
        std::string groupConfig;
        bool isLegacyGo;
        bool isNeedDhcp;
        std::string gcIp;
        std::string goIp;
    };

    struct DestroyGroupParam {
        std::string interface;
    };

    struct WifiDirectP2pDeviceInfo {
        std::string address;
        std::string randomMac;
    };

    struct WifiDirectP2pGroupInfo {
        bool isGroupOwner;
        int32_t frequency;
        std::string interface;
        std::string goIpAddr;
        WifiDirectP2pDeviceInfo groupOwner;
        std::vector<WifiDirectP2pDeviceInfo> clientDevices;
    };

    static int32_t GetChannel5GListIntArray(std::vector<int> &frequencyList);
    static bool IsWifiP2pEnabled();
    static std::string GetInterfaceCoexistCap();
    static int32_t GetStationFrequency();

    static int32_t P2pCreateGroup(const CreateGroupParam &param);
    static int32_t P2pConnectGroup(const ConnectParam &param);
    static int32_t P2pShareLinkReuse();
    static int32_t DestroyGroup(const DestroyGroupParam &param);
    static int32_t P2pShareLinkRemoveGroup(const DestroyGroupParam &param);
    static int32_t GetStationFrequencyWithFilter();
    static int32_t GetRecommendChannel();
    static int32_t GetSelfWifiConfigInfo(std::string &config);
    static int32_t SetPeerWifiConfigInfo(const std::string &config);
    static int32_t GetGroupInfo(WifiDirectP2pGroupInfo &groupInfoOut);
    static int32_t GetGroupConfig(std::string &groupConfigString);
    static int32_t GetIpAddress(std::string &ipString);
    static std::string GetMacAddress();
    static int32_t GetDynamicMacAddress(std::string &macString);
    static int32_t RequestGcIp(const std::string &macString, std::string &ipString);
    static int32_t P2pConfigGcIp(const std::string &interface, const std::string &ip);
    static int32_t SetPeerWifiConfigInfoV2(const uint8_t *cfg, size_t size);
    static bool IsWideBandSupported();
    static bool IsWifiEnable();
    static bool IsWifiConnected();
    using GetCoexConflictCodeHook = std::function<int(const char *, int32_t)>;
    static void Register(const GetCoexConflictCodeHook &coexConflictor);
    static int GetCoexConflictCode(const char *ifName, int32_t channelId);
    static int GetApChannel();
    static int32_t GetP2pGroupFrequency();

private:
    static constexpr int P2P_GROUP_CONFIG_INDEX_SSID = 0;
    static constexpr int P2P_GROUP_CONFIG_INDEX_BSSID = 1;
    static constexpr int P2P_GROUP_CONFIG_INDEX_SHARE_KEY = 2;
    static constexpr int P2P_GROUP_CONFIG_INDEX_FREQ = 3;
    static constexpr int P2P_GROUP_CONFIG_INDEX_MODE = 4;
    static constexpr int P2P_GROUP_CONFIG_INDEX_MAX = 5;

    static inline GetCoexConflictCodeHook getCoexConflictCodeHook_;
};
} // namespace OHOS::SoftBus
#endif
