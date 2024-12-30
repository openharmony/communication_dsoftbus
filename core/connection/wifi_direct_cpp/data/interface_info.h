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
#ifndef INTERFACE_INFO_H
#define INTERFACE_INFO_H

#include <mutex>
#include "info_container.h"
#include "ipv4_info.h"
#include "link_info.h"
#include "wifi_direct_defines.h"

namespace OHOS::SoftBus {

enum class InterfaceInfoKey {
    DYNAMIC_MAC = 0,
    INTERFACE_NAME = 1,
    CAPABILITY = 2,
    WIFI_DIRECT_ROLE = 3,
    BASE_MAC = 4,
    PHYSICAL_RATE = 5,
    SUPPORT_BAND = 6,
    CHANNEL_AND_BANDWIDTH = 7,
    COEXIST_CHANNEL_LIST = 8,
    HML_LINK_COUNT = 9,
    ISLAND_DEVICE_COUNT = 10,
    COEXIST_VAP_COUNT = 11,
    IPV4 = 12,
    CHANNEL_5G_LIST = 13,
    SSID = 14,
    PORT = 15,
    IS_WIDE_BAND_SUPPORT = 16,
    CENTER_20M = 17,
    CENTER_FREQUENCY1 = 18,
    CENTER_FREQUENCY2 = 19,
    BANDWIDTH = 20,
    WIFI_CFG_INFO = 21,
    IS_ENABLE = 22,
    CONNECTED_DEVICE_COUNT = 23,
    PSK = 24,
    REUSE_COUNT = 25,
    IS_AVAILABLE = 26,
    COEXIST_RULE = 27,
    LINK_MODE = 28,
    LISTEN_MODULE = 29,
};

class InterfaceInfo : public Serializable, public InfoContainer<InterfaceInfoKey> {
public:
    enum InterfaceType {
        P2P,
        HML,
        MAX,
    };

    int Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const override;
    int Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input) override;

    static void MarshallingString(
        WifiDirectProtocol &protocol, InterfaceInfoKey key, Serializable::ValueType type, const std::string &value);

    /* Get/Set */
    void SetName(const std::string &value);
    std::string GetName() const;

    std::vector<uint8_t> GetChannelAndBandWidth() const;

    void SetIpString(const Ipv4Info &ipv4Info);
    Ipv4Info GetIpString() const;

    void SetRole(LinkInfo::LinkMode value);
    LinkInfo::LinkMode GetRole() const;

    void SetSsid(const std::string &value);
    std::string GetSsid() const;

    // P2P links share the same listen port, so define port in interface info
    void SetP2pListenPort(const int &value);
    int GetP2pListenPort() const;

    // P2P links share the same listen module, so define module in interface info
    void SetP2pListenModule(const int &value);
    int GetP2pListenModule() const;

    void SetP2pGroupConfig(const std::string &groupConfig);
    std::string GetP2pGroupConfig() const;

    void SetDynamicMac(const std::string &value);
    std::string GetDynamicMac() const;

    void SetPsk(const std::string &value);
    std::string GetPsk() const;

    void SetCenter20M(int value);
    int GetCenter20M() const;

    void SetBandWidth(int value);
    int GetBandWidth() const;

    void SetIsEnable(bool value);
    bool IsEnable() const;

    void SetConnectedDeviceCount(int32_t value);
    int32_t GetConnectedDeviceCount() const;

    void SetBaseMac(const std::string &value);
    std::string GetBaseMac() const;

    void SetCapability(int32_t value);
    int32_t GetCapability() const;

    void SetReuseCount(int value);
    int GetReuseCount() const;

    void SetChannel5GList(const std::vector<int> &value);
    std::vector<int> GetChannel5GList() const;

    void SetIsAvailable(bool value);
    bool IsAvailable() const;
    void RefreshIsAvailable();

    void SetPhysicalRate(int value);
    int GetPhysicalRate() const;

    void IncreaseRefCount();
    void DecreaseRefCount();
};
} // namespace OHOS::SoftBus
#endif