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
#ifndef WIFI_DIRECT_LINK_INFO_H
#define WIFI_DIRECT_LINK_INFO_H

#include <any>
#include <map>
#include "ipv4_info.h"
#include "serializable.h"
#include "info_container.h"
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
class NegotiateMessage;
enum class LinkInfoKey {
    LOCAL_INTERFACE = 0,
    REMOTE_INTERFACE = 1,
    LOCAL_LINK_MODE = 2,
    REMOTE_LINK_MODE = 3,
    CENTER_20M = 4,
    CENTER_FREQUENCY1 = 5,
    CENTER_FREQUENCY2 = 6,
    BANDWIDTH = 7,
    SSID = 8,
    BSSID = 9,
    PSK = 10,
    IS_DHCP = 11,
    LOCAL_IPV4 = 12,
    REMOTE_IPV4 = 13,
    AUTH_PORT = 14,
    MAX_PHYSICAL_RATE = 15,
    REMOTE_DEVICE = 16,
    STATUS = 17,
    LOCAL_BASE_MAC = 18,
    REMOTE_BASE_MAC = 19,
    IS_CLIENT = 20,
    LOCAL_IPV6 = 21,
    REMOTE_IPV6 = 22,
    CUSTOM_PORT = 23,
    IPADDR_TYPE = 24,
};

class LinkInfo : public Serializable, public InfoContainer<LinkInfoKey> {
public:
    enum class LinkMode {
        INVALID = -1,
        NONE = 0,
        STA = 1,
        AP = 2,
        GO = 4,
        GC = 8,
        HML = 16,
    };

    LinkInfo() = default;
    LinkInfo(const std::string &localInterface, const std::string &remoteInterface,
             LinkMode localMode, LinkMode remoteMode);

    int Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const override;
    int Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input) override;

    void SetLocalInterface(const std::string &interface);
    std::string GetLocalInterface() const;

    void SetRemoteInterface(const std::string &interface);
    std::string GetRemoteInterface() const;

    void SetLocalLinkMode(LinkMode mode);
    LinkMode GetLocalLinkMode() const;

    void SetRemoteLinkMode(LinkMode mode);
    LinkMode GetRemoteLinkMode() const;

    void SetCenter20M(int freq);
    int GetCenter20M() const;

    void SetCenterFrequency1(int freq);
    int GetCenterFrequency1() const;

    void SetCenterFrequency2(int freq);
    int GetCenterFrequency2() const;

    void SetBandWidth(int bandWidth);
    int GetBandWidth() const;

    void SetSsid(const std::string &ssid);
    std::string GetSsid() const;

    void SetBssid(const std::string &bssid);
    std::string GetBssid() const;

    void SetPsk(const std::string &psk);
    std::string GetPsk() const;

    void SetIsDhcp(bool isDhcp);
    bool GetIsDhcp() const;

    void SetLocalIpv4Info(const Ipv4Info &ipv4Info);
    Ipv4Info GetLocalIpv4Info() const;

    void SetRemoteIpv4Info(const Ipv4Info &ipv4Info);
    Ipv4Info GetRemoteIpv4Info() const;

    void SetAuthPort(int port);
    int GetAuthPort() const;

    void SetMaxPhysicalRate(int rate);
    int GetMaxPhysicalRate() const;

    void SetRemoteDevice(const std::string &device);
    std::string GetRemoteDevice() const;

    void SetStatus(int status);
    int GetStatus() const;

    void SetLocalBaseMac(const std::string &mac);
    std::string GetLocalBaseMac() const;

    void SetRemoteBaseMac(const std::string &mac);
    std::string GetRemoteBaseMac() const;

    void SetIsClient(bool client);
    bool GetIsClient() const;

    void SetLocalIpv6(const std::string &value);
    std::string GetLocalIpv6() const;

    void SetRemoteIpv6(const std::string &value);
    std::string GetRemoteIpv6() const;

    void SetCustomPort(int value);
    int GetCustomPort();

    void SetIpAddrType(enum IpAddrType value);
    enum IpAddrType GetIpAddrType();

    static std::string ToString(LinkMode mode);
};
}
#endif
