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

#include "link_info.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "protocol/wifi_direct_protocol.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
template<> InfoContainer<LinkInfoKey>::KeyTypeTable InfoContainer<LinkInfoKey>::keyTypeTable_ = {
    { LinkInfoKey::LOCAL_INTERFACE, Serializable::ValueType::STRING },
    { LinkInfoKey::REMOTE_INTERFACE, Serializable::ValueType::STRING },
    { LinkInfoKey::LOCAL_LINK_MODE, Serializable::ValueType::INT },
    { LinkInfoKey::REMOTE_LINK_MODE, Serializable::ValueType::INT },
    { LinkInfoKey::CENTER_20M, Serializable::ValueType::INT },
    { LinkInfoKey::CENTER_FREQUENCY1, Serializable::ValueType::INT },
    { LinkInfoKey::CENTER_FREQUENCY2, Serializable::ValueType::INT },
    { LinkInfoKey::BANDWIDTH, Serializable::ValueType::INT },
    { LinkInfoKey::SSID, Serializable::ValueType::STRING },
    { LinkInfoKey::BSSID, Serializable::ValueType::STRING },
    { LinkInfoKey::PSK, Serializable::ValueType::STRING },
    { LinkInfoKey::IS_DHCP, Serializable::ValueType::BOOL },
    { LinkInfoKey::LOCAL_IPV4, Serializable::ValueType::IPV4_INFO },
    { LinkInfoKey::REMOTE_IPV4, Serializable::ValueType::IPV4_INFO },
    { LinkInfoKey::AUTH_PORT, Serializable::ValueType::INT },
    { LinkInfoKey::MAX_PHYSICAL_RATE, Serializable::ValueType::INT },
    { LinkInfoKey::REMOTE_DEVICE, Serializable::ValueType::STRING },
    { LinkInfoKey::STATUS, Serializable::ValueType::INT },
    { LinkInfoKey::LOCAL_BASE_MAC, Serializable::ValueType::STRING },
    { LinkInfoKey::REMOTE_BASE_MAC, Serializable::ValueType::STRING },
    { LinkInfoKey::LOCAL_IPV6, Serializable::ValueType::STRING },
    { LinkInfoKey::REMOTE_IPV6, Serializable::ValueType::STRING },
    { LinkInfoKey::CUSTOM_PORT, Serializable::ValueType::INT },
    { LinkInfoKey::IPADDR_TYPE, Serializable::ValueType::INT },
};

LinkInfo::LinkInfo(const std::string &localInterface, const std::string &remoteInterface, LinkMode localMode,
                   LinkMode remoteMode)
{
    SetLocalInterface(localInterface);
    SetRemoteInterface(remoteInterface);
    SetLocalLinkMode(localMode);
    SetRemoteLinkMode(remoteMode);
}

int LinkInfo::Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const
{
    for (const auto &[key, value] : values_) {
        auto type = keyTypeTable_[key];
        switch (type) {
            case Serializable::ValueType::BOOL: {
                uint8_t data = std::any_cast<bool>(value);
                protocol.Write(static_cast<int>(key), type, &data, sizeof(data));
            }
                break;
            case Serializable::ValueType::INT: {
                std::vector<uint8_t> data;
                WifiDirectUtils::IntToBytes(std::any_cast<int>(value), sizeof(int), data);
                protocol.Write(static_cast<int>(key), type, data.data(), data.size());
            }
                break;
            case Serializable::ValueType::STRING: {
                const auto &data = std::any_cast<const std::string &>(value);
                protocol.Write(static_cast<int>(key), type, (uint8_t *)data.c_str(), data.length());
            }
                break;
            case Serializable::ValueType::IPV4_INFO: {
                const auto &ipv4Info = std::any_cast<const Ipv4Info &>(value);
                std::vector<uint8_t> ipv4InfoOutput;
                ipv4Info.Marshalling(ipv4InfoOutput);
                protocol.Write(static_cast<int>(key), type, ipv4InfoOutput.data(), ipv4InfoOutput.size());
            }
                break;
            default:
                continue;
        }
    }

    protocol.GetOutput(output);
    return SOFTBUS_OK;
}

int LinkInfo::Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input)
{
    int key = 0;
    uint8_t *data = nullptr;
    size_t size = 0;

    protocol.SetInput(input);
    while (protocol.Read(key, data, size)) {
        auto valueType = keyTypeTable_[LinkInfoKey(key)];
        switch (valueType) {
            case Serializable::ValueType::BOOL:
                Set(LinkInfoKey(key), *(bool *)(data));
                break;
            case Serializable::ValueType::INT:
                Set(LinkInfoKey(key), *(int *)(data));
                break;
            case Serializable::ValueType::STRING:
                size = WifiDirectUtils::CalculateStringLength((char *)data, size);
                Set(LinkInfoKey(key), std::string(reinterpret_cast<const char *>(data), size));
                break;
            case Serializable::ValueType::IPV4_INFO: {
                Ipv4Info ipv4Info;
                ipv4Info.Unmarshalling(data, size);
                Set(LinkInfoKey(key), ipv4Info);
            }
                break;
            default:
                continue;
        }
    }

    return SOFTBUS_OK;
}

void LinkInfo::SetLocalInterface(const std::string &interface)
{
    Set(LinkInfoKey::LOCAL_INTERFACE, interface);
}

std::string LinkInfo::GetLocalInterface() const
{
    return Get(LinkInfoKey::LOCAL_INTERFACE, std::string(""));
}

void LinkInfo::SetRemoteInterface(const std::string &interface)
{
    Set(LinkInfoKey::REMOTE_INTERFACE, interface);
}

std::string LinkInfo::GetRemoteInterface() const
{
    return Get(LinkInfoKey::REMOTE_INTERFACE, std::string(""));
}

void LinkInfo::SetLocalLinkMode(LinkMode mode)
{
    Set(LinkInfoKey::LOCAL_LINK_MODE, static_cast<int>(mode));
}

LinkInfo::LinkMode LinkInfo::GetLocalLinkMode() const
{
    auto value = Get(LinkInfoKey::LOCAL_LINK_MODE, static_cast<int>(LinkMode::INVALID));
    return static_cast<LinkInfo::LinkMode>(value);
}

void LinkInfo::SetRemoteLinkMode(LinkMode mode)
{
    Set(LinkInfoKey::REMOTE_LINK_MODE, static_cast<int>(mode));
}

LinkInfo::LinkMode LinkInfo::GetRemoteLinkMode() const
{
    auto value = Get(LinkInfoKey::REMOTE_LINK_MODE, static_cast<int>(LinkMode::INVALID));
    return static_cast<LinkInfo::LinkMode>(value);
}

void LinkInfo::SetCenter20M(int freq)
{
    Set(LinkInfoKey::CENTER_20M, freq);
}

int LinkInfo::GetCenter20M() const
{
    return Get(LinkInfoKey::CENTER_20M, 0);
}

void LinkInfo::SetCenterFrequency1(int freq)
{
    Set(LinkInfoKey::CENTER_FREQUENCY1, freq);
}

int LinkInfo::GetCenterFrequency1() const
{
    return Get(LinkInfoKey::CENTER_FREQUENCY1, 0);
}

void LinkInfo::SetCenterFrequency2(int freq)
{
    Set(LinkInfoKey::CENTER_FREQUENCY2, freq);
}

int LinkInfo::GetCenterFrequency2() const
{
    return Get(LinkInfoKey::CENTER_FREQUENCY2, 0);
}

void LinkInfo::SetBandWidth(int bandWidth)
{
    Set(LinkInfoKey::BANDWIDTH, bandWidth);
}

int LinkInfo::GetBandWidth() const
{
    return Get(LinkInfoKey::BANDWIDTH, 0);
}

void LinkInfo::SetSsid(const std::string &ssid)
{
    Set(LinkInfoKey::SSID, ssid);
}

std::string LinkInfo::GetSsid() const
{
    return Get(LinkInfoKey::SSID, std::string(""));
}

void LinkInfo::SetBssid(const std::string &bssid)
{
    Set(LinkInfoKey::BSSID, bssid);
}

std::string LinkInfo::GetBssid() const
{
    return Get(LinkInfoKey::BSSID, std::string(""));
}

void LinkInfo::SetPsk(const std::string &psk)
{
    Set(LinkInfoKey::PSK, psk);
}

std::string LinkInfo::GetPsk() const
{
    return Get(LinkInfoKey::PSK, std::string(""));
}

void LinkInfo::SetIsDhcp(bool isDhcp)
{
    Set(LinkInfoKey::IS_DHCP, isDhcp);
}

bool LinkInfo::GetIsDhcp() const
{
    return Get(LinkInfoKey::IS_DHCP, false);
}

void LinkInfo::SetLocalIpv4Info(const Ipv4Info &ipv4Info)
{
    Set(LinkInfoKey::LOCAL_IPV4, (const std::any &)ipv4Info);
}

Ipv4Info LinkInfo::GetLocalIpv4Info() const
{
    return Get(LinkInfoKey::LOCAL_IPV4, Ipv4Info());
}

void LinkInfo::SetRemoteIpv4Info(const Ipv4Info &ipv4Info)
{
    Set(LinkInfoKey::REMOTE_IPV4, (const std::any &)ipv4Info);
}

Ipv4Info LinkInfo::GetRemoteIpv4Info() const
{
    return Get(LinkInfoKey::REMOTE_IPV4, Ipv4Info());
}

void LinkInfo::SetAuthPort(int port)
{
    Set(LinkInfoKey::AUTH_PORT, port);
}

int LinkInfo::GetAuthPort() const
{
    return Get(LinkInfoKey::AUTH_PORT, 0);
}

void LinkInfo::SetMaxPhysicalRate(int rate)
{
    Set(LinkInfoKey::MAX_PHYSICAL_RATE, rate);
}

int LinkInfo::GetMaxPhysicalRate() const
{
    return Get(LinkInfoKey::MAX_PHYSICAL_RATE, 0);
}

void LinkInfo::SetRemoteDevice(const std::string &device)
{
    Set(LinkInfoKey::REMOTE_DEVICE, device);
}

std::string LinkInfo::GetRemoteDevice() const
{
    return Get(LinkInfoKey::REMOTE_DEVICE, std::string());
}

void LinkInfo::SetStatus(int status)
{
    Set(LinkInfoKey::STATUS, status);
}

int LinkInfo::GetStatus() const
{
    return Get(LinkInfoKey::STATUS, 0);
}

void LinkInfo::SetLocalBaseMac(const std::string &mac)
{
    Set(LinkInfoKey::LOCAL_BASE_MAC, mac);
}

std::string LinkInfo::GetLocalBaseMac() const
{
    return Get(LinkInfoKey::LOCAL_BASE_MAC, std::string());
}

void LinkInfo::SetRemoteBaseMac(const std::string &mac)
{
    Set(LinkInfoKey::REMOTE_BASE_MAC, mac);
}

std::string LinkInfo::GetRemoteBaseMac() const
{
    return Get(LinkInfoKey::REMOTE_BASE_MAC, std::string());
}

void LinkInfo::SetIsClient(bool client)
{
    Set(LinkInfoKey::IS_CLIENT, client);
}

bool LinkInfo::GetIsClient() const
{
    return Get(LinkInfoKey::IS_CLIENT, false);
}

void LinkInfo::SetLocalIpv6(const std::string &value)
{
    Set(LinkInfoKey::LOCAL_IPV6, value);
}

std::string LinkInfo::GetLocalIpv6() const
{
    return Get(LinkInfoKey::LOCAL_IPV6, std::string());
}

void LinkInfo::SetRemoteIpv6(const std::string &value)
{
    Set(LinkInfoKey::REMOTE_IPV6, value);
}

std::string LinkInfo::GetRemoteIpv6() const
{
    return Get(LinkInfoKey::REMOTE_IPV6, std::string());
}

void LinkInfo::SetCustomPort(int value)
{
    Set(LinkInfoKey::CUSTOM_PORT, value);
}

int LinkInfo::GetCustomPort()
{
    return Get(LinkInfoKey::CUSTOM_PORT, 0);
}

void LinkInfo::SetIpAddrType(enum IpAddrType value)
{
    Set(LinkInfoKey::IPADDR_TYPE, static_cast<int>(value));
}

enum IpAddrType LinkInfo::GetIpAddrType()
{
    auto ret = Get(LinkInfoKey::IPADDR_TYPE, 0);
    return static_cast<enum IpAddrType>(ret);
}

std::string LinkInfo::ToString(LinkMode mode)
{
    switch (mode) {
        case LinkMode::INVALID:
            return "INVALID";
        case LinkMode::NONE:
            return "NONE";
        case LinkMode::STA:
            return "STA";
        case LinkMode::AP:
            return "AP";
        case LinkMode::GO:
            return "GO";
        case LinkMode::GC:
            return "GC";
        case LinkMode::HML:
            return "HML";
        default:
            return "UNKNOWN_MODE(" + std::to_string(static_cast<int>(mode)) + ")";
    }
}
}
