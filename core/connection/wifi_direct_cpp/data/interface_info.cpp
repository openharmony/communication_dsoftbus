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

#include <any>
#include <string>
#include "conn_log.h"
#include "interface_info.h"
#include "protocol/wifi_direct_protocol.h"
#include "softbus_error_code.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {

template <>
InfoContainer<InterfaceInfoKey>::KeyTypeTable InfoContainer<InterfaceInfoKey>::keyTypeTable_ = {
    { InterfaceInfoKey::DYNAMIC_MAC,            Serializable::ValueType::STRING    },
    { InterfaceInfoKey::INTERFACE_NAME,         Serializable::ValueType::STRING    },
    { InterfaceInfoKey::CAPABILITY,             Serializable::ValueType::INT       },
    { InterfaceInfoKey::WIFI_DIRECT_ROLE,       Serializable::ValueType::INT       },
    { InterfaceInfoKey::BASE_MAC,               Serializable::ValueType::STRING    },
    { InterfaceInfoKey::PHYSICAL_RATE,          Serializable::ValueType::INT       },
    { InterfaceInfoKey::SUPPORT_BAND,           Serializable::ValueType::BYTE      },
    { InterfaceInfoKey::CHANNEL_AND_BANDWIDTH,  Serializable::ValueType::BYTE_ARRAY},
    { InterfaceInfoKey::COEXIST_CHANNEL_LIST,   Serializable::ValueType::INT_ARRAY },
    { InterfaceInfoKey::HML_LINK_COUNT,         Serializable::ValueType::INT       },
    { InterfaceInfoKey::ISLAND_DEVICE_COUNT,    Serializable::ValueType::INT       },
    { InterfaceInfoKey::COEXIST_VAP_COUNT,      Serializable::ValueType::BOOL      },
    { InterfaceInfoKey::IPV4,                   Serializable::ValueType::IPV4_INFO },
    { InterfaceInfoKey::CHANNEL_5G_LIST,        Serializable::ValueType::INT_ARRAY },
    { InterfaceInfoKey::SSID,                   Serializable::ValueType::STRING    },
    { InterfaceInfoKey::PORT,                   Serializable::ValueType::INT       },
    { InterfaceInfoKey::IS_WIDE_BAND_SUPPORT,   Serializable::ValueType::BOOL      },
    { InterfaceInfoKey::CENTER_20M,             Serializable::ValueType::INT       },
    { InterfaceInfoKey::CENTER_FREQUENCY1,      Serializable::ValueType::INT       },
    { InterfaceInfoKey::CENTER_FREQUENCY2,      Serializable::ValueType::INT       },
    { InterfaceInfoKey::BANDWIDTH,              Serializable::ValueType::INT       },
    { InterfaceInfoKey::WIFI_CFG_INFO,          Serializable::ValueType::STRING    },
    { InterfaceInfoKey::IS_ENABLE,              Serializable::ValueType::BOOL      },
    { InterfaceInfoKey::CONNECTED_DEVICE_COUNT, Serializable::ValueType::INT       },
    { InterfaceInfoKey::PSK,                    Serializable::ValueType::STRING    },
    { InterfaceInfoKey::REUSE_COUNT,            Serializable::ValueType::INT       },
    { InterfaceInfoKey::IS_AVAILABLE,           Serializable::ValueType::BOOL      },
    { InterfaceInfoKey::COEXIST_RULE,           Serializable::ValueType::BOOL      },
    { InterfaceInfoKey::LINK_MODE,              Serializable::ValueType::INT       },
    { InterfaceInfoKey::LISTEN_MODULE,          Serializable::ValueType::INT       },
};

void InterfaceInfo::MarshallingString(
    WifiDirectProtocol &protocol, InterfaceInfoKey key, Serializable::ValueType type, const std::string &value)
{
    if (key == InterfaceInfoKey::DYNAMIC_MAC || key == InterfaceInfoKey::BASE_MAC) {
        auto macString = std::any_cast<const std::string>(value);
        auto macArray = WifiDirectUtils::MacStringToArray(macString);
        if (!macArray.empty()) {
            protocol.Write(static_cast<int>(key), type, macArray.data(), macArray.size());
        }
    } else {
        protocol.Write(static_cast<int>(key), type, reinterpret_cast<const uint8_t*>(value.c_str()), value.length());
    }
}

int InterfaceInfo::Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const
{
    ProtocolType protocolType = protocol.GetType();
    for (const auto &[key, value] : values_) {
        auto type = keyTypeTable_[key];
        if (protocolType == ProtocolType::TLV &&
            (key == InterfaceInfoKey::DYNAMIC_MAC || key == InterfaceInfoKey::BASE_MAC)) {
            auto macString = std::any_cast<const std::string>(value);
            auto macArray = WifiDirectUtils::MacStringToArray(macString);
            if (!macArray.empty()) {
                protocol.Write(static_cast<int>(key), type, macArray.data(), macArray.size());
            }
            continue;
        }

        switch (type) {
            case Serializable::ValueType::BOOL: {
                uint8_t data = std::any_cast<bool>(value);
                protocol.Write(static_cast<int>(key), type, &data, sizeof(data));
                break;
            }
            case Serializable::ValueType::INT: {
                std::vector<uint8_t> data;
                WifiDirectUtils::IntToBytes(std::any_cast<int>(value), sizeof(int), data);
                protocol.Write(static_cast<int>(key), type, data.data(), data.size());
                break;
            }
            case Serializable::ValueType::BYTE_ARRAY: {
                const auto &data = std::any_cast<const std::vector<uint8_t> &>(value);
                protocol.Write(static_cast<int>(key), type, data.data(), data.size());
                break;
            }
            case Serializable::ValueType::STRING: {
                MarshallingString(protocol, key, type, std::any_cast<const std::string>(value));
                break;
            }
            case Serializable::ValueType::IPV4_INFO: {
                const auto &ipv4Info = std::any_cast<const Ipv4Info &>(value);
                std::vector<uint8_t> ipv4InfoOutput;
                ipv4Info.Marshalling(ipv4InfoOutput);
                protocol.Write(static_cast<int>(key), type, ipv4InfoOutput.data(), ipv4InfoOutput.size());
                break;
            }
            default:
                continue;
        }
    }
    protocol.GetOutput(output);
    return SOFTBUS_OK;
}

int InterfaceInfo::Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input)
{
    int key = 0;
    uint8_t *data = nullptr;
    size_t size = 0;
    enum ProtocolType protocolType = protocol.GetType();

    protocol.SetInput(input);
    while (protocol.Read(key, data, size)) {
        auto type = keyTypeTable_[InterfaceInfoKey(key)];
        auto keyValue = static_cast<InterfaceInfoKey>(key);
        if (protocolType == ProtocolType::TLV &&
            (keyValue == InterfaceInfoKey::DYNAMIC_MAC || keyValue == InterfaceInfoKey::BASE_MAC)) {
            std::vector<uint8_t> macArray(data, data + size);
            auto macAddressStr = WifiDirectUtils::MacArrayToString(macArray);
            Set(InterfaceInfoKey(key), macAddressStr);
            continue;
        }

        switch (type) {
            case Serializable::ValueType::BOOL: {
                Set(InterfaceInfoKey(key), *(bool *)(data));
                break;
            }
            case Serializable::ValueType::INT: {
                int intKey = (int)WifiDirectUtils::BytesToInt((uint8_t *)data, size);
                Set(InterfaceInfoKey(key), intKey);
                break;
            }
            case Serializable::ValueType::STRING: {
                size = WifiDirectUtils::CalculateStringLength((char *)data, size);
                Set(InterfaceInfoKey(key), std::string(reinterpret_cast<const char *>(data), size));
                break;
            }
            case Serializable::ValueType::BYTE_ARRAY: {
                Set(InterfaceInfoKey(key), std::vector<uint8_t>(data, data + size));
                break;
            }
            case Serializable::ValueType::IPV4_INFO: {
                Ipv4Info ipv4Info;
                ipv4Info.Unmarshalling(data, size);
                Set(InterfaceInfoKey(key), ipv4Info);
                break;
            }
            default:
                continue;
        }
    }

    return SOFTBUS_OK;
}

void InterfaceInfo::SetName(const std::string &value)
{
    Set(InterfaceInfoKey::INTERFACE_NAME, value);
}

std::string InterfaceInfo::GetName() const
{
    return Get(InterfaceInfoKey::INTERFACE_NAME, std::string(""));
}

std::vector<uint8_t> InterfaceInfo::GetChannelAndBandWidth() const
{
    return Get(InterfaceInfoKey::CHANNEL_AND_BANDWIDTH, std::vector<uint8_t>());
}

void InterfaceInfo::SetIpString(const Ipv4Info &ipv4Info)
{
    Set(InterfaceInfoKey::IPV4, ipv4Info);
}

Ipv4Info InterfaceInfo::GetIpString() const
{
    return Get(InterfaceInfoKey::IPV4, Ipv4Info());
}

void InterfaceInfo::SetRole(LinkInfo::LinkMode value)
{
    Set(InterfaceInfoKey::WIFI_DIRECT_ROLE, static_cast<int>(value));
}

LinkInfo::LinkMode InterfaceInfo::GetRole() const
{
    auto ret = Get(InterfaceInfoKey::WIFI_DIRECT_ROLE, 0);
    return static_cast<LinkInfo::LinkMode>(ret);
}

void InterfaceInfo::SetSsid(const std::string &value)
{
    Set(InterfaceInfoKey::SSID, value);
}

std::string InterfaceInfo::GetSsid() const
{
    return Get(InterfaceInfoKey::SSID, std::string(""));
}

void InterfaceInfo::SetP2pListenPort(const int &value)
{
    Set(InterfaceInfoKey::PORT, value);
}

int InterfaceInfo::GetP2pListenPort() const
{
    return Get(InterfaceInfoKey::PORT, 0);
}

void InterfaceInfo::SetP2pListenModule(const int &value)
{
    Set(InterfaceInfoKey::LISTEN_MODULE, value);
}

int InterfaceInfo::GetP2pListenModule() const
{
    return Get(InterfaceInfoKey::LISTEN_MODULE, -1);
}

void InterfaceInfo::SetP2pGroupConfig(const std::string &groupConfig)
{
    Set(InterfaceInfoKey::WIFI_CFG_INFO, groupConfig);
    auto ret = WifiDirectUtils::SplitString(groupConfig, "\n");
    Set(InterfaceInfoKey::SSID, ret[P2P_GROUP_CONFIG_INDEX_SSID]);
    if (!GetDynamicMac().empty()) {
        Set(InterfaceInfoKey::DYNAMIC_MAC, ret[P2P_GROUP_CONFIG_INDEX_BSSID]);
    }
    Set(InterfaceInfoKey::PSK, ret[P2P_GROUP_CONFIG_INDEX_SHARE_KEY]);
    Set(InterfaceInfoKey::CENTER_20M, std::stoi(ret[P2P_GROUP_CONFIG_INDEX_FREQ]));
}

std::string InterfaceInfo::GetP2pGroupConfig() const
{
    return Get(InterfaceInfoKey::WIFI_CFG_INFO, std::string(""));
}

void InterfaceInfo::SetDynamicMac(const std::string &value)
{
    Set(InterfaceInfoKey::DYNAMIC_MAC, value);
}

std::string InterfaceInfo::GetDynamicMac() const
{
    return Get(InterfaceInfoKey::DYNAMIC_MAC, std::string(""));
}

void InterfaceInfo::SetPsk(const std::string &value)
{
    Set(InterfaceInfoKey::PSK, value);
}

std::string InterfaceInfo::GetPsk() const
{
    return Get(InterfaceInfoKey::PSK, std::string(""));
}

void InterfaceInfo::SetCenter20M(int value)
{
    Set(InterfaceInfoKey::CENTER_20M, value);
}

int InterfaceInfo::GetCenter20M() const
{
    return Get(InterfaceInfoKey::CENTER_20M, 0);
}

void InterfaceInfo::SetBandWidth(int value)
{
    Set(InterfaceInfoKey::BANDWIDTH, value);
}

int InterfaceInfo::GetBandWidth() const
{
    return Get(InterfaceInfoKey::BANDWIDTH, 0);
}

void InterfaceInfo::SetIsEnable(bool value)
{
    Set(InterfaceInfoKey::IS_ENABLE, value);
}

bool InterfaceInfo::IsEnable() const
{
    return Get(InterfaceInfoKey::IS_ENABLE, false);
}

void InterfaceInfo::SetConnectedDeviceCount(int32_t value)
{
    Set(InterfaceInfoKey::CONNECTED_DEVICE_COUNT, value);
}

int32_t InterfaceInfo::GetConnectedDeviceCount() const
{
    return Get(InterfaceInfoKey::CONNECTED_DEVICE_COUNT, 0);
}

void InterfaceInfo::SetBaseMac(const std::string &value)
{
    Set(InterfaceInfoKey::BASE_MAC, value);
}

std::string InterfaceInfo::GetBaseMac() const
{
    return Get(InterfaceInfoKey::BASE_MAC, std::string(""));
}

void InterfaceInfo::SetCapability(int32_t value)
{
    Set(InterfaceInfoKey::CAPABILITY, value);
}

int32_t InterfaceInfo::GetCapability() const
{
    return Get(InterfaceInfoKey::CAPABILITY, 0);
}

void InterfaceInfo::SetReuseCount(int value)
{
    Set(InterfaceInfoKey::REUSE_COUNT, value);
}

int InterfaceInfo::GetReuseCount() const
{
    return Get(InterfaceInfoKey::REUSE_COUNT, 0);
}

void InterfaceInfo::SetChannel5GList(const std::vector<int> &value)
{
    Set(InterfaceInfoKey::CHANNEL_5G_LIST, value);
}

std::vector<int> InterfaceInfo::GetChannel5GList() const
{
    std::vector<int> result;
    return Get(InterfaceInfoKey::CHANNEL_5G_LIST, result);
}

void InterfaceInfo::SetIsAvailable(bool value)
{
    Set(InterfaceInfoKey::IS_AVAILABLE, value);
}

bool InterfaceInfo::IsAvailable() const
{
    return Get(InterfaceInfoKey::IS_AVAILABLE, true);
}

void InterfaceInfo::RefreshIsAvailable()
{
    if (!IsEnable()) {
        CONN_LOGW(CONN_WIFI_DIRECT, "isEnable=0, interface name=%{public}s", GetName().c_str());
        SetIsAvailable(false);
        return;
    }

    if (GetRole() == LinkInfo::LinkMode::GC) {
        CONN_LOGW(CONN_WIFI_DIRECT, "already gc");
        SetIsAvailable(false);
        return;
    }
    SetIsAvailable(true);
}

void InterfaceInfo::SetPhysicalRate(int value)
{
    Set(InterfaceInfoKey::PHYSICAL_RATE, value);
}

int InterfaceInfo::GetPhysicalRate() const
{
    return Get(InterfaceInfoKey::PHYSICAL_RATE, 0);
}

void InterfaceInfo::IncreaseRefCount()
{
    int count = Get(InterfaceInfoKey::REUSE_COUNT, 0);
    count++;
    Set(InterfaceInfoKey::REUSE_COUNT, count);
    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount = %{public}d", count);
}

void InterfaceInfo::DecreaseRefCount()
{
    int count = Get(InterfaceInfoKey::REUSE_COUNT, 0);
    --count;
    Set(InterfaceInfoKey::REUSE_COUNT, count);
    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount = %{public}d", count);
}
} // namespace OHOS::SoftBus
