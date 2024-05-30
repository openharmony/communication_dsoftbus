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
#include "wifi_config_info.h"
#include "conn_log.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
template <>
InfoContainer<WifiConfigInfoKey>::KeyTypeTable InfoContainer<WifiConfigInfoKey>::keyTypeTable_ = {
    {WifiConfigInfoKey::INTERFACE_INFO_ARRAY, Serializable::ValueType::INTERFACE_INFO_ARRAY},
    { WifiConfigInfoKey::DEVICE_ID,           Serializable::ValueType::STRING              },
};

WifiConfigInfo::WifiConfigInfo(std::vector<uint8_t> &config)
{
    auto pro = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    if (pro == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "create tlv protocol failed");
        return;
    }
    pro->SetFormat(ProtocolFormat { TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE1 });
    Unmarshalling(*pro, std::vector<uint8_t>(config.begin() + HEADER_LEN, config.end()));
}

int WifiConfigInfo::Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input)
{
    int key = 0;
    uint8_t *data = nullptr;
    size_t size = 0;

    protocol.SetInput(input);
    while (protocol.Read(key, data, size)) {
        auto type = keyTypeTable_[static_cast<WifiConfigInfoKey>(key)];
        switch (Serializable::ValueType(type)) {
            case Serializable::ValueType::INTERFACE_INFO_ARRAY:
                UnmarshallingInterfaceArray(protocol, data, size);
                break;
            default:
                continue;
        }
    }
    return SOFTBUS_OK;
}

void WifiConfigInfo::MarshallingInterfaceArray(WifiDirectProtocol &protocol) const
{
    auto interfaceArray = GetInterfaceInfoArray();
    for (const auto &interface : interfaceArray) {
        auto pro = WifiDirectProtocolFactory::CreateProtocol(protocol.GetType());
        if (pro != nullptr) {
            std::vector<uint8_t> output;
            pro->SetFormat(protocol.GetFormat());
            interface.Marshalling(*pro, output);
            protocol.Write(static_cast<int>(WifiConfigInfoKey::INTERFACE_INFO_ARRAY),
                           Serializable::ValueType::INTERFACE_INFO_ARRAY, output.data(), output.size());
        }
    }
}

int WifiConfigInfo::Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const
{
    for (const auto &[key, value] : values_) {
        auto type = keyTypeTable_[key];
        switch (type) {
            case Serializable::ValueType::INTERFACE_INFO_ARRAY:
                MarshallingInterfaceArray(protocol);
                break;
            default:
                continue;
        }
    }
    protocol.GetOutput(output);
    return SOFTBUS_OK;
}

void WifiConfigInfo::UnmarshallingInterfaceArray(WifiDirectProtocol &protocol, uint8_t *data, size_t size)
{
    CONN_CHECK_AND_RETURN_LOGW(data != nullptr, CONN_WIFI_DIRECT, "data is nullptr");
    auto pro = WifiDirectProtocolFactory::CreateProtocol(protocol.GetType());
    CONN_CHECK_AND_RETURN_LOGE(pro != nullptr, CONN_WIFI_DIRECT, "create protocol failed");
    pro->SetFormat(ProtocolFormat { TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE1 });

    InterfaceInfo info;
    std::vector<uint8_t> input(data, data + size);
    info.Unmarshalling(*pro, input);
    auto interfaceArray = GetInterfaceInfoArray();
    interfaceArray.push_back(info);
    SetInterfaceInfoArray(interfaceArray);
}

void WifiConfigInfo::SetInterfaceInfoArray(const std::vector<InterfaceInfo> &value)
{
    Set(WifiConfigInfoKey::INTERFACE_INFO_ARRAY, value);
}

std::vector<InterfaceInfo> WifiConfigInfo::GetInterfaceInfoArray() const
{
    return Get(WifiConfigInfoKey::INTERFACE_INFO_ARRAY, std::vector<InterfaceInfo>());
}

InterfaceInfo WifiConfigInfo::GetInterfaceInfo(const std::string &name) const
{
    auto interfaces = GetInterfaceInfoArray();
    for (const auto &interface : interfaces) {
        if (name == interface.GetName()) {
            return interface;
        }
    }
    return {};
}

void WifiConfigInfo::SetDeviceId(const std::string &value)
{
    Set(WifiConfigInfoKey::DEVICE_ID, value);
}

std::string WifiConfigInfo::GetDeviceId() const
{
    return Get(WifiConfigInfoKey::DEVICE_ID, std::string(""));
}
} // namespace OHOS::SoftBus
