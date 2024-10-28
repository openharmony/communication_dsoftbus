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
#include "negotiate_message.h"

#include "conn_log.h"
#include "softbus_error_code.h"

#include "protocol/wifi_direct_protocol_factory.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
std::set<NegotiateMessageKey> NegotiateMessage::keyIgnoreTable_ = {
    NegotiateMessageKey::REMOTE_DEVICE_ID,
};

std::map<NegotiateMessageKey, std::string> NegotiateMessage::keyStringTable_ = {
    /* old p2p */
    { NegotiateMessageKey::GC_CHANNEL_LIST,     "KEY_GC_CHANNEL_LIST"     },
    { NegotiateMessageKey::STATION_FREQUENCY,   "KEY_STATION_FREQUENCY"   },
    { NegotiateMessageKey::ROLE,                "KEY_ROLE"                },
    { NegotiateMessageKey::EXPECTED_ROLE,       "KEY_EXPECTED_ROLE"       },
    { NegotiateMessageKey::VERSION,             "KEY_VERSION"             },
    { NegotiateMessageKey::GC_IP,               "KEY_GC_IP"               },
    { NegotiateMessageKey::WIDE_BAND_SUPPORTED, "KEY_WIDE_BAND_SUPPORTED" },
    { NegotiateMessageKey::GROUP_CONFIG,        "KEY_GROUP_CONFIG"        },
    { NegotiateMessageKey::MAC,                 "KEY_MAC"                 },
    { NegotiateMessageKey::BRIDGE_SUPPORTED,    "KEY_BRIDGE_SUPPORTED"    },
    { NegotiateMessageKey::GO_IP,               "KEY_GO_IP"               },
    { NegotiateMessageKey::GO_MAC,              "KEY_GO_MAC"              },
    { NegotiateMessageKey::GO_PORT,             "KEY_GO_PORT"             },
    { NegotiateMessageKey::IP,                  "KEY_IP"                  },
    { NegotiateMessageKey::RESULT,              "KEY_RESULT"              },
    { NegotiateMessageKey::CONTENT_TYPE,        "KEY_CONTENT_TYPE"        },
    { NegotiateMessageKey::GC_MAC,              "KEY_GC_MAC"              },
    { NegotiateMessageKey::SELF_WIFI_CONFIG,    "KEY_SELF_WIFI_CONFIG"    },
    { NegotiateMessageKey::GC_CHANNEL_SCORE,    "KEY_GC_CHANNEL_SCORE"    },
    { NegotiateMessageKey::COMMAND_TYPE,        "KEY_COMMAND_TYPE"        },
    { NegotiateMessageKey::INTERFACE_NAME,      "KEY_INTERFACE_NAME"      },
};

template <>
InfoContainer<NegotiateMessageKey>::KeyTypeTable InfoContainer<NegotiateMessageKey>::keyTypeTable_ = {
    { NegotiateMessageKey::MSG_TYPE,              Serializable::ValueType::INT                  },
    { NegotiateMessageKey::SESSION_ID,            Serializable::ValueType::UINT                 },
    { NegotiateMessageKey::WIFI_CFG_TYPE,         Serializable::ValueType::INT                  },
    { NegotiateMessageKey::WIFI_CFG_INFO,         Serializable::ValueType::BYTE_ARRAY           },
    { NegotiateMessageKey::IPV4_INFO_ARRAY,       Serializable::ValueType::IPV4_INFO_ARRAY      },
    { NegotiateMessageKey::PREFER_LINK_MODE,      Serializable::ValueType::INT                  },
    { NegotiateMessageKey::IS_MODE_STRICT,        Serializable::ValueType::BOOL                 },
    { NegotiateMessageKey::PREFER_LINK_BANDWIDTH, Serializable::ValueType::INT                  },
    { NegotiateMessageKey::IS_BRIDGE_SUPPORTED,   Serializable::ValueType::BOOL                 },
    { NegotiateMessageKey::LINK_INFO,             Serializable::ValueType::LINK_INFO            },
    { NegotiateMessageKey::RESULT_CODE,           Serializable::ValueType::INT                  },
    { NegotiateMessageKey::INTERFACE_INFO_ARRAY,  Serializable::ValueType::INTERFACE_INFO_ARRAY },
    { NegotiateMessageKey::REMOTE_DEVICE_ID,      Serializable::ValueType::STRING               },
    { NegotiateMessageKey::EXTRA_DATA_ARRAY,      Serializable::ValueType::BYTE_ARRAY           },
    { NegotiateMessageKey::INNER_LINK,            Serializable::ValueType::INNER_LINK           },
    { NegotiateMessageKey::IS_PROXY_ENABLE,       Serializable::ValueType::BOOL                 },
    { NegotiateMessageKey::CHANNEL_5G_LIST,       Serializable::ValueType::STRING               },
    { NegotiateMessageKey::CHANNEL_5G_SCORE,      Serializable::ValueType::STRING               },
    { NegotiateMessageKey::CHALLENGE_CODE,        Serializable::ValueType::UINT                 },
    { NegotiateMessageKey::REMOTE_NETWORK_ID,     Serializable::ValueType::STRING               },

    /* old p2p */
    { NegotiateMessageKey::GC_CHANNEL_LIST,       Serializable::ValueType::STRING               },
    { NegotiateMessageKey::STATION_FREQUENCY,     Serializable::ValueType::INT                  },
    { NegotiateMessageKey::ROLE,                  Serializable::ValueType::INT                  },
    { NegotiateMessageKey::EXPECTED_ROLE,         Serializable::ValueType::INT                  },
    { NegotiateMessageKey::VERSION,               Serializable::ValueType::INT                  },
    { NegotiateMessageKey::GC_IP,                 Serializable::ValueType::STRING               },
    { NegotiateMessageKey::WIDE_BAND_SUPPORTED,   Serializable::ValueType::BOOL                 },
    { NegotiateMessageKey::GROUP_CONFIG,          Serializable::ValueType::STRING               },
    { NegotiateMessageKey::MAC,                   Serializable::ValueType::STRING               },
    { NegotiateMessageKey::BRIDGE_SUPPORTED,      Serializable::ValueType::BOOL                 },
    { NegotiateMessageKey::GO_IP,                 Serializable::ValueType::STRING               },
    { NegotiateMessageKey::GO_MAC,                Serializable::ValueType::STRING               },
    { NegotiateMessageKey::GO_PORT,               Serializable::ValueType::INT                  },
    { NegotiateMessageKey::IP,                    Serializable::ValueType::STRING               },
    { NegotiateMessageKey::RESULT,                Serializable::ValueType::INT                  },
    { NegotiateMessageKey::CONTENT_TYPE,          Serializable::ValueType::INT                  },
    { NegotiateMessageKey::GC_MAC,                Serializable::ValueType::STRING               },
    { NegotiateMessageKey::SELF_WIFI_CONFIG,      Serializable::ValueType::STRING               },
    { NegotiateMessageKey::GC_CHANNEL_SCORE,      Serializable::ValueType::STRING               },
    { NegotiateMessageKey::COMMAND_TYPE,          Serializable::ValueType::INT                  },
    { NegotiateMessageKey::INTERFACE_NAME,        Serializable::ValueType::STRING               },
};

static std::map<NegotiateMessageType, std::string> g_messageNameMap = {
    { NegotiateMessageType::CMD_INVALID,                 "CMD_INVALID"                 },
    { NegotiateMessageType::CMD_CONN_V2_REQ_1,           "CMD_CONN_V2_REQ_1"           },
    { NegotiateMessageType::CMD_CONN_V2_REQ_2,           "CMD_CONN_V2_REQ_2"           },
    { NegotiateMessageType::CMD_CONN_V2_REQ_3,           "CMD_CONN_V2_REQ_3"           },
    { NegotiateMessageType::CMD_CONN_V2_RESP_1,          "CMD_CONN_V2_RESP_1"          },
    { NegotiateMessageType::CMD_CONN_V2_RESP_2,          "CMD_CONN_V2_RESP_2"          },
    { NegotiateMessageType::CMD_CONN_V2_RESP_3,          "CMD_CONN_V2_RESP_3"          },
    { NegotiateMessageType::CMD_DISCONNECT_V2_REQ,       "CMD_DISCONNECT_V2_REQ"       },
    { NegotiateMessageType::CMD_DISCONNECT_V2_RESP,      "CMD_DISCONNECT_V2_RESP"      },
    { NegotiateMessageType::CMD_FORCE_DISCONNECT_REQ,    "CMD_FORCE_DISCONNECT_REQ"    },
    { NegotiateMessageType::CMD_CLIENT_JOIN_FAIL_NOTIFY, "CMD_CLIENT_JOIN_FAIL_NOTIFY" },
    { NegotiateMessageType::CMD_TRIGGER_REQ,             "CMD_TRIGGER_REQ"             },
    { NegotiateMessageType::CMD_TRIGGER_RESP,            "CMD_TRIGGER_RESP"            },
    { NegotiateMessageType::CMD_AUTH_LISTEN_RESP,        "CMD_AUTH_LISTEN_RESP"        },
    { NegotiateMessageType::CMD_RENEGOTIATE_REQ,         "CMD_RENEGOTIATE_REQ"         },
    { NegotiateMessageType::CMD_RENEGOTIATE_RESP,        "CMD_RENEGOTIATE_RESP"        },
    { NegotiateMessageType::CMD_AUTH_HAND_SHAKE,         "CMD_AUTH_HAND_SHAKE"         },
    { NegotiateMessageType::CMD_AUTH_HAND_SHAKE_RSP,     "CMD_AUTH_HAND_SHAKE_RSP"     },
    { NegotiateMessageType::CMD_DETECT_LINK_REQ,         "CMD_DETECT_LINK_REQ"         },
    { NegotiateMessageType::CMD_DETECT_LINK_RSP,         "CMD_DETECT_LINK_RSP"         },
    { NegotiateMessageType::CMD_V3_REQ,                  "CMD_V3_REQ"                  },
    { NegotiateMessageType::CMD_V3_RSP,                  "CMD_V3_RSP"                  },
    { NegotiateMessageType::CMD_V3_CUSTOM_PORT_REQ,      "CMD_V3_CUSTOM_PORT_REQ"      },
    { NegotiateMessageType::CMD_V3_CUSTOM_PORT_RSP,      "CMD_V3_CUSTOM_PORT_RSP"      },
    { NegotiateMessageType::CMD_ERROR_NOTIFICATION,      "CMD_ERROR_NOTIFICATION"      },
};

static std::map<LegacyCommandType, std::string> g_legacyMessageNameMap = {
    { LegacyCommandType::CMD_INVALID,                    "CMD_INVALID"                    },
    { LegacyCommandType::CMD_DISCONNECT_V1_REQ,          "CMD_DISCONNECT_V1_REQ"          },
    { LegacyCommandType::CMD_CONN_V1_REQ,                "CMD_CONN_V1_REQ"                },
    { LegacyCommandType::CMD_CONN_V1_RESP,               "CMD_CONN_V1_RESP"               },
    { LegacyCommandType::CMD_REUSE_REQ,                  "CMD_REUSE_REQ"                  },
    { LegacyCommandType::CMD_CTRL_CHL_HANDSHAKE,         "CMD_CTRL_CHL_HANDSHAKE"         },
    { LegacyCommandType::CMD_GC_WIFI_CONFIG_CHANGED,     "CMD_GC_WIFI_CONFIG_CHANGED"     },
    { LegacyCommandType::CMD_REUSE_RESP,                 "CMD_REUSE_RESP"                 },
    { LegacyCommandType::CMD_PC_GET_INTERFACE_INFO_REQ,  "CMD_PC_GET_INTERFACE_INFO_REQ"  },
    { LegacyCommandType::CMD_PC_GET_INTERFACE_INFO_RESP, "CMD_PC_GET_INTERFACE_INFO_RESP" },
    { LegacyCommandType::CMD_FORCE_DISCONNECT_V1_REQ,    "CMD_FORCE_DISCONNECT_V1_REQ"    },
};

NegotiateMessage::NegotiateMessage() { }

NegotiateMessage::NegotiateMessage(NegotiateMessageType type)
{
    SetMessageType(type);
}

NegotiateMessage::NegotiateMessage(LegacyCommandType type)
{
    SetMessageType(type);
}

NegotiateMessage::~NegotiateMessage() { }

int NegotiateMessage::Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const
{
    for (const auto &[key, value] : values_) {
        if (keyIgnoreTable_.find(key) != keyIgnoreTable_.end()) {
            continue;
        }
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
            case Serializable::ValueType::UINT: {
                std::vector<uint8_t> data;
                WifiDirectUtils::IntToBytes(std::any_cast<uint32_t>(value), sizeof(uint32_t), data);
                protocol.Write(static_cast<int>(key), type, data.data(), data.size());
            }
                break;
            case Serializable::ValueType::STRING: {
                auto data = std::any_cast<std::string>(value);
                protocol.Write(static_cast<int>(key), type, (uint8_t *)data.c_str(), data.length());
            }
                break;
            case Serializable::ValueType::BYTE_ARRAY: {
                const auto &data = std::any_cast<const std::vector<uint8_t> &>(value);
                protocol.Write(static_cast<int>(key), type, data.data(), data.size());
            }
                break;
            case Serializable::ValueType::IPV4_INFO_ARRAY:
                MarshallingIpv4Array(protocol);
                break;
            case Serializable::ValueType::INTERFACE_INFO_ARRAY:
                MarshallingInterfaceArray(protocol);
                break;
            case Serializable::ValueType::LINK_INFO:
                MarshallingLinkInfo(protocol);
                break;
            default:
                continue;
        }
    }
    protocol.GetOutput(output);
    return SOFTBUS_OK;
}

void NegotiateMessage::MarshallingIpv4Array(WifiDirectProtocol &protocol) const
{
    std::vector<uint8_t> output;
    auto ipv4Array = GetIpv4InfoArray();
    for (const auto &ipv4 : ipv4Array) {
        std::vector<uint8_t> ipv4Output;
        ipv4.Marshalling(ipv4Output);
        output.insert(output.end(), ipv4Output.begin(), ipv4Output.end());
    }
    protocol.Write((int)NegotiateMessageKey::IPV4_INFO_ARRAY, Serializable::ValueType::IPV4_INFO_ARRAY, output.data(),
        output.size());
}

void NegotiateMessage::MarshallingInterfaceArray(WifiDirectProtocol &protocol) const
{
    auto interfaceArray = GetInterfaceInfoArray();
    for (const auto &interface : interfaceArray) {
        auto pro = WifiDirectProtocolFactory::CreateProtocol(protocol.GetType());
        if (pro != nullptr) {
            std::vector<uint8_t> interfaceOutput;
            pro->SetFormat(protocol.GetFormat());
            interface.Marshalling(*pro, interfaceOutput);
            protocol.Write(static_cast<int>(NegotiateMessageKey::INTERFACE_INFO_ARRAY),
                Serializable::ValueType::INTERFACE_INFO_ARRAY, interfaceOutput.data(), interfaceOutput.size());
        }
    }
}

void NegotiateMessage::MarshallingLinkInfo(WifiDirectProtocol &protocol) const
{
    auto pro = WifiDirectProtocolFactory::CreateProtocol(protocol.GetType());
    if (pro == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "create protocol failed");
        return;
    }
    pro->SetFormat(protocol.GetFormat());

    auto linkInfo = GetLinkInfo();
    std::vector<uint8_t> output;
    linkInfo.Marshalling(*pro, output);
    protocol.Write(static_cast<int>(NegotiateMessageKey::LINK_INFO), Serializable::ValueType::LINK_INFO, output.data(),
        output.size());
}

int NegotiateMessage::Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input)
{
    int key = 0;
    uint8_t *data = nullptr;
    size_t size = 0;

    protocol.SetInput(input);
    while (protocol.Read(key, data, size)) {
        auto type = keyTypeTable_[static_cast<NegotiateMessageKey>(key)];
        switch (Serializable::ValueType(type)) {
            case Serializable::ValueType::BOOL:
                Set(NegotiateMessageKey(key), *(bool *)(data));
                break;
            case Serializable::ValueType::INT:
                Set(NegotiateMessageKey(key), *(int *)(data));
                break;
            case Serializable::ValueType::UINT:
                Set(NegotiateMessageKey(key), *(uint32_t *)(data));
                break;
            case Serializable::ValueType::STRING:
                size = WifiDirectUtils::CalculateStringLength((char *)data, size);
                Set(NegotiateMessageKey(key), std::string(reinterpret_cast<const char *>(data), size));
                break;
            case Serializable::ValueType::BYTE_ARRAY:
                Set(NegotiateMessageKey(key), std::vector<uint8_t>(data, data + size));
                break;
            case Serializable::ValueType::IPV4_INFO_ARRAY:
                UnmarshallingIpv4Array(data, size);
                break;
            case Serializable::ValueType::INTERFACE_INFO_ARRAY:
                UnmarshallingInterfaceArray(protocol, data, size);
                break;
            case Serializable::ValueType::LINK_INFO:
                UnmarshallingLinkInfo(protocol, data, size);
                break;
            default:
                continue;
        }
    }

    return SOFTBUS_OK;
}

void NegotiateMessage::UnmarshallingIpv4Array(uint8_t *data, size_t size)
{
    std::vector<Ipv4Info> ipv4Array;
    for (size_t pos = 0; pos + Ipv4Info::Ipv4InfoSize() <= size; pos += Ipv4Info::Ipv4InfoSize()) {
        Ipv4Info ipv4;
        ipv4.Unmarshalling(data + pos, Ipv4Info::Ipv4InfoSize());
        ipv4Array.push_back(ipv4);
    }
    if (!ipv4Array.empty()) {
        SetIpv4InfoArray(ipv4Array);
    }
}

void NegotiateMessage::UnmarshallingInterfaceArray(WifiDirectProtocol &protocol, uint8_t *data, size_t size)
{
    auto pro = WifiDirectProtocolFactory::CreateProtocol(protocol.GetType());
    if (pro == nullptr) {
        return;
    }
    pro->SetFormat(protocol.GetFormat());

    InterfaceInfo info;
    std::vector<uint8_t> input(data, data + size);
    info.Unmarshalling(*pro, input);
    auto interfaceArray = GetInterfaceInfoArray();
    interfaceArray.push_back(info);
    SetInterfaceInfoArray(interfaceArray);
}

void NegotiateMessage::UnmarshallingLinkInfo(WifiDirectProtocol &protocol, uint8_t *data, size_t size)
{
    auto pro = WifiDirectProtocolFactory::CreateProtocol(protocol.GetType());
    if (pro == nullptr) {
        return;
    }
    pro->SetFormat(protocol.GetFormat());

    LinkInfo info;
    std::vector<uint8_t> input(data, data + size);
    info.Unmarshalling(*pro, input);
    SetLinkInfo(info);
}

void NegotiateMessage::SetMessageType(NegotiateMessageType value)
{
    Set(NegotiateMessageKey::MSG_TYPE, static_cast<int>(value));
}

void NegotiateMessage::SetMessageType(LegacyCommandType value)
{
    Set(NegotiateMessageKey::MSG_TYPE, static_cast<int>(value));
}

NegotiateMessageType NegotiateMessage::GetMessageType() const
{
    auto value = Get(NegotiateMessageKey::MSG_TYPE, static_cast<int>(NegotiateMessageType::CMD_INVALID));
    return static_cast<NegotiateMessageType>(value);
}

std::string NegotiateMessage::MessageTypeToString() const
{
    auto legacyCmdType = GetLegacyP2pCommandType();
    if (legacyCmdType != LegacyCommandType::CMD_INVALID) {
        auto it = g_legacyMessageNameMap.find(legacyCmdType);
        if (it == g_legacyMessageNameMap.end()) {
            CONN_LOGE(CONN_WIFI_DIRECT, "not find legacy %{public}d", static_cast<int>(GetMessageType()));
            return "";
        }
        return it->second;
    }

    auto it = g_messageNameMap.find(GetMessageType());
    if (it == g_messageNameMap.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find %{public}d", static_cast<int>(GetMessageType()));
        return "";
    }
    return it->second;
}

void NegotiateMessage::SetSessionId(uint32_t value)
{
    Set(NegotiateMessageKey::SESSION_ID, value);
}

uint32_t NegotiateMessage::GetSessionId() const
{
    return Get(NegotiateMessageKey::SESSION_ID, static_cast<uint32_t>(SESSION_ID_INVALID));
}

void NegotiateMessage::SetWifiConfigInfo(const std::vector<uint8_t> &value)
{
    Set(NegotiateMessageKey::WIFI_CFG_INFO, value);
}

std::vector<uint8_t> NegotiateMessage::GetWifiConfigInfo() const
{
    return Get(NegotiateMessageKey::WIFI_CFG_INFO, std::vector<uint8_t>());
}

void NegotiateMessage::SetIpv4InfoArray(const std::vector<Ipv4Info> &value)
{
    Set(NegotiateMessageKey::IPV4_INFO_ARRAY, value);
}

std::vector<Ipv4Info> NegotiateMessage::GetIpv4InfoArray() const
{
    return Get(NegotiateMessageKey::IPV4_INFO_ARRAY, std::vector<Ipv4Info>());
}

void NegotiateMessage::SetPreferLinkMode(LinkInfo::LinkMode value)
{
    Set(NegotiateMessageKey::PREFER_LINK_MODE, static_cast<int>(value));
}

LinkInfo::LinkMode NegotiateMessage::GetPreferLinkMode() const
{
    auto value = Get(NegotiateMessageKey::PREFER_LINK_MODE, static_cast<int>(LinkInfo::LinkMode::INVALID));
    return static_cast<LinkInfo::LinkMode>(value);
}

void NegotiateMessage::SetIsModeStrict(bool value)
{
    Set(NegotiateMessageKey::IS_MODE_STRICT, value);
}

bool NegotiateMessage::GetIsModeStrict() const
{
    return Get(NegotiateMessageKey::IS_MODE_STRICT, false);
}

void NegotiateMessage::SetPreferLinkBandWidth(int value)
{
    Set(NegotiateMessageKey::PREFER_LINK_BANDWIDTH, value);
}

int NegotiateMessage::GetPreferLinkBandWidth() const
{
    return Get(NegotiateMessageKey::PREFER_LINK_BANDWIDTH, 0);
}

void NegotiateMessage::SetIsBridgeSupported(bool value)
{
    Set(NegotiateMessageKey::IS_BRIDGE_SUPPORTED, value);
}

bool NegotiateMessage::GetIsBridgeSupported() const
{
    return Get(NegotiateMessageKey::IS_BRIDGE_SUPPORTED, false);
}

void NegotiateMessage::SetLinkInfo(const LinkInfo &value)
{
    Set(NegotiateMessageKey::LINK_INFO, value);
}

LinkInfo NegotiateMessage::GetLinkInfo() const
{
    return Get(NegotiateMessageKey::LINK_INFO, LinkInfo());
}

void NegotiateMessage::SetResultCode(int value)
{
    Set(NegotiateMessageKey::RESULT_CODE, value);
}

int NegotiateMessage::GetResultCode() const
{
    return Get(NegotiateMessageKey::RESULT_CODE, RESULT_CODE_INVALID);
}

void NegotiateMessage::SetInterfaceInfoArray(const std::vector<InterfaceInfo> &value)
{
    Set(NegotiateMessageKey::INTERFACE_INFO_ARRAY, value);
}

std::vector<InterfaceInfo> NegotiateMessage::GetInterfaceInfoArray() const
{
    return Get(NegotiateMessageKey::INTERFACE_INFO_ARRAY, std::vector<InterfaceInfo>());
}

void NegotiateMessage::SetRemoteDeviceId(const std::string &value)
{
    Set(NegotiateMessageKey::REMOTE_DEVICE_ID, value);
}

std::string NegotiateMessage::GetRemoteDeviceId() const
{
    return Get(NegotiateMessageKey::REMOTE_DEVICE_ID, std::string());
}

void NegotiateMessage::SetRemoteNetworkId(const std::string &value)
{
    Set(NegotiateMessageKey::REMOTE_NETWORK_ID, value);
}

std::string NegotiateMessage::GetRemoteNetworkId() const
{
    return Get(NegotiateMessageKey::REMOTE_NETWORK_ID, std::string());
}

void NegotiateMessage::SetExtraData(const std::vector<uint8_t> &value)
{
    Set(NegotiateMessageKey::EXTRA_DATA_ARRAY, value);
}

std::vector<uint8_t> NegotiateMessage::GetExtraData() const
{
    return Get(NegotiateMessageKey::EXTRA_DATA_ARRAY, std::vector<uint8_t>());
}

void NegotiateMessage::SetIsProxyEnable(bool value)
{
    Set(NegotiateMessageKey::IS_PROXY_ENABLE, value);
}

bool NegotiateMessage::GetIsProxyEnable() const
{
    return Get(NegotiateMessageKey::IS_PROXY_ENABLE, false);
}

void NegotiateMessage::Set5GChannelList(const std::string &value)
{
    Set(NegotiateMessageKey::CHANNEL_5G_LIST, value);
}

std::string NegotiateMessage::Get5GChannelList() const
{
    return Get(NegotiateMessageKey::CHANNEL_5G_LIST, std::string());
}

void NegotiateMessage::Set5GChannelScore(const std::string &value)
{
    Set(NegotiateMessageKey::CHANNEL_5G_SCORE, value);
}

std::string NegotiateMessage::Get5GChannelScore() const
{
    return Get(NegotiateMessageKey::CHANNEL_5G_SCORE, std::string());
}

void NegotiateMessage::SetChallengeCode(uint32_t value)
{
    Set(NegotiateMessageKey::CHALLENGE_CODE, value);
}

uint32_t NegotiateMessage::GetChallengeCode() const
{
    return Get(NegotiateMessageKey::CHALLENGE_CODE, static_cast<uint32_t>(0));
}

void NegotiateMessage::SetNewPtkFrame(bool value)
{
    Set(NegotiateMessageKey::NEW_PTK_FRAME, value);
}

bool NegotiateMessage::GetNewPtkFrame() const
{
    return Get(NegotiateMessageKey::NEW_PTK_FRAME, false);
}

void NegotiateMessage::SetLegacyP2pGcChannelList(const std::string &value)
{
    Set(NegotiateMessageKey::GC_CHANNEL_LIST, value);
}

std::string NegotiateMessage::GetLegacyP2pGcChannelList() const
{
    return Get(NegotiateMessageKey::GC_CHANNEL_LIST, std::string());
}

void NegotiateMessage::SetLegacyP2pStationFrequency(int value)
{
    Set(NegotiateMessageKey::STATION_FREQUENCY, value);
}

int NegotiateMessage::GetLegacyP2pStationFrequency() const
{
    return Get(NegotiateMessageKey::STATION_FREQUENCY, 0);
}

void NegotiateMessage::SetLegacyP2pRole(WifiDirectRole value)
{
    Set(NegotiateMessageKey::ROLE, static_cast<int>(value));
}

WifiDirectRole NegotiateMessage::GetLegacyP2pRole() const
{
    auto value = Get(NegotiateMessageKey::ROLE, static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_INVALID));
    return static_cast<WifiDirectRole>(value);
}

void NegotiateMessage::SetLegacyP2pExpectedRole(WifiDirectRole value)
{
    Set(NegotiateMessageKey::EXPECTED_ROLE, static_cast<int>(value));
}

WifiDirectRole NegotiateMessage::GetLegacyP2pExpectedRole() const
{
    auto value = Get(NegotiateMessageKey::EXPECTED_ROLE, static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_INVALID));
    return static_cast<WifiDirectRole>(value);
}

void NegotiateMessage::SetLegacyP2pVersion(int value)
{
    Set(NegotiateMessageKey::VERSION, value);
}

int NegotiateMessage::GetLegacyP2pVersion() const
{
    return Get(NegotiateMessageKey::VERSION, 0);
}

void NegotiateMessage::SetLegacyP2pGcIp(const std::string &value)
{
    Set(NegotiateMessageKey::GC_IP, value);
}

std::string NegotiateMessage::GetLegacyP2pGcIp() const
{
    return Get(NegotiateMessageKey::GC_IP, std::string());
}

void NegotiateMessage::SetLegacyP2pWideBandSupported(bool value)
{
    Set(NegotiateMessageKey::WIDE_BAND_SUPPORTED, value);
}

bool NegotiateMessage::GetLegacyP2pWideBandSupported() const
{
    return Get(NegotiateMessageKey::WIDE_BAND_SUPPORTED, false);
}

void NegotiateMessage::SetLegacyP2pGroupConfig(const std::string &value)
{
    Set(NegotiateMessageKey::GROUP_CONFIG, value);
}

std::string NegotiateMessage::GetLegacyP2pGroupConfig() const
{
    return Get(NegotiateMessageKey::GROUP_CONFIG, std::string());
}

void NegotiateMessage::SetLegacyP2pMac(const std::string &value)
{
    Set(NegotiateMessageKey::MAC, value);
}

std::string NegotiateMessage::GetLegacyP2pMac() const
{
    return Get(NegotiateMessageKey::MAC, std::string());
}

void NegotiateMessage::SetLegacyP2pBridgeSupport(bool value)
{
    Set(NegotiateMessageKey::BRIDGE_SUPPORTED, value);
}

bool NegotiateMessage::GetLegacyP2pBridgeSupport() const
{
    return Get(NegotiateMessageKey::BRIDGE_SUPPORTED, false);
}

void NegotiateMessage::SetLegacyP2pGoIp(const std::string &value)
{
    Set(NegotiateMessageKey::GO_IP, value);
}

std::string NegotiateMessage::GetLegacyP2pGoIp() const
{
    return Get(NegotiateMessageKey::GO_IP, std::string());
}

void NegotiateMessage::SetLegacyP2pGoMac(const std::string &value)
{
    Set(NegotiateMessageKey::GO_MAC, value);
}

std::string NegotiateMessage::GetLegacyP2pGoMac() const
{
    return Get(NegotiateMessageKey::GO_MAC, std::string());
}

void NegotiateMessage::SetLegacyP2pGoPort(int value)
{
    Set(NegotiateMessageKey::GO_PORT, value);
}

int NegotiateMessage::GetLegacyP2pGoPort() const
{
    return Get(NegotiateMessageKey::GO_PORT, 0);
}

void NegotiateMessage::SetLegacyP2pIp(const std::string &value)
{
    Set(NegotiateMessageKey::IP, value);
}

std::string NegotiateMessage::GetLegacyP2pIp() const
{
    return Get(NegotiateMessageKey::IP, std::string());
}

void NegotiateMessage::SetLegacyP2pResult(LegacyResult value)
{
    Set(NegotiateMessageKey::RESULT, static_cast<int>(value));
}

LegacyResult NegotiateMessage::GetLegacyP2pResult() const
{
    auto value = Get(NegotiateMessageKey::RESULT, static_cast<int>(LegacyResult::OK));
    return static_cast<LegacyResult>(value);
}

void NegotiateMessage::SetLegacyP2pContentType(LegacyContentType value)
{
    Set(NegotiateMessageKey::CONTENT_TYPE, static_cast<int>(value));
}

LegacyContentType NegotiateMessage::GetLegacyP2pContentType() const
{
    auto value = Get(NegotiateMessageKey::CONTENT_TYPE, static_cast<int>(LegacyContentType::INVALID));
    return static_cast<LegacyContentType>(value);
}

void NegotiateMessage::SetLegacyP2pGcMac(const std::string &value)
{
    Set(NegotiateMessageKey::GC_MAC, value);
}

std::string NegotiateMessage::GetLegacyP2pGcMac() const
{
    return Get(NegotiateMessageKey::GC_MAC, std::string());
}

void NegotiateMessage::SetLegacyP2pWifiConfigInfo(const std::string &value)
{
    Set(NegotiateMessageKey::SELF_WIFI_CONFIG, value);
}

std::string NegotiateMessage::GetLegacyP2pWifiConfigInfo() const
{
    return Get(NegotiateMessageKey::SELF_WIFI_CONFIG, std::string());
}

void NegotiateMessage::SetLegacyP2pCommandType(LegacyCommandType value)
{
    Set(NegotiateMessageKey::COMMAND_TYPE, static_cast<int>(value));
}

LegacyCommandType NegotiateMessage::GetLegacyP2pCommandType() const
{
    auto value = Get(NegotiateMessageKey::COMMAND_TYPE, static_cast<int>(LegacyCommandType::CMD_INVALID));
    return static_cast<LegacyCommandType>(value);
}

void NegotiateMessage::SetLegacyInterfaceName(const std::string &value)
{
    Set(NegotiateMessageKey::INTERFACE_NAME, value);
}
std::string NegotiateMessage::GetLegacyInterfaceName() const
{
    return Get(NegotiateMessageKey::INTERFACE_NAME, std::string(""));
}

} // namespace OHOS::SoftBus
