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
#ifndef NEGOTIATE_MESSAGE_H
#define NEGOTIATE_MESSAGE_H

#include <map>
#include <set>
#include "info_container.h"
#include "ipv4_info.h"
#include "interface_info.h"
#include "link_info.h"

#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
enum class LegacyCommandType {
    CMD_INVALID = -1,
    /* v1 cmd */
    CMD_DISCONNECT_V1_REQ = 5,
    CMD_CONN_V1_REQ = 8,
    CMD_CONN_V1_RESP = 9,
    CMD_REUSE_REQ = 12,
    CMD_CTRL_CHL_HANDSHAKE = 13,
    CMD_GC_WIFI_CONFIG_CHANGED = 17,
    CMD_REUSE_RESP = 19,

    CMD_PC_GET_INTERFACE_INFO_REQ = 30,
    CMD_PC_GET_INTERFACE_INFO_RESP = 31,
    CMD_FORCE_DISCONNECT_V1_REQ = 32,
};

enum class LegacyContentType {
    INVALID = -1,
    GO_INFO = 1,
    GC_INFO = 2,
    RESULT = 3,
};

enum class LegacyResult {
    OK = 0,
    V1_ERROR_CONNECTED_WITH_MISMATCHED_ROLE = -1,
    V1_ERROR_IF_NOT_AVAILABLE = -25,
};

enum class NegotiateMessageType {
    CMD_INVALID = -1,
    /* v1 cmd is defined by LegacyCommandType*/

    /* v2 cmd */
    CMD_CONN_V2_REQ_1 = 21,
    CMD_CONN_V2_REQ_2 = 22,
    CMD_CONN_V2_REQ_3 = 23,
    CMD_CONN_V2_RESP_1 = 24,
    CMD_CONN_V2_RESP_2 = 25,
    CMD_CONN_V2_RESP_3 = 26,
    CMD_DISCONNECT_V2_REQ = 27,
    CMD_DISCONNECT_V2_RESP = 28,
    CMD_CLIENT_JOIN_FAIL_NOTIFY = 29,
    /* 30-49 is for LegacyCommandType*/

    CMD_TRIGGER_REQ = 50,
    CMD_TRIGGER_RESP = 51,
    CMD_AUTH_LISTEN_RESP = 52,
    CMD_RENEGOTIATE_REQ = 53,
    CMD_RENEGOTIATE_RESP = 54,
    CMD_AUTH_HAND_SHAKE = 55,
    CMD_AUTH_HAND_SHAKE_RSP = 56,
    CMD_DETECT_LINK_REQ = 57,
    CMD_DETECT_LINK_RSP = 58,
    CMD_FORCE_DISCONNECT_REQ = 59,

    CMD_V3_REQ = 100,
    CMD_V3_RSP = 101,
    CMD_V3_CUSTOM_PORT_REQ = 102,
    CMD_V3_CUSTOM_PORT_RSP = 103,
    CMD_ERROR_NOTIFICATION = 104,
};

enum class NegotiateMessageKey {
    MSG_TYPE = 0,
    SESSION_ID = 1,
    WIFI_CFG_INFO = 2,
    IPV4_INFO_ARRAY = 3,
    PREFER_LINK_MODE = 4,
    IS_MODE_STRICT = 5,
    PREFER_LINK_BANDWIDTH = 6,
    IS_BRIDGE_SUPPORTED = 7,
    LINK_INFO = 8,
    RESULT_CODE = 9,
    INTERFACE_INFO_ARRAY = 10,
    REMOTE_DEVICE_ID = 11,
    NEGO_CHANNEL = 12,
    EXTRA_DATA_ARRAY = 13,
    INNER_LINK = 14,
    WIFI_CFG_TYPE = 15,
    IS_PROXY_ENABLE = 16,
    CHANNEL_5G_LIST = 17,
    CHANNEL_5G_SCORE = 18,
    CHALLENGE_CODE = 19,
    NEW_PTK_FRAME = 20,
    REMOTE_NETWORK_ID = 21,

    /* old p2p */
    GC_CHANNEL_LIST = 200,
    STATION_FREQUENCY = 201,
    ROLE = 202,
    EXPECTED_ROLE = 203,
    VERSION = 204,
    GC_IP = 205,
    WIDE_BAND_SUPPORTED = 206,
    GROUP_CONFIG = 207,
    MAC = 208,
    BRIDGE_SUPPORTED = 209,
    GO_IP = 210,
    GO_MAC = 211,
    GO_PORT = 212,
    IP = 213,
    RESULT = 214,
    CONTENT_TYPE = 215,
    GC_MAC = 216,
    SELF_WIFI_CONFIG = 217,
    GC_CHANNEL_SCORE = 218,
    COMMAND_TYPE = 219,
    INTERFACE_NAME = 220,
};

class NegotiateMessage : public Serializable, public InfoContainer<NegotiateMessageKey> {
public:
    NegotiateMessage();
    explicit NegotiateMessage(NegotiateMessageType type);
    explicit NegotiateMessage(LegacyCommandType type);
    ~NegotiateMessage() override;

    int Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const override;
    int Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input) override;

    void SetMessageType(NegotiateMessageType value);
    void SetMessageType(LegacyCommandType value);
    NegotiateMessageType GetMessageType() const;
    std::string MessageTypeToString() const;

    static constexpr int SESSION_ID_INVALID = -1;
    void SetSessionId(uint32_t value);
    uint32_t GetSessionId() const;

    void SetWifiConfigInfo(const std::vector<uint8_t> &value);
    std::vector<uint8_t> GetWifiConfigInfo() const;

    void SetIpv4InfoArray(const std::vector<Ipv4Info> &value);
    std::vector<Ipv4Info> GetIpv4InfoArray() const;

    void SetPreferLinkMode(LinkInfo::LinkMode value);
    LinkInfo::LinkMode GetPreferLinkMode() const;

    void SetIsModeStrict(bool value);
    bool GetIsModeStrict() const;

    void SetPreferLinkBandWidth(int value);
    int GetPreferLinkBandWidth() const;

    void SetIsBridgeSupported(bool value);
    bool GetIsBridgeSupported() const;

    void SetLinkInfo(const LinkInfo &value);
    LinkInfo GetLinkInfo() const;

    static constexpr int RESULT_CODE_INVALID = -1;
    void SetResultCode(int value);
    int GetResultCode() const;

    void SetInterfaceInfoArray(const std::vector<InterfaceInfo> &value);
    std::vector<InterfaceInfo> GetInterfaceInfoArray() const;

    void SetRemoteDeviceId(const std::string &value);
    std::string GetRemoteDeviceId() const;

    void SetRemoteNetworkId(const std::string &value);
    std::string GetRemoteNetworkId() const;

    void SetExtraData(const std::vector<uint8_t> &value);
    std::vector<uint8_t> GetExtraData() const;

    void SetIsProxyEnable(bool value);
    bool GetIsProxyEnable() const;

    void Set5GChannelList(const std::string &value);
    std::string Get5GChannelList() const;

    void Set5GChannelScore(const std::string &value);
    std::string Get5GChannelScore() const;

    void SetChallengeCode(uint32_t value);
    uint32_t GetChallengeCode() const;

    void SetNewPtkFrame(bool value);
    bool GetNewPtkFrame() const;

    void SetLegacyP2pGcChannelList(const std::string &value);
    std::string GetLegacyP2pGcChannelList() const;

    void SetLegacyP2pStationFrequency(int value);
    int GetLegacyP2pStationFrequency() const;

    void SetLegacyP2pRole(WifiDirectRole value);
    WifiDirectRole GetLegacyP2pRole() const;

    void SetLegacyP2pExpectedRole(WifiDirectRole value);
    WifiDirectRole GetLegacyP2pExpectedRole() const;

    void SetLegacyP2pVersion(int value);
    int GetLegacyP2pVersion() const;

    void SetLegacyP2pGcIp(const std::string &value);
    std::string GetLegacyP2pGcIp() const;

    void SetLegacyP2pWideBandSupported(bool value);
    bool GetLegacyP2pWideBandSupported() const;

    void SetLegacyP2pGroupConfig(const std::string &value);
    std::string GetLegacyP2pGroupConfig() const;

    void SetLegacyP2pMac(const std::string &value);
    std::string GetLegacyP2pMac() const;

    void SetLegacyP2pBridgeSupport(bool value);
    bool GetLegacyP2pBridgeSupport() const;

    void SetLegacyP2pGoIp(const std::string &value);
    std::string GetLegacyP2pGoIp() const;

    void SetLegacyP2pGoMac(const std::string &value);
    std::string GetLegacyP2pGoMac() const;

    void SetLegacyP2pGoPort(int value);
    int GetLegacyP2pGoPort() const;

    void SetLegacyP2pIp(const std::string &value);
    std::string GetLegacyP2pIp() const;

    void SetLegacyP2pResult(LegacyResult value);
    LegacyResult GetLegacyP2pResult() const;

    void SetLegacyP2pContentType(LegacyContentType value);
    LegacyContentType GetLegacyP2pContentType() const;

    void SetLegacyP2pGcMac(const std::string &value);
    std::string GetLegacyP2pGcMac() const;

    void SetLegacyP2pWifiConfigInfo(const std::string &value);
    std::string GetLegacyP2pWifiConfigInfo() const;

    void SetLegacyP2pCommandType(LegacyCommandType value);
    LegacyCommandType GetLegacyP2pCommandType() const;

    void SetLegacyInterfaceName(const std::string &value);
    std::string GetLegacyInterfaceName() const;

    static std::map<NegotiateMessageKey, std::string> keyStringTable_;

private:
    void MarshallingIpv4Array(WifiDirectProtocol &protocol) const ;
    void MarshallingInterfaceArray(WifiDirectProtocol &protocol) const ;
    void MarshallingLinkInfo(WifiDirectProtocol &protocol) const ;

    void UnmarshallingIpv4Array(uint8_t *data, size_t size);
    void UnmarshallingInterfaceArray(WifiDirectProtocol &protocol, uint8_t *data, size_t size);
    void UnmarshallingLinkInfo(WifiDirectProtocol &protocol, uint8_t *data, size_t size);

    static std::set<NegotiateMessageKey> keyIgnoreTable_;
};
}
#endif
