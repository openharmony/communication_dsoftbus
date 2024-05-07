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

#include "wifi_direct_utils.h"
#include "bus_center_manager.h"
#include "conn_log.h"
#include "lnn_p2p_info.h"
#include "lnn_feature_capability.h"
#include "securec.h"
#include "softbus_error_code.h"
#include "syspara/parameters.h"
#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_defines.h"
#include <algorithm>
#include <arpa/inet.h>
#include <endian.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace OHOS::SoftBus {
std::vector<std::string> WifiDirectUtils::SplitString(const std::string &input, const std::string &delimiter)
{
    std::vector<std::string> tokens;
    size_t s = 0;
    size_t e = 0;

    while ((e = input.find(delimiter, s)) != std::string::npos) {
        auto token = input.substr(s, e - s);
        s += token.size() + delimiter.size();
        tokens.push_back(token);
    }
    if (s < input.length()) {
        tokens.push_back(input.substr(s, input.length() - s));
    }
    return tokens;
}

uint32_t WifiDirectUtils::BytesToInt(const std::vector<uint8_t> &data)
{
    return BytesToInt(data.data(), data.size());
}

uint32_t WifiDirectUtils::BytesToInt(const uint8_t *data, uint32_t size)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(size <= sizeof(uint32_t), 0, CONN_WIFI_DIRECT, "data len invalid");
    uint32_t result = 0;
    int res = memcpy_s(&result, sizeof(result), data, size);
    CONN_CHECK_AND_RETURN_RET_LOGW(res == EOK, 0, CONN_WIFI_DIRECT, "copy failed");
    return le32toh(result);
}

void WifiDirectUtils::IntToBytes(uint32_t data, uint32_t len, std::vector<uint8_t> &out)
{
    data = htole32(data);
    std::vector<uint8_t> result(len);
    if (memcpy_s(result.data(), len, &data, len) != EOK) {
        return;
    }
    out.insert(out.end(), result.begin(), result.end());
}

static constexpr int BYTE_HEX_BUF_LEN = 4;
std::string WifiDirectUtils::ToString(const std::vector<uint8_t> &input)
{
    char buf[BYTE_HEX_BUF_LEN] {};
    std::string result;
    for (const auto byte : input) {
        sprintf_s(buf, sizeof(buf), "%02x", byte);
        result += buf;
    }
    return result;
}

static constexpr int BYTE_HEX_SIZE = 2;
std::vector<uint8_t> WifiDirectUtils::ToBinary(const std::string &input)
{
    std::vector<uint8_t> result;
    for (size_t pos = 0; pos < input.length(); pos += BYTE_HEX_SIZE) {
        auto byteStr = input.substr(pos, BYTE_HEX_SIZE);
        char *end = nullptr;
        auto byte = std::strtoul(byteStr.c_str(), &end, 16);
        result.push_back(byte);
    }
    return result;
}

bool WifiDirectUtils::Is2GBand(int frequency)
{
    return frequency >= FREQUENCY_2G_FIRST && frequency <= FREQUENCY_2G_LAST;
}

bool WifiDirectUtils::Is5GBand(int frequency)
{
    return frequency >= FREQUENCY_5G_FIRST && frequency <= FREQUENCY_5G_LAST;
}

int WifiDirectUtils::ChannelToFrequency(int channel)
{
    if (channel >= CHANNEL_2G_FIRST && channel <= CHANNEL_2G_LAST) {
        return (channel - CHANNEL_2G_FIRST) * FREQUENCY_STEP + FREQUENCY_2G_FIRST;
    } else if (channel >= CHANNEL_5G_FIRST && channel <= CHANNEL_5G_LAST) {
        return (channel - CHANNEL_5G_FIRST) * FREQUENCY_STEP + FREQUENCY_5G_FIRST;
    } else {
        return FREQUENCY_INVALID;
    }
}

int WifiDirectUtils::FrequencyToChannel(int frequency)
{
    if (Is2GBand(frequency)) {
        return (frequency - FREQUENCY_2G_FIRST) / FREQUENCY_STEP + CHANNEL_2G_FIRST;
    } else if (Is5GBand(frequency)) {
        return (frequency - FREQUENCY_5G_FIRST) / FREQUENCY_STEP + CHANNEL_5G_FIRST;
    } else {
        return CHANNEL_INVALID;
    }
}

std::string WifiDirectUtils::NetworkIdToUuid(const std::string &networkId)
{
    char uuid[UUID_BUF_LEN] {};
    int ret = LnnGetRemoteStrInfo(networkId.c_str(), STRING_KEY_UUID, uuid, UUID_BUF_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "get uuid failed");
    return uuid;
}

std::string WifiDirectUtils::UuidToNetworkId(const std::string &uuid)
{
    char networkId[NETWORK_ID_BUF_LEN] {};
    auto ret = LnnGetNetworkIdByUuid(uuid.c_str(), networkId, sizeof(networkId));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "get network id failed");
    return networkId;
}

std::string WifiDirectUtils::GetLocalNetworkId()
{
    char networkId[NETWORK_ID_BUF_LEN] {};
    auto ret = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, networkId, NETWORK_ID_BUF_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "get network id failed");
    return networkId;
}

std::string WifiDirectUtils::GetLocalUuid()
{
    char uuid[UUID_BUF_LEN] {};
    auto ret = LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "get uuid id failed");
    return uuid;
}

static constexpr int PTK_128BIT_LEN = 16;
std::vector<uint8_t> WifiDirectUtils::GetLocalPtk(const std::string &remoteNetworkId)
{
    auto remoteUuid = NetworkIdToUuid(remoteNetworkId);
    std::vector<uint8_t> result;
    uint8_t ptkBytes[PTK_DEFAULT_LEN] {};
    auto ret = LnnGetLocalPtkByUuid(remoteUuid.c_str(), (char *)ptkBytes, sizeof(ptkBytes));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, result, CONN_WIFI_DIRECT, "get local ptk failed");
    result.insert(result.end(), ptkBytes, ptkBytes + PTK_128BIT_LEN);
    return result;
}

std::vector<uint8_t> WifiDirectUtils::GetRemotePtk(const std::string &remoteNetworkId)
{
    std::vector<uint8_t> result;
    uint8_t ptkBytes[PTK_DEFAULT_LEN] = { 0 };
    int32_t ret = LnnGetRemoteByteInfo(remoteNetworkId.c_str(), BYTE_KEY_REMOTE_PTK, ptkBytes, sizeof(ptkBytes));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, result, CONN_WIFI_DIRECT, "get remote ptk failed");
    result.insert(result.end(), ptkBytes, ptkBytes + PTK_128BIT_LEN);
    return result;
}

bool WifiDirectUtils::IsRemoteSupportTlv(const std::string &remoteDeviceId)
{
    bool result = false;
    auto networkId = UuidToNetworkId(remoteDeviceId);
    auto ret = LnnGetRemoteBoolInfo(networkId.c_str(), BOOL_KEY_TLV_NEGOTIATION, &result);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, true, CONN_WIFI_DIRECT, "get tlv feature failed");
    return result;
}

bool WifiDirectUtils::IsLocalSupportTlv()
{
    uint64_t capability = LnnGetFeatureCapabilty();
    return IsFeatureSupport(capability, BIT_WIFI_DIRECT_TLV_NEGOTIATION);
}

static constexpr int MAC_BYTE_HEX_SIZE = 4;
std::string WifiDirectUtils::MacArrayToString(const std::vector<uint8_t> &macArray)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(!macArray.empty(), "", CONN_WIFI_DIRECT, "mac empty");
    std::string macString;
    char buf[MAC_BYTE_HEX_SIZE] {};
    for (const auto byte : macArray) {
        if (sprintf_s(buf, MAC_BYTE_HEX_SIZE, "%02x:", byte) < 0) {
            return "";
        }
        macString.append(buf);
    }
    macString.erase(macString.length() - 1);
    return macString;
}

static constexpr int BASE_HEX = 16;
std::vector<uint8_t> WifiDirectUtils::MacStringToArray(const std::string &macString)
{
    std::vector<uint8_t> array;
    CONN_CHECK_AND_RETURN_RET_LOGE(!macString.empty(), array, CONN_WIFI_DIRECT, "mac empty");
    auto tokens = SplitString(macString, ":");
    for (const auto &token : tokens) {
        size_t idx {};
        array.push_back(static_cast<uint8_t>(stoul(token, &idx, BASE_HEX)));
    }
    return array;
}

std::vector<uint8_t> WifiDirectUtils::GetInterfaceMacAddr(const std::string &interface)
{
    struct ifreq ifr { };
    std::vector<uint8_t> macArray;

    int ret = strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), interface.c_str());
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, macArray, CONN_WIFI_DIRECT, "copy interface name failed");
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    CONN_CHECK_AND_RETURN_RET_LOGW(fd > 0, macArray, CONN_WIFI_DIRECT, "open socket failed");
    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    CONN_CHECK_AND_RETURN_RET_LOGW(ret == 0, macArray, CONN_WIFI_DIRECT, "get hw addr failed ret=%{public}d", ret);
    macArray.insert(macArray.end(), ifr.ifr_hwaddr.sa_data, ifr.ifr_hwaddr.sa_data + MAC_ADDR_ARRAY_SIZE);
    return macArray;
}

std::vector<Ipv4Info> WifiDirectUtils::GetLocalIpv4Infos()
{
    std::vector<Ipv4Info> ipv4Infos;
    struct ifaddrs *ifAddr = nullptr;
    if (getifaddrs(&ifAddr) == -1) {
        CONN_LOGE(CONN_WIFI_DIRECT, "getifaddrs failed, errno=%{public}d", errno);
        return ipv4Infos;
    }

    struct ifaddrs *ifa = nullptr;
    for (ifa = ifAddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET || ifa->ifa_netmask == nullptr ||
            strcmp(ifa->ifa_name, "chba0") != 0) {
            continue;
        }
        char ip[IP_LEN] {};
        auto *addr = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
        inet_ntop(AF_INET, &addr->sin_addr.s_addr, ip, sizeof(ip));
        ipv4Infos.emplace_back(ip);

        CONN_LOGI(CONN_WIFI_DIRECT, "name=%{public}s, ip=%{public}s", ifa->ifa_name, WifiDirectAnonymizeIp(ip).c_str());
    }

    freeifaddrs(ifAddr);
    return ipv4Infos;
}

int WifiDirectUtils::CompareIgnoreCase(const std::string &left, const std::string &right)
{
    std::string leftLower = left;
    std::transform(left.begin(), left.end(), leftLower.begin(), ::tolower);
    std::string rightLower = right;
    std::transform(right.begin(), right.end(), rightLower.begin(), ::tolower);
    return leftLower.compare(rightLower);
}

bool WifiDirectUtils::SupportHml()
{
    bool support = OHOS::system::GetBoolParameter("persist.sys.softbus.connect.hml", true);
    CONN_LOGI(CONN_WIFI_DIRECT, "persist.sys.softbus.connect.hml=%{public}d", support);
    return support;
}

bool WifiDirectUtils::SupportHmlTwo()
{
    bool support = OHOS::system::GetBoolParameter("persist.sys.softbus.connect.hml_two", true);
    CONN_LOGI(CONN_WIFI_DIRECT, "persist.sys.softbus.connect.hml_two=%{public}d", support);
    return support;
}

int32_t WifiDirectUtils::GetInterfaceIpString(const std::string &interface, std::string &ip)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "interface=%{public}s", interface.c_str());

    int32_t socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    CONN_CHECK_AND_RETURN_RET_LOGW(socketFd >= 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "open socket failed");

    struct ifreq request { };
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    int32_t ret = strcpy_s(request.ifr_name, sizeof(request.ifr_name), (const char *)interface.c_str());
    if (ret != EOK) {
        CONN_LOGW(CONN_WIFI_DIRECT, "copy interface name failed");
        close(socketFd);
        return SOFTBUS_ERR;
    }

    ret = ioctl(socketFd, SIOCGIFADDR, &request);
    close(socketFd);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret >= 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get ifr conf failed ret=%{public}d", ret);

    auto *sockAddrIn = (struct sockaddr_in *)&request.ifr_addr;
    char ipString[IP_LEN] = { 0 };
    if (!inet_ntop(sockAddrIn->sin_family, &sockAddrIn->sin_addr, ipString, IP_LEN)) {
        CONN_LOGW(CONN_WIFI_DIRECT, "inet_ntop failed");
        return SOFTBUS_ERR;
    }
    ip = std::string(ipString);
    return SOFTBUS_OK;
}

bool WifiDirectUtils::IsInChannelList(int32_t channel, const std::vector<int> &channelArray)
{
    for (size_t i = 0; i < channelArray.size(); i++) {
        if (channel == channelArray[i]) {
            return true;
        }
    }
    return false;
}

int32_t WifiDirectUtils::IpStringToIntArray(const char *addrString, uint32_t *addrArray, size_t addrArraySize)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(addrString, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "addrString is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(
        addrArraySize >= IPV4_ADDR_ARRAY_LEN, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "array to small");

    int32_t ret = sscanf_s(addrString, "%u.%u.%u.%u", addrArray, addrArray + 1, addrArray + 2, addrArray + 3);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret > 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "scan ip number failed");
    return SOFTBUS_OK;
}

std::string WifiDirectUtils::ChannelListToString(const std::vector<int> &channels)
{
    std::string stringChannels;
    for (auto i = 0; i < channels.size(); i++) {
        if (i != 0) {
            stringChannels += "##";
        }
        stringChannels += std::to_string(channels[i]);
    }
    return stringChannels;
}

std::vector<int> WifiDirectUtils::StringToChannelList(std::string channels)
{
    std::vector<int> vectorChannels;
    if (channels.empty()) {
        return vectorChannels;
    }

    auto values = SplitString(channels, "##");
    for (auto c : values) {
        vectorChannels.push_back(std::stoi(c));
    }
    return vectorChannels;
}

WifiDirectRole WifiDirectUtils::ToWifiDirectRole(LinkInfo::LinkMode mode)
{
    switch (mode) {
        case LinkInfo::LinkMode::INVALID:
            return WifiDirectRole::WIFI_DIRECT_ROLE_INVALID;
        case LinkInfo::LinkMode::NONE:
            return WifiDirectRole::WIFI_DIRECT_ROLE_NONE;
        case LinkInfo::LinkMode::STA:
            return WifiDirectRole::WIFI_DIRECT_ROLE_INVALID;
        case LinkInfo::LinkMode::AP:
            return WifiDirectRole::WIFI_DIRECT_ROLE_INVALID;
        case LinkInfo::LinkMode::GO:
            return WifiDirectRole::WIFI_DIRECT_ROLE_GO;
        case LinkInfo::LinkMode::GC:
            return WifiDirectRole::WIFI_DIRECT_ROLE_GC;
        case LinkInfo::LinkMode::HML:
            return WifiDirectRole::WIFI_DIRECT_ROLE_HML;
        default:
            return WifiDirectRole::WIFI_DIRECT_ROLE_INVALID;
    }
}

void WifiDirectUtils::ShowLinkInfoList(const std::string &banana, const std::vector<LinkInfo> &inkList)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "banana=%{public}s", banana.c_str());

    for (const LinkInfo &info : inkList) {
        CONN_LOGI(CONN_WIFI_DIRECT, "interface=%{public}s, mode=%{public}d", info.GetLocalInterface().c_str(),
            static_cast<int>(info.GetLocalLinkMode()));
    }
}
} // namespace OHOS::SoftBus
