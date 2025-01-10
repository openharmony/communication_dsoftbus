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

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <endian.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bus_center_manager.h"
#include "conn_log.h"
#include "data/link_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_vap_info.h"
#include "lnn_node_info.h"
#include "lnn_p2p_info.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "syspara/parameters.h"
#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_defines.h"

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

int WifiDirectUtils::GetRecommendChannelFromLnn(const std::string &networkId)
{
    char udid[UDID_BUF_LEN] {};
    int ret = LnnGetRemoteStrInfo(networkId.c_str(), STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get udid failed, ret = %{public}d", ret);
    int channelIdLnn = 0;
    ret = LnnGetRecommendChannel(udid, &channelIdLnn);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get channel from Lnn failed, ret = %{public}d", ret);
    return channelIdLnn;
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

int32_t WifiDirectUtils::GetLocalConnSubFeature(uint64_t &feature)
{
    uint64_t connSubFeature = 0;
    auto ret = LnnGetLocalNumU64Info(NUM_KEY_CONN_SUB_FEATURE_CAPA, &connSubFeature);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get connSubFeature failed");
    feature = connSubFeature;
    return SOFTBUS_OK;
}

static constexpr int PTK_128BIT_LEN = 16;
std::vector<uint8_t> WifiDirectUtils::GetLocalPtk(const std::string &remoteNetworkId)
{
    auto remoteUuid = NetworkIdToUuid(remoteNetworkId);
    std::vector<uint8_t> result;
    uint8_t ptkBytes[PTK_DEFAULT_LEN] {};
    auto ret = LnnGetLocalPtkByUuid(remoteUuid.c_str(), (char *)ptkBytes, sizeof(ptkBytes));
    if (ret == SOFTBUS_NOT_FIND) {
        ret = LnnGetLocalDefaultPtkByUuid(remoteUuid.c_str(), (char *)ptkBytes, sizeof(ptkBytes));
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, result, CONN_WIFI_DIRECT, "get local ptk failed");
    result.insert(result.end(), ptkBytes, ptkBytes + PTK_128BIT_LEN);
    return result;
}

std::vector<uint8_t> WifiDirectUtils::GetRemotePtk(const std::string &remoteNetworkId)
{
    std::vector<uint8_t> result;
    uint8_t ptkBytes[PTK_DEFAULT_LEN] {};
    uint8_t zeroPtkBytes[PTK_DEFAULT_LEN] {};
    auto remoteUuid = NetworkIdToUuid(remoteNetworkId);
    int32_t ret = LnnGetRemoteByteInfo(remoteNetworkId.c_str(), BYTE_KEY_REMOTE_PTK, ptkBytes, sizeof(ptkBytes));
    if (ret == SOFTBUS_OK && memcmp(ptkBytes, zeroPtkBytes, PTK_DEFAULT_LEN) == 0) {
        ret = LnnGetRemoteDefaultPtkByUuid(remoteUuid.c_str(), (char *)ptkBytes, sizeof(ptkBytes));
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, result, CONN_WIFI_DIRECT, "get remote ptk failed");
    result.insert(result.end(), ptkBytes, ptkBytes + PTK_128BIT_LEN);
    return result;
}

bool WifiDirectUtils::IsRemoteSupportTlv(const std::string &remoteDeviceId)
{
    bool result = false;
    auto networkId = UuidToNetworkId(remoteDeviceId);
    auto ret = LnnGetRemoteBoolInfoIgnoreOnline(networkId.c_str(), BOOL_KEY_TLV_NEGOTIATION, &result);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, true, CONN_WIFI_DIRECT, "get tlv feature failed");
    return result;
}

bool WifiDirectUtils::IsLocalSupportTlv()
{
    uint64_t capability = LnnGetFeatureCapabilty();
    return IsFeatureSupport(capability, BIT_WIFI_DIRECT_TLV_NEGOTIATION);
}

void WifiDirectUtils::SetLocalWifiDirectMac(const std::string &mac)
{
    LnnSetLocalStrInfo(STRING_KEY_WIFIDIRECT_ADDR, mac.c_str());
}

bool WifiDirectUtils::IsDeviceOnline(const std::string &remoteNetworkId)
{
    return LnnGetOnlineStateById(remoteNetworkId.c_str(), CATEGORY_NETWORK_ID);
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

std::string WifiDirectUtils::MacArrayToString(const uint8_t *mac, int size)
{
    std::vector<uint8_t> macArray(mac, mac + size);
    return MacArrayToString(macArray);
}

static constexpr int BASE_HEX = 16;
std::vector<uint8_t> WifiDirectUtils::MacStringToArray(const std::string &macString)
{
    std::vector<uint8_t> array;
    CONN_CHECK_AND_RETURN_RET_LOGE(!macString.empty(), array, CONN_WIFI_DIRECT, "mac empty");
    auto tokens = SplitString(macString, ":");
    for (const auto &token : tokens) {
        size_t idx {};
        unsigned long result = 0;
        try {
            result = std::stoul(token, &idx, BASE_HEX);
        } catch (const std::out_of_range& e) {
            // invalid mac address, which is printed for fault locating.
            CONN_LOGE(CONN_NEARBY, "out of range, error mac string=%{public}s", macString.c_str());
            return std::vector<uint8_t>();
        } catch (const std::invalid_argument& e) {
            // invalid mac address, which is printed for fault locating.
            CONN_LOGE(CONN_NEARBY, "invalid argument, error mac string=%{public}s", macString.c_str());
            return std::vector<uint8_t>();
        }
        array.push_back(static_cast<uint8_t>(result));
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
    CONN_CHECK_AND_RETURN_RET_LOGW(fd > 0, macArray, CONN_WIFI_DIRECT,
        "open socket failed, fd=%{public}d, errno=%{public}d(%{public}s)", fd, errno, strerror(errno));
    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    CONN_CHECK_AND_RETURN_RET_LOGW(ret == 0, macArray, CONN_WIFI_DIRECT,
        "get hw addr failed ret=%{public}d, errno=%{public}d(%{public}s)", ret, errno, strerror(errno));
    macArray.insert(macArray.end(), ifr.ifr_hwaddr.sa_data, ifr.ifr_hwaddr.sa_data + MAC_ADDR_ARRAY_SIZE);
    return macArray;
}

std::string WifiDirectUtils::GetInterfaceIpv6Addr(const std::string &name)
{
    struct ifaddrs *allAddr = nullptr;
    auto ret = getifaddrs(&allAddr);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, "", CONN_WIFI_DIRECT,
        "getifaddrs failed, ret=%{public}d, errno=%{public}d(%{public}s)", ret, errno, strerror(errno));

    for (struct ifaddrs *ifa = allAddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET6 || ifa->ifa_netmask == nullptr ||
            strcmp(ifa->ifa_name, name.c_str()) != 0) {
            continue;
        }
        char ip[IP_LEN] {};
        auto *addr = reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
        inet_ntop(AF_INET6, &addr->sin6_addr.s6_addr, ip, sizeof(ip));
        return ip;
    }

    freeifaddrs(allAddr);
    return "";
}

std::vector<Ipv4Info> WifiDirectUtils::GetLocalIpv4Infos()
{
    std::vector<Ipv4Info> ipv4Infos;
    struct ifaddrs *ifAddr = nullptr;
    if (getifaddrs(&ifAddr) == -1) {
        CONN_LOGE(CONN_WIFI_DIRECT, "getifaddrs failed, errno=%{public}d(%{public}s)", errno, strerror(errno));
        return ipv4Infos;
    }

    struct ifaddrs *ifa = nullptr;
    for (ifa = ifAddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET || ifa->ifa_netmask == nullptr ||
            strcmp(ifa->ifa_name, IF_NAME_HML) != 0) {
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
    CONN_CHECK_AND_RETURN_RET_LOGW(socketFd >= 0, SOFTBUS_CONN_OPEN_SOCKET_FAILED, CONN_WIFI_DIRECT,
        "open socket failed, socketFd=%{public}d, errno=%{public}d(%{public}s)", socketFd, errno, strerror(errno));

    struct ifreq request { };
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    int32_t ret = strcpy_s(request.ifr_name, sizeof(request.ifr_name), (const char *)interface.c_str());
    if (ret != EOK) {
        CONN_LOGW(CONN_WIFI_DIRECT, "copy interface name failed");
        close(socketFd);
        return SOFTBUS_CONN_COPY_INTERFACE_NAME_FAILED;
    }

    ret = ioctl(socketFd, SIOCGIFADDR, &request);
    close(socketFd);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret >= 0, SOFTBUS_CONN_GET_IFR_CONF_FAILED, CONN_WIFI_DIRECT,
        "get ifr conf failed ret=%{public}d, errno=%{public}d(%{public}s)", ret, errno, strerror(errno));

    auto *sockAddrIn = (struct sockaddr_in *)&request.ifr_addr;
    char ipString[IP_LEN] = { 0 };
    if (!inet_ntop(sockAddrIn->sin_family, &sockAddrIn->sin_addr, ipString, IP_LEN)) {
        CONN_LOGW(CONN_WIFI_DIRECT, "inet_ntop failed");
        return SOFTBUS_CONN_INET_NTOP_FAILED;
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
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == IPV4_ADDR_ARRAY_LEN, SOFTBUS_CONN_SCAN_IP_NUMBER_FAILED, CONN_WIFI_DIRECT, "scan ip number failed");
    return SOFTBUS_OK;
}

std::string WifiDirectUtils::ChannelListToString(const std::vector<int> &channels)
{
    std::string stringChannels;
    for (size_t i = 0; i < channels.size(); i++) {
        if (i != 0) {
            stringChannels += "##";
        }
        stringChannels += std::to_string(channels[i]);
    }
    return stringChannels;
}

static bool StringToInt(const std::string &channelString, int32_t &result)
{
    auto [ptr, ec] = std::from_chars(channelString.data(), channelString.data() + channelString.size(), result);
    return ec == std::errc{} && ptr == channelString.data() + channelString.size();
}

std::vector<int> WifiDirectUtils::StringToChannelList(std::string channels)
{
    std::vector<int> vectorChannels;
    if (channels.empty()) {
        return vectorChannels;
    }

    auto values = SplitString(channels, "##");
    for (auto c : values) {
        int32_t result = 0;
        CONN_CHECK_AND_RETURN_RET_LOGE(StringToInt(c, result), std::vector<int>(),
            CONN_WIFI_DIRECT, "not a int value=%{public}s", c.c_str());
        vectorChannels.push_back(result);
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
    int count = 0;
    for (const auto &info : inkList) {
        CONN_LOGI(CONN_WIFI_DIRECT, "%{public}s[%{public}d]: name=%{public}s, mode=%{public}d", banana.c_str(), count,
                  info.GetLocalInterface().c_str(), info.GetLocalLinkMode());
        count++;
    }
}

enum WifiDirectBandWidth WifiDirectUtils::BandWidthNumberToEnum(int bandWidth)
{
    return bandWidth >= BAND_WIDTH_160M_NUMBER ? BAND_WIDTH_160M : BAND_WIDTH_80M;
}

int WifiDirectUtils::BandWidthEnumToNumber(WifiDirectBandWidth bandWidth)
{
    switch (bandWidth) {
        case BAND_WIDTH_160M:
            return BAND_WIDTH_160M_NUMBER;
        default:
            return BAND_WIDTH_80M_NUMBER;
    }
}

void WifiDirectUtils::SerialFlowEnter()
{
    std::unique_lock lock(serialParallelLock_);
    CONN_LOGI(CONN_WIFI_DIRECT, "serialCount=%{public}d, parallelCount=%{public}d", serialCount_, parallelCount_);
    serialParallelCv_.wait(lock, [] () { return parallelCount_ == 0; });
    serialCount_++;
    CONN_LOGI(CONN_WIFI_DIRECT, "serialCount=%{public}d, parallelCount=%{public}d", serialCount_, parallelCount_);
}

void WifiDirectUtils::SerialFlowExit()
{
    std::unique_lock lock(serialParallelLock_);
    serialCount_--;
    CONN_LOGI(CONN_WIFI_DIRECT, "serialCount=%{public}d, parallelCount=%{public}d", serialCount_, parallelCount_);
    serialParallelCv_.notify_all();
}

void WifiDirectUtils::ParallelFlowEnter()
{
    std::unique_lock lock(serialParallelLock_);
    CONN_LOGI(CONN_WIFI_DIRECT, "serialCount=%{public}d, parallelCount=%{public}d", serialCount_, parallelCount_);
    serialParallelCv_.wait(lock, [] () { return serialCount_ == 0; });
    parallelCount_++;
    CONN_LOGI(CONN_WIFI_DIRECT, "serialCount=%{public}d, parallelCount=%{public}d", serialCount_, parallelCount_);
}

void WifiDirectUtils::ParallelFlowExit()
{
    std::unique_lock lock(serialParallelLock_);
    parallelCount_--;
    CONN_LOGI(CONN_WIFI_DIRECT, "serialCount=%{public}d, parallelCount=%{public}d", serialCount_, parallelCount_);
    serialParallelCv_.notify_all();
}

uint32_t WifiDirectUtils::CalculateStringLength(const char *str, uint32_t size)
{
    for (int32_t i = static_cast<int32_t>(size) - 1; i >= 0; i--) {
        if (str[i] != '\0') {
            return static_cast<uint32_t>(i) + 1;
        }
    }
    return 0;
}

void WifiDirectUtils::SyncLnnInfoForP2p(WifiDirectRole role, const std::string &localMac, const std::string &goMac)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "role=%{public}d, localMac=%{public}s, goMac=%{public}s",
        role, WifiDirectAnonymizeMac(localMac).c_str(), WifiDirectAnonymizeMac(goMac).c_str());
    int32_t ret = LnnSetLocalNumInfo(NUM_KEY_P2P_ROLE, role);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "set lnn p2p role failed");
    }

    ret = LnnSetLocalStrInfo(STRING_KEY_P2P_MAC, localMac.c_str());
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "set lnn my mac failed");
    }

    ret = LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, goMac.c_str());
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "set lnn go mac failed");
    }

    LnnSyncP2pInfo();
}

static constexpr int DFS_CHANNEL_FIRST = 52;
static constexpr int DFS_CHANNEL_LAST = 64;
bool WifiDirectUtils::IsDfsChannel(const int &frequency)
{
    int32_t channel = FrequencyToChannel(frequency);
    CONN_LOGI(CONN_WIFI_DIRECT, "channel=%{public}d", channel);
    if (channel >= DFS_CHANNEL_FIRST && channel <= DFS_CHANNEL_LAST) {
        return true;
    }
    return false;
}

bool WifiDirectUtils::CheckLinkAtDfsChannelConflict(const std::string &remoteDeviceId, InnerLink::LinkType type)
{
    bool dfsLinkIsExist = false;
    auto remoteNetworkId = UuidToNetworkId(remoteDeviceId);

    int32_t osType = OH_OS_TYPE;
    if (LnnGetOsTypeByNetworkId(remoteNetworkId.c_str(), &osType) != SOFTBUS_OK || osType == OH_OS_TYPE) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get os type failed");
        return false;
    }

    LinkManager::GetInstance().ForEach([&dfsLinkIsExist, osType, type](InnerLink &link) {
        if (link.GetLinkType() == type && IsDfsChannel(link.GetFrequency())) {
            dfsLinkIsExist = true;
            return true;
        }
        return false;
    });
    CONN_LOGI(CONN_WIFI_DIRECT, "dfsLinkIsExist=%{public}d", dfsLinkIsExist);
    return dfsLinkIsExist;
}

int32_t WifiDirectUtils::GetOsType(const char *networkId)
{
    int32_t osType = OH_OS_TYPE;
    auto ret = LnnGetOsTypeByNetworkId(networkId, &osType);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get os type failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "dfx remote os type %{public}d", osType);
    return osType;
}

int32_t WifiDirectUtils::GetDeviceType(const char *networkId)
{
    int32_t deviceTypeId = 0;
    auto ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_DEV_TYPE_ID, &deviceTypeId);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get remote device type failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "dfx remote device type %{public}d", deviceTypeId);
    return deviceTypeId;
}

int32_t WifiDirectUtils::GetDeviceType()
{
    int32_t deviceTypeId = 0;
    auto ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &deviceTypeId);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get local device type failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "dfx local device type %{public}d", deviceTypeId);
    return deviceTypeId;
}

int32_t WifiDirectUtils::GetRemoteConnSubFeature(const std::string &remoteNetworkId, uint64_t &feature)
{
    uint64_t connSubFeature = 0;
    auto ret = LnnGetRemoteNumU64Info(remoteNetworkId.c_str(), NUM_KEY_CONN_SUB_FEATURE_CAPA, &connSubFeature);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT,
        "remoteNetworkId=%{public}s, get connSubFeature failed", WifiDirectAnonymizeDeviceId(remoteNetworkId).c_str());
    feature = connSubFeature;
    return SOFTBUS_OK;
}

std::string WifiDirectUtils::GetRemoteOsVersion(const char *remoteNetworkId)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(remoteNetworkId != nullptr, "", CONN_WIFI_DIRECT, "remoteNetworkId is null");
    std::string remoteOsVersion;
    NodeInfo *nodeInfo = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    CONN_CHECK_AND_RETURN_RET_LOGE(nodeInfo != nullptr, "", CONN_WIFI_DIRECT, "nodeInfo malloc err");
    auto ret = LnnGetRemoteNodeInfoById(remoteNetworkId, CATEGORY_NETWORK_ID, nodeInfo);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get remote os version failed");
        SoftBusFree(nodeInfo);
        return "";
    }
    remoteOsVersion = nodeInfo->deviceInfo.deviceVersion;
    SoftBusFree(nodeInfo);
    return remoteOsVersion;
}

int32_t WifiDirectUtils::GetRemoteScreenStatus(const char *remoteNetworkId)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(remoteNetworkId != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT,
        "remoteNetworkId is null");
    NodeInfo *nodeInfo = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    CONN_CHECK_AND_RETURN_RET_LOGE(nodeInfo != nullptr, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "nodeInfo malloc err");
    auto ret = LnnGetRemoteNodeInfoByKey(remoteNetworkId, nodeInfo);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get screen status failed");
        SoftBusFree(nodeInfo);
        return ret;
    }
    int screenStatus = nodeInfo->isScreenOn;
    CONN_LOGI(CONN_WIFI_DIRECT, "remote screen status %{public}d", screenStatus);
    SoftBusFree(nodeInfo);
    return screenStatus;
}
} // namespace OHOS::SoftBus
