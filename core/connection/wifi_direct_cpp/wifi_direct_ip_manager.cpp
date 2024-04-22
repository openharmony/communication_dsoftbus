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
#include "wifi_direct_ip_manager.h"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "adapter/net_manager_adapter.h"
#include "conn_log.h"
#include "net_conn_client.h"
#include "softbus_error_code.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
static constexpr int32_t HML_IP_NET_END = 255;
static constexpr int32_t HEXADECIMAL = 16;
static constexpr int32_t U_L_BIT = 7;
static constexpr int32_t GROUP_LENGTH = 4;
static constexpr int32_t EIGHT = 8;

static constexpr char HML_IP_PREFIX[] = "172.30.";
static constexpr char HML_IP_SOURCE_SUFFIX[] = ".2";
static constexpr char HML_IP_SINK_SUFFIX[] = ".1";
static constexpr char BITS_TO_BE_INSERTED[] = ":FF:FE";

std::string WifiDirectIpManager::ApplyIpv6(const std::string &mac)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(!mac.empty(), "", CONN_WIFI_DIRECT, "mac is null");
    std::bitset<EUI_64_IDENTIFIER_LEN> eui64Bits = GetEUI64Identifier(mac);
    std::string eui64String = BitsetToIPv6(eui64Bits);
    std::string ipv6String = "FE80:";
    for (int i = 0; i < GROUP_LENGTH; i++) {
        ipv6String += ":";
        ipv6String += eui64String.substr(i * GROUP_LENGTH, GROUP_LENGTH);
    }
    // FE80:0200:02FF:FE0D:4891
    ipv6String += "%chba0";
    return ipv6String;
}

int32_t WifiDirectIpManager::ApplyIpv4(const std::vector<Ipv4Info> &localArray,
                                       const std::vector<Ipv4Info> &remoteArray, Ipv4Info &source, Ipv4Info &sink)
{
    std::string subNet = ApplySubNet(localArray, remoteArray);
    CONN_CHECK_AND_RETURN_RET_LOGE(!subNet.empty(), SOFTBUS_ERR, CONN_WIFI_DIRECT, "apply subnet failed");

    std::string sourceIp = subNet + HML_IP_SOURCE_SUFFIX;
    std::string sinkIp = subNet + HML_IP_SINK_SUFFIX;
    int32_t ret = source.FromIpString(sourceIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "source ip to ipv4 failed");
    ret = sink.FromIpString(sinkIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "sink ip to ipv4 failed");

    return SOFTBUS_OK;
}

std::string WifiDirectIpManager::ApplySubNet(const std::vector<Ipv4Info> &localArray,
                                             const std::vector<Ipv4Info> &remoteArray)
{
    std::array<bool, HML_IP_NET_END> bookMark {};
    bookMark[0] = true;
    std::string subNet;
    for (const auto &ipv4 : localArray) {
        bookMark[ipv4.GetSubNet()] = true;
    }
    for (const auto &ipv4 : remoteArray) {
        bookMark[ipv4.GetSubNet()] = true;
    }
    for (uint32_t i = 0; i < bookMark.size(); i++) {
        if (!bookMark[i]) {
            subNet = HML_IP_PREFIX + std::to_string(i);
            return subNet;
        }
    }
    return "";
}

std::bitset<EUI_64_IDENTIFIER_LEN> WifiDirectIpManager::GetEUI64Identifier(const std::string &mac)
{
    std::bitset<EUI_64_IDENTIFIER_LEN> eui64Bits;

    std::string macTMp(mac);
    macTMp.insert(mac.length() / 2, BITS_TO_BE_INSERTED);
    std::stringstream ss(macTMp);
    std::string segment;
    while (std::getline(ss, segment, ':')) {
        eui64Bits <<= EIGHT;
        eui64Bits |= std::bitset<EUI_64_IDENTIFIER_LEN>(std::stoi(segment, nullptr, HEXADECIMAL));
    }
    eui64Bits.flip(EUI_64_IDENTIFIER_LEN - U_L_BIT);
    return eui64Bits;
}

std::string WifiDirectIpManager::BitsetToIPv6(const std::bitset<EUI_64_IDENTIFIER_LEN> &eui64Bits)
{
    std::string eui64String;
    std::string binary = eui64Bits.to_string();
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(HEXADECIMAL) << std::uppercase << eui64Bits.to_ulong();
    eui64String = ss.str();
    return eui64String;
}

int32_t WifiDirectIpManager::ConfigIpv4(
    const std::string &interface, const Ipv4Info &local, const Ipv4Info &remote, const std::string &remoteMac)

{
    std::string localIpStr = local.ToIpString();
    CONN_CHECK_AND_RETURN_RET_LOGE(!localIpStr.empty(), SOFTBUS_ERR, CONN_WIFI_DIRECT, "convert local ip failed");
    std::string remoteIpStr = remote.ToIpString();
    CONN_CHECK_AND_RETURN_RET_LOGE(!remoteIpStr.empty(), SOFTBUS_ERR, CONN_WIFI_DIRECT, "convert remote ip failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "localIp=%{public}s, remoteIp=%{public}s, remoteMac=%{public}s",
              localIpStr.c_str(), remoteIpStr.c_str(), WifiDirectAnonymizeMac(remoteMac).c_str());

    int32_t ret = AddInterfaceAddress(interface, localIpStr, local.GetPrefixLength());
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "add ip failed");
    ips_.insert(localIpStr);

    ret = AddStaticArp(interface, remoteIpStr, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "add static arp failed");
    arps_[remoteIpStr] = remoteMac;
    return SOFTBUS_OK;
}

void WifiDirectIpManager::ReleaseIpv4(
    const std::string &interface, const Ipv4Info &local, const Ipv4Info &remote, const std::string &remoteMac)
{
    std::string localIpStr = local.ToIpString();
    CONN_CHECK_AND_RETURN_LOGE(!localIpStr.empty(), CONN_WIFI_DIRECT, "convert local ip failed");
    std::string remoteIpStr = remote.ToIpString();
    CONN_CHECK_AND_RETURN_LOGE(!remoteIpStr.empty(), CONN_WIFI_DIRECT, "convert remote ip failed");

    CONN_LOGI(CONN_WIFI_DIRECT, "localIp=%{public}s, remoteIp=%{public}s, remoteMac=%{public}s",
              WifiDirectAnonymizeIp(localIpStr).c_str(), WifiDirectAnonymizeIp(remoteIpStr).c_str(),
              WifiDirectAnonymizeMac(remoteMac).c_str());

    if (DeleteInterfaceAddress(interface, localIpStr, local.GetPrefixLength()) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "delete ip failed. ip=%{public}s", WifiDirectAnonymizeIp(localIpStr).c_str());
    }
    ips_.erase(localIpStr);

    if (DeleteStaticArp(interface, remoteIpStr, remoteMac) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "delete arp failed. remoteIp=%{public}s, remoteMac=%{public}s",
            WifiDirectAnonymizeIp(remoteIpStr).c_str(), WifiDirectAnonymizeMac(remoteMac).c_str());
    }
    arps_.erase(remoteIpStr);
}

int32_t WifiDirectIpManager::AddInterfaceAddress(
    const std::string &interface, const std::string &ipString, int32_t prefixLength)
{
    std::string gateWay;
    int32_t ret = GetNetworkGateWay(ipString, gateWay);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get gate way failed");
    std::string destination;
    ret = GetNetworkDestination(ipString, destination);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get destination failed");

    ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().AddInterfaceAddress(interface, ipString, prefixLength);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "add ip failed");
    ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().AddNetworkRoute(
        LOCAL_NETWORK_ID, interface, destination, gateWay);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "add route failed");
    return SOFTBUS_OK;
}
int32_t WifiDirectIpManager::DeleteInterfaceAddress(
    const std::string &interface, const std::string &ipString, int32_t prefixLength)
{
    std::string gateWay;
    int32_t ret = GetNetworkGateWay(ipString, gateWay);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get gate way failed");
    std::string destination;
    ret = GetNetworkDestination(ipString, destination);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get destination failed");
    ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().RemoveNetworkRoute(
        LOCAL_NETWORK_ID, interface, destination, gateWay);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "remove route failed");
    }
    ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().DelInterfaceAddress(interface, ipString, prefixLength);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "delete ip failed");
    }
    return SOFTBUS_OK;
}
int32_t WifiDirectIpManager::AddStaticArp(
    const std::string &interface, const std::string &ipString, const std::string &macString)
{
    return OHOS::NetManagerStandard::NetConnClient::GetInstance().AddStaticArp(ipString, macString, interface);
}
int32_t WifiDirectIpManager::DeleteStaticArp(
    const std::string &interface, const std::string &ipString, const std::string &macString)
{
    return OHOS::NetManagerStandard::NetConnClient::GetInstance().DelStaticArp(ipString, macString, interface);
}

int32_t WifiDirectIpManager::GetNetworkGateWay(const std::string &ipString, std::string &gateWay)
{
    auto pos = ipString.find_last_of('.');
    CONN_CHECK_AND_RETURN_RET_LOGE(pos != std::string::npos, SOFTBUS_ERR, CONN_WIFI_DIRECT, "can't find dot");
    gateWay = ipString.substr(0, pos) + ".1";
    CONN_LOGI(CONN_WIFI_DIRECT, "gateWay=%{public}s", WifiDirectAnonymizeIp(gateWay).c_str());
    return SOFTBUS_OK;
}
int32_t WifiDirectIpManager::GetNetworkDestination(const std::string &ipString, std::string &destination)
{
    auto pos = ipString.find_last_of('.');
    CONN_CHECK_AND_RETURN_RET_LOGE(pos != std::string::npos, SOFTBUS_ERR, CONN_WIFI_DIRECT, "can't find dot");
    destination = ipString.substr(0, pos) + ".0/24";
    CONN_LOGI(CONN_WIFI_DIRECT, "destination=%{public}s", WifiDirectAnonymizeIp(destination).c_str());
    return SOFTBUS_OK;
}

void WifiDirectIpManager::ClearAllIpv4(const std::string &interface)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "interface=%{public}s", interface.c_str());
    for (const std::string &ipString : ips_) {
        Ipv4Info localIp(ipString);
        if (DeleteInterfaceAddress(interface, ipString, localIp.GetPrefixLength()) != SOFTBUS_OK) {
            CONN_LOGE(CONN_WIFI_DIRECT, "delete ip failed. ip=%{public}s", WifiDirectAnonymizeIp(ipString).c_str());
        }
        ips_.erase(ipString);
    }

    for (const auto &remote : arps_) {
        const auto &remoteIp = remote.first;
        const auto &remoteMac = remote.second;
        if (DeleteStaticArp(interface, remoteIp, remoteMac) != SOFTBUS_OK) {
            CONN_LOGE(CONN_WIFI_DIRECT, "delete arp failed. remoteIp=%{public}s, remoteMac=%{public}s",
                WifiDirectAnonymizeIp(remoteIp).c_str(), WifiDirectAnonymizeIp(remoteMac).c_str());
        }
        arps_.erase(remoteIp);
    }
}
} // namespace OHOS::SoftBus
