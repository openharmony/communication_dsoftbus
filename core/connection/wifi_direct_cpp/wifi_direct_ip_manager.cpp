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
#include <arpa/inet.h>
#include "securec.h"
#include "conn_log.h"
#include "net_conn_client.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
static constexpr int32_t U_L_BIT = 0x2;
static constexpr uint8_t INSERT_BYTE_0 = 0xff;
static constexpr uint8_t INSERT_BYTE_1 = 0xfe;
static constexpr int INSERT_POS = 3;
static constexpr int IPV6_PREFIX = 64;

static constexpr int32_t HML_IP_NET_END = 256;
static constexpr char HML_IP_PREFIX[] = "172.30.";
static constexpr char HML_IP_SOURCE_SUFFIX[] = ".2";
static constexpr char HML_IP_SINK_SUFFIX[] = ".1";

void WifiDirectIpManager::Init()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
}

std::string WifiDirectIpManager::ApplyIpv6(const std::string &mac)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(!mac.empty(), "", CONN_WIFI_DIRECT, "mac is null");
    auto array = WifiDirectUtils::MacStringToArray(mac);
    if ((array[0] & U_L_BIT) == 0) {
        array[0] |= U_L_BIT;
    } else {
        array[0] &= ~U_L_BIT;
    }
    array.insert(array.begin() + INSERT_POS, { INSERT_BYTE_0, INSERT_BYTE_1 });
    char ip[IP_STR_MAX_LEN] {};
    auto ret = sprintf_s(ip, sizeof(ip), "fe80::%02x%02x:%02x%02x:%02x%02x:%02x%02x%%chba0",
                         array[0], array[1], array[2], array[3], array[4], array[5], array[6], array[7]);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret > 0, "", CONN_WIFI_DIRECT, "format failed");

    SoftBusSockAddrIn6 addrIn6 {};
    if (Ipv6AddrToAddrIn(&addrIn6, ip, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "to addrIn6 failed");
        return "";
    }
    char result[IP_STR_MAX_LEN] {};
    if (Ipv6AddrInToAddr(&addrIn6, result, sizeof(result)) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "to ip string failed");
        return "";
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "scopeId=%{public}u", addrIn6.sin6ScopeId);
    std::string finalResult = result;
    if (addrIn6.sin6ScopeId == 0) {
        finalResult += "%chba0";
    }
    return finalResult;
}

int32_t WifiDirectIpManager::ApplyIpv4(
    const std::vector<Ipv4Info> &localArray, const std::vector<Ipv4Info> &remoteArray, Ipv4Info &source, Ipv4Info &sink)
{
    std::string subNet = ApplySubNet(localArray, remoteArray);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        !subNet.empty(), SOFTBUS_CONN_APPLY_SUBNET_FAIL, CONN_WIFI_DIRECT, "apply subnet failed");

    std::string sourceIp = subNet + HML_IP_SOURCE_SUFFIX;
    std::string sinkIp = subNet + HML_IP_SINK_SUFFIX;
    int32_t ret = source.FromIpString(sourceIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "source ip to ipv4 failed");
    ret = sink.FromIpString(sinkIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "sink ip to ipv4 failed");

    return SOFTBUS_OK;
}

std::string WifiDirectIpManager::ApplySubNet(
    const std::vector<Ipv4Info> &localArray, const std::vector<Ipv4Info> &remoteArray)
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

int32_t WifiDirectIpManager::ConfigIpv6(const std::string &interface, const std::string &ip)
{
    auto ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().AddInterfaceAddress(interface, ip, IPV6_PREFIX);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == 0, SOFTBUS_CONN_CONFIG_IPV6_CONFIG_IP_FAILED, CONN_WIFI_DIRECT, "add ip failed");
    return SOFTBUS_OK;
}

int32_t WifiDirectIpManager::ConfigIpv4(
    const std::string &interface, const Ipv4Info &local, const Ipv4Info &remote, const std::string &remoteMac)
{
    std::string localIpStr = local.ToIpString();
    CONN_CHECK_AND_RETURN_RET_LOGE(
        !localIpStr.empty(), SOFTBUS_CONN_CONVERT_LOCAL_IP_FAIL, CONN_WIFI_DIRECT, "convert local ip failed");
    std::string remoteIpStr = remote.ToIpString();
    CONN_CHECK_AND_RETURN_RET_LOGE(
        !remoteIpStr.empty(), SOFTBUS_CONN_CONVERT_REMOTE_IP_FAIL, CONN_WIFI_DIRECT, "convert remote ip failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "localIp=%{public}s, remoteIp=%{public}s, remoteMac=%{public}s",
        WifiDirectAnonymizeIp(localIpStr).c_str(), WifiDirectAnonymizeIp(remoteIpStr).c_str(),
        WifiDirectAnonymizeMac(remoteMac).c_str());

    int32_t ret = AddInterfaceAddress(interface, localIpStr, local.GetPrefixLength());
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "add ip failed");

    ret = AddStaticArp(interface, remoteIpStr, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "add static arp failed");
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

    if (DeleteStaticArp(interface, remoteIpStr, remoteMac) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "delete arp failed. remoteIp=%{public}s, remoteMac=%{public}s",
            WifiDirectAnonymizeIp(remoteIpStr).c_str(), WifiDirectAnonymizeMac(remoteMac).c_str());
    }
}

void WifiDirectIpManager::ClearAllIpv4()
{
    auto localIpv4Array = WifiDirectUtils::GetLocalIpv4Infos();
    for (const auto &ipv4 : localIpv4Array) {
        std::string ipStr = ipv4.ToIpString();
        if (DeleteInterfaceAddress(IF_NAME_HML, ipStr, ipv4.GetPrefixLength()) != SOFTBUS_OK) {
            CONN_LOGE(CONN_WIFI_DIRECT, "delete ip failed. ip=%{public}s", WifiDirectAnonymizeIp(ipStr).c_str());
        }
    }
}

int32_t WifiDirectIpManager::AddInterfaceAddress(
    const std::string &interface, const std::string &ipString, int32_t prefixLength)
{
    std::string gateWay;
    int32_t ret = GetNetworkGateWay(ipString, gateWay);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get gate way failed");
    std::string destination;
    ret = GetNetworkDestination(ipString, destination);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get destination failed");

    ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().AddInterfaceAddress(interface, ipString, prefixLength);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == NetManagerStandard::NETMANAGER_SUCCESS, ret, CONN_WIFI_DIRECT, "add ip failed ret=%{public}d", ret);
    ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().AddNetworkRoute(
        LOCAL_NETWORK_ID, interface, destination, gateWay);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == NetManagerStandard::NETMANAGER_SUCCESS, ret, CONN_WIFI_DIRECT, "add route failed ret=%{public}d", ret);
    return SOFTBUS_OK;
}

int32_t WifiDirectIpManager::DeleteInterfaceAddress(
    const std::string &interface, const std::string &ipString, int32_t prefixLength)
{
    std::string gateWay;
    int32_t ret = GetNetworkGateWay(ipString, gateWay);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, ret, CONN_WIFI_DIRECT, "get gate way failed");
    std::string destination;
    ret = GetNetworkDestination(ipString, destination);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == 0, ret, CONN_WIFI_DIRECT, "get destination failed");
    ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().RemoveNetworkRoute(
        LOCAL_NETWORK_ID, interface, destination, gateWay);
    if (ret != NetManagerStandard::NETMANAGER_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "remove route failed ret=%{public}d", ret);
    }
    ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().DelInterfaceAddress(interface, ipString, prefixLength);
    if (ret != NetManagerStandard::NETMANAGER_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "delete ip failed ret=%{public}d", ret);
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
    CONN_CHECK_AND_RETURN_RET_LOGE(
        pos != std::string::npos, SOFTBUS_CONN_FIND_DOT_FAIL, CONN_WIFI_DIRECT, "can't find dot");
    gateWay = ipString.substr(0, pos) + ".1";
    CONN_LOGI(CONN_WIFI_DIRECT, "gateWay=%{public}s", WifiDirectAnonymizeIp(gateWay).c_str());
    return SOFTBUS_OK;
}

int32_t WifiDirectIpManager::GetNetworkDestination(const std::string &ipString, std::string &destination)
{
    auto pos = ipString.find_last_of('.');
    CONN_CHECK_AND_RETURN_RET_LOGE(
        pos != std::string::npos, SOFTBUS_CONN_FIND_DOT_FAIL, CONN_WIFI_DIRECT, "can't find dot");
    destination = ipString.substr(0, pos) + ".0/24";
    CONN_LOGI(CONN_WIFI_DIRECT, "destination=%{public}s", WifiDirectAnonymizeIp(destination).c_str());
    return SOFTBUS_OK;
}
} // namespace OHOS::SoftBus
