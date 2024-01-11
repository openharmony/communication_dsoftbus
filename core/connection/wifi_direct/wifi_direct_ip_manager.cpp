/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>
#include <map>
#include <set>
#include "conn_log.h"
#include "softbus_error_code.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_network_utils.h"
#include "utils/wifi_direct_anonymous.h"
#include "adapter/single/net_manager_adapter.h"

static constexpr int32_t HML_IP_NET_START = 1;
static constexpr int32_t HML_IP_NET_END = 255;
static constexpr const char *HML_IP_SOURCE_SUFFIX = ".2";
static constexpr const char *HML_IP_SINK_SUFFIX = ".1";

static std::map<std::string, std::string> g_remoteArps;
static std::set<std::pair<std::string, int32_t>> g_localIps;

/* private method forward declare */
static std::vector<std::string> GetHmlAllUsedIp(std::initializer_list<std::vector<WifiDirectIpv4Info>*> all);
static std::string ApplySubNet(struct WifiDirectIpv4Info *remoteArray, size_t remoteArraySize);

/* public interface */
static int32_t ApplyIp(struct WifiDirectIpv4Info *remoteArray, size_t remoteArraySize,
                       struct WifiDirectIpv4Info *source, struct WifiDirectIpv4Info *sink)
{
    std::string subNet = ApplySubNet(remoteArray, remoteArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGE(!subNet.empty(), SOFTBUS_ERR, CONN_WIFI_DIRECT, "apply subnet failed");

    std::string sourceIp = subNet + HML_IP_SOURCE_SUFFIX;
    std::string sinkIp = subNet + HML_IP_SINK_SUFFIX;
    int32_t ret = WifiDirectIpStringToIpv4(sourceIp.c_str(), source);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "source ip to ipv4 failed");
    ret = WifiDirectIpStringToIpv4(sinkIp.c_str(), sink);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "sink ip to ipv4 failed");

    return SOFTBUS_OK;
}

static int32_t ConfigIp(const char *interface, struct WifiDirectIpv4Info *local, struct WifiDirectIpv4Info *remote,
                        const char *remoteMac)
{
    char localIp[IP_ADDR_STR_LEN] = {0};
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = WifiDirectIpv4ToString(local, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "convert local ip failed");
    ret = WifiDirectIpv4ToString(remote, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "convert remote ip failed");
    CONN_LOGD(CONN_WIFI_DIRECT,
        "config ip. interface=%{public}s, localIp=%{public}s, remoteIp=%{public}s, remoteMac=%{public}s",
        interface, WifiDirectAnonymizeIp(localIp), WifiDirectAnonymizeIp(remoteIp),
        WifiDirectAnonymizeMac(remoteMac));

    ret = AddInterfaceAddress(interface, localIp, local->prefixLength);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "add ip failed");
    g_localIps.insert({localIp, local->prefixLength});

    ret = AddStaticArp(interface, remoteIp, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "add static arp failed");
    g_remoteArps.insert({remoteIp, remoteMac});
    return SOFTBUS_OK;
}

static void ReleaseIp(const char *interface, struct WifiDirectIpv4Info *local, struct WifiDirectIpv4Info *remote,
                      const char *remoteMac)
{
    char localIp[IP_ADDR_STR_LEN] = {0};
    char remoteIp[IP_ADDR_STR_LEN] = {0};
    int32_t ret = WifiDirectIpv4ToString(local, localIp, sizeof(localIp));
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "convert local ip failed");
    ret = WifiDirectIpv4ToString(remote, remoteIp, sizeof(remoteIp));
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "convert remote ip failed");

    CONN_LOGD(CONN_WIFI_DIRECT,
        "release ip. interface=%{public}s, localIp=%{public}s, localPrefixLength=%{public}hhu, "
        "remoteIp=%{public}s, remoteMac=%{public}s",
        interface, WifiDirectAnonymizeIp(localIp), local->prefixLength,
        WifiDirectAnonymizeIp(remoteIp), WifiDirectAnonymizeMac(remoteMac));

    ret = DeleteInterfaceAddress(interface, localIp, local->prefixLength);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "delete ip failed");
    g_localIps.erase({localIp, local->prefixLength});

    ret = DeleteStaticArp(interface, remoteIp, remoteMac);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "delete static arp failed");
    g_remoteArps.erase(remoteIp);
}

static void ClearAllIps(const char *interface)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "interface=%{public}s", interface);
    for (const auto &local : g_localIps) {
        const auto *localIp = local.first.c_str();
        if (DeleteInterfaceAddress(interface, localIp, local.second) != SOFTBUS_OK) {
            CONN_LOGE(CONN_WIFI_DIRECT, "delete failed. ip=%{public}s", WifiDirectAnonymizeIp(localIp));
        }
    }

    for (const auto &remote : g_remoteArps) {
        const auto *remoteIp = remote.first.c_str();
        const auto *remoteMac = remote.second.c_str();
        if (DeleteStaticArp(interface, remoteIp, remoteMac) != SOFTBUS_OK) {
            CONN_LOGE(CONN_WIFI_DIRECT,
                "delete arp failed. "
                "WifiDirectAnonymizeIp.remoteIp=%{public}s, WifiDirectAnonymizeIp.remoteMac=%{public}s",
                WifiDirectAnonymizeIp(remoteIp), WifiDirectAnonymizeIp(remoteMac));
        }
    }
}

/* private method implement */
static std::vector<std::string> GetHmlAllUsedIp(std::initializer_list<std::vector<WifiDirectIpv4Info>*> all)
{
    std::vector<std::string> hmlAll;
    for (const auto array : all) {
        for (const auto &entry : *array) {
            char ip[IP_ADDR_STR_LEN] = {0};
            int32_t ret = WifiDirectIpv4ToString(&entry, ip, sizeof(ip));
            if (ret != SOFTBUS_OK) {
                CONN_LOGE(CONN_WIFI_DIRECT, "convert failed");
                continue;
            }

            std::string ipStr = ip;
            if (ipStr.find(HML_IP_NET_PREFIX) != std::string::npos) {
                hmlAll.push_back(ipStr);
                CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectAnonymizeIp=%{public}s", WifiDirectAnonymizeIp(ip));
            }
        }
    }

    return hmlAll;
}

static std::string ApplySubNet(struct WifiDirectIpv4Info *remoteArray, size_t remoteArraySize)
{
    size_t localIpv4ArraySize = INTERFACE_NUM_MAX;
    struct WifiDirectIpv4Info localIpv4Array[INTERFACE_NUM_MAX];
    int32_t ret = GetWifiDirectNetWorkUtils()->getLocalIpv4InfoArray(localIpv4Array, &localIpv4ArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, "", CONN_WIFI_DIRECT, "get local ipv4 array failed");

    std::vector<WifiDirectIpv4Info> localIpv4Infos(localIpv4Array, localIpv4Array + localIpv4ArraySize);
    std::vector<WifiDirectIpv4Info> remoteIpv4Infos(remoteArray, remoteArray + remoteArraySize);
    std::vector<std::string> all = GetHmlAllUsedIp({&localIpv4Infos, &remoteIpv4Infos});

    std::string subNet;
    for (int32_t i = HML_IP_NET_START; i < HML_IP_NET_END; i++) {
        bool found = true;
        subNet = HML_IP_NET_PREFIX + std::to_string(i);
        for (const auto &usedIp : all) {
            if (usedIp.find(subNet) != std::string::npos) {
                found = false;
                break;
            }
        }
        if (found) {
            CONN_LOGI(CONN_WIFI_DIRECT, "subNet=%{public}s", subNet.c_str());
            return subNet;
        }
    }

    return "";
}

static struct WifiDirectIpManager g_manager = {
    .applyIp = ApplyIp,
    .configIp = ConfigIp,
    .releaseIp = ReleaseIp,
    .cleanAllIps = ClearAllIps,
};

struct WifiDirectIpManager* GetWifiDirectIpManager(void)
{
    return &g_manager;
}