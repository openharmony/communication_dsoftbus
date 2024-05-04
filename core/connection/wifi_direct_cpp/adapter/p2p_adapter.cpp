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

#include "p2p_adapter.h"

#include "securec.h"
#include <memory>

#include "kits/c/wifi_device.h"
#include "kits/c/wifi_hid2d.h"
#include "kits/c/wifi_p2p.h"

#include "conn_log.h"
#include "softbus_error_code.h"

#include "data/interface_info.h"
#include "data/interface_manager.h"
#include "softbus_adapter_crypto.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
static constexpr char DEFAULT_NET_MASK[] = "255.255.255.0";
static constexpr int CHANNEL_ARRAY_NUM_MAX = 256;

int32_t P2pAdapter::GetChannel5GListIntArray(std::vector<int> &channels)
{
    int array[CHANNEL_ARRAY_NUM_MAX] {};
    auto ret = Hid2dGetChannelListFor5G(array, CHANNEL_ARRAY_NUM_MAX);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "ret=%{public}d", ret);

    int count = 0;
    while (array[count]) {
        channels.push_back(array[count]);
        count++;
    }

    return SOFTBUS_OK;
}

bool P2pAdapter::IsWifiEnable()
{
    return IsWifiActive() == WIFI_STA_ACTIVE;
}

bool P2pAdapter::IsWifiConnected()
{
    return false;
}

bool P2pAdapter::IsWifiP2pEnabled()
{
    enum P2pState state;
    auto ret = GetP2pEnableStatus(&state);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, false, CONN_WIFI_DIRECT, "get p2p enable status failed");

    return state == P2P_STATE_STARTED;
}

std::string P2pAdapter::GetInterfaceCoexistCap()
{
    return "";
}

int32_t P2pAdapter::GetStationFrequency()
{
    WifiLinkedInfo linkedInfo;
    int32_t ret = GetLinkedInfo(&linkedInfo);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "get wifi linked info failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "frequency=%{public}d", linkedInfo.frequency);

    return linkedInfo.frequency;
}

bool P2pAdapter::IsThreeVapConflict()
{
    return false;
}

int32_t P2pAdapter::P2pCreateGroup(const CreateGroupParam &param)
{
    FreqType type = param.isWideBandSupported ? FREQUENCY_160M : FREQUENCY_DEFAULT;
    int32_t ret = Hid2dCreateGroup(param.frequency, type);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT,
        "create group failed, frequency=%{public}d, type=%{public}d, error=%{public}d", param.frequency, type, ret);

    CONN_LOGI(CONN_WIFI_DIRECT, "create group success");
    return SOFTBUS_OK;
}

int32_t P2pAdapter::P2pConnectGroup(const ConnectParam &param)
{
    std::vector<std::string> configs = WifiDirectUtils::SplitString(param.groupConfig, "\n");

    Hid2dConnectConfig connectConfig;
    (void)memset_s(&connectConfig, sizeof(connectConfig), 0, sizeof(connectConfig));

    int32_t ret =
        strcpy_s(connectConfig.ssid, sizeof(connectConfig.ssid), configs[P2P_GROUP_CONFIG_INDEX_SSID].c_str());
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy ssid failed");

    std::vector<uint8_t> bssid = WifiDirectUtils::MacStringToArray(configs[P2P_GROUP_CONFIG_INDEX_BSSID]);
    memcpy_s(connectConfig.bssid, sizeof(connectConfig.bssid), bssid.data(), sizeof(connectConfig.bssid));

    ret = strcpy_s(connectConfig.preSharedKey, sizeof(connectConfig.preSharedKey),
        configs[P2P_GROUP_CONFIG_INDEX_SHARE_KEY].c_str());
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy share key failed");

    connectConfig.frequency = strtol(configs[P2P_GROUP_CONFIG_INDEX_FREQ].c_str(), nullptr, DECIMAL_BASE);

    if (param.isLegacyGo) {
        connectConfig.dhcpMode = CONNECT_AP_NODHCP;
    } else {
        connectConfig.dhcpMode = CONNECT_GO_NODHCP;
        if (configs.size() == P2P_GROUP_CONFIG_INDEX_MAX &&
            !strcmp(configs[P2P_GROUP_CONFIG_INDEX_MODE].c_str(), "1")) {
            connectConfig.dhcpMode = CONNECT_AP_DHCP;
        }
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "dhcpMode=%{public}d", connectConfig.dhcpMode);
    ret = Hid2dConnect(&connectConfig);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "connect group failed");

    CONN_LOGI(CONN_WIFI_DIRECT, "connect group success");
    return SOFTBUS_OK;
}

int32_t P2pAdapter::P2pShareLinkReuse()
{
    WifiErrorCode ret = Hid2dSharedlinkIncrease();
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "failed ret=%{public}d", ret);
    return SOFTBUS_OK;
}

int32_t P2pAdapter::P2pShareLinkRemoveGroup(const DestroyGroupParam &param)
{
    WifiErrorCode ret = Hid2dSharedlinkDecrease();
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "failed ret=%{public}d", ret);
    return SOFTBUS_OK;
}

int32_t P2pAdapter::DestroyGroup(const DestroyGroupParam &param)
{
    LinkInfo::LinkMode role;
    InterfaceManager::GetInstance().ReadInterface(
        InterfaceInfo::InterfaceType::P2P, [&role](const InterfaceInfo &info) {
            role = info.GetRole();
            return SOFTBUS_OK;
        });

    WifiErrorCode ret;
    if (role == LinkInfo::LinkMode::GO) {
        ret = RemoveGroup();
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "remove group failed, ret=%{public}d", ret);
    } else if (role == LinkInfo::LinkMode::GC) {
        ret = Hid2dRemoveGcGroup(param.interface.c_str());
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT,
            "remove gc group of interface failed, interface=%{public}s, ret=%{public}d", param.interface.c_str(), ret);
    } else {
        CONN_LOGW(CONN_WIFI_DIRECT, "unknonwn api role. role=%{public}d", role);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t P2pAdapter::GetStationFrequencyWithFilter()
{
    int32_t frequency = P2pAdapter::GetStationFrequency();
    CONN_CHECK_AND_RETURN_RET_LOGW(frequency > 0, FREQUENCY_INVALID, CONN_WIFI_DIRECT, "invalid frequency");

    if (WifiDirectUtils::Is5GBand(frequency)) {
        std::vector<int> channelArray;
        auto ret = P2pAdapter::GetChannel5GListIntArray(channelArray);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
        int32_t channel = WifiDirectUtils::FrequencyToChannel(frequency);
        if (WifiDirectUtils::IsInChannelList(channel, channelArray)) {
            return frequency;
        }
        return FREQUENCY_INVALID;
    }
    if (WifiDirectUtils::Is2GBand(frequency)) {
        return frequency;
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "get local frequency failed");
    return FREQUENCY_INVALID;
}

int32_t P2pAdapter::GetRecommendChannel(void)
{
    RecommendChannelRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    RecommendChannelResponse response;
    (void)memset_s(&response, sizeof(response), 0, sizeof(response));

    int32_t ret = Hid2dGetRecommendChannel(&request, &response);
    if (ret != WIFI_SUCCESS) {
        return ret;
    }

    if (response.centerFreq) {
        return WifiDirectUtils::FrequencyToChannel(response.centerFreq);
    }

    if (response.centerFreq1) {
        return WifiDirectUtils::FrequencyToChannel(response.centerFreq1);
    }

    return CHANNEL_INVALID;
}

int32_t P2pAdapter::GetSelfWifiConfigInfo(std::string &config)
{
    uint8_t wifiConfig[CFG_DATA_MAX_BYTES] = { 0 };
    int32_t wifiConfigSize = 0;
    int32_t ret = Hid2dGetSelfWifiCfgInfo(TYPE_OF_GET_SELF_CONFIG, (char *)wifiConfig, &wifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "get self wifi config failed, error=%{public}d", ret);

    CONN_LOGI(CONN_WIFI_DIRECT, "wifiConfigSize=%{public}d", wifiConfigSize);
    if (wifiConfigSize == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "empty wifi cfg");
        return SOFTBUS_OK;
    }

    uint8_t encode[CFG_DATA_MAX_BYTES] = { 0 };
    size_t encodeSize = 0;
    ret = SoftBusBase64Encode(encode, sizeof(encode), &encodeSize, wifiConfig, wifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "encode failed, error=%{public}d", ret);

    config = std::string((const char *)encode, encodeSize);
    return SOFTBUS_OK;
}

int32_t P2pAdapter::SetPeerWifiConfigInfo(const std::string &config)
{
    auto peerCfgLen = config.size() + 1;
    auto decodeCfg = new uint8_t[peerCfgLen];
    size_t decodeLen = 0;
    CONN_CHECK_AND_RETURN_RET_LOGE(decodeCfg, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "alloc failed");

    int32_t ret = SoftBusBase64Decode(decodeCfg, peerCfgLen, &decodeLen, (uint8_t *)config.c_str(), config.size());
    if (ret != SOFTBUS_OK) {
        delete[] decodeCfg;
        CONN_LOGI(CONN_WIFI_DIRECT, "decode wifi cfg failed, error=%{public}d", ret);
        return ret;
    }
    ret = Hid2dSetPeerWifiCfgInfo(TYPE_OF_SET_PEER_CONFIG, (char *)decodeCfg, (int32_t)decodeLen);
    delete[] decodeCfg;
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "set wifi cfg failed, error=%{public}d", ret);
    CONN_LOGI(CONN_WIFI_DIRECT, "set success");
    return SOFTBUS_ERR;
}

int32_t P2pAdapter::SetPeerWifiConfigInfoV2(const uint8_t *cfg, size_t size)
{
    (void)cfg;
    (void)size;
    return SOFTBUS_ERR;
}

bool P2pAdapter::IsWideBandSupported()
{
    return Hid2dIsWideBandwidthSupported();
}

int32_t P2pAdapter::GetGroupInfo(WifiDirectP2pGroupInfo &groupInfoOut)
{
    WifiP2pGroupInfo info {};
    auto ret = GetCurrentGroup(&info);
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current group failed, error=%{public}d", ret);
        return ret;
    }
    groupInfoOut.isGroupOwner = info.isP2pGroupOwner;
    groupInfoOut.frequency = info.frequency;
    groupInfoOut.interface = info.interface;
    std::vector<uint8_t> devAddrArray(info.owner.devAddr, info.owner.devAddr + sizeof(info.owner.devAddr));
    groupInfoOut.groupOwner = WifiDirectUtils::MacArrayToString(devAddrArray);
    for (auto i = 0; i < info.clientDevicesSize; i++) {
        std::vector<uint8_t> clientAddrArray(
            info.clientDevices[i].devAddr, info.clientDevices[i].devAddr + sizeof(info.clientDevices[i].devAddr));
        groupInfoOut.clientDevices.push_back(WifiDirectUtils::MacArrayToString(clientAddrArray));
    }
    return SOFTBUS_OK;
}

int32_t P2pAdapter::GetGroupConfig(std::string &groupConfigString)
{
    auto groupInfo = std::make_shared<WifiP2pGroupInfo>();
    auto ret = GetCurrentGroup(groupInfo.get());
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current group failed, error=%{public}d", ret);
        return ret;
    }

    std::string interface = groupInfo->interface;
    std::vector<uint8_t> macAddrArray = WifiDirectUtils::GetInterfaceMacAddr(interface);

    std::string macAddrString = WifiDirectUtils::MacArrayToString(macAddrArray);

    CONN_LOGI(CONN_WIFI_DIRECT, "frequency=%{public}d", groupInfo->frequency);

    groupConfigString = groupInfo->groupName;
    groupConfigString += "\n";
    groupConfigString += macAddrString;
    groupConfigString += "\n";
    groupConfigString += groupInfo->passphrase;
    groupConfigString += "\n";
    groupConfigString += std::to_string(groupInfo->frequency);

    return SOFTBUS_OK;
}

int32_t P2pAdapter::GetIpAddress(std::string &ipString)
{
    auto groupInfo = std::make_shared<WifiP2pGroupInfo>();
    if (groupInfo == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "alloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = GetCurrentGroup(groupInfo.get());
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current group failed, error=%{public}d", ret);
        return ret;
    }

    std::string interface = groupInfo->interface;
    CONN_LOGI(CONN_WIFI_DIRECT, "interfaceName=%{public}s", interface.c_str());
    ret = WifiDirectUtils::GetInterfaceIpString(interface, ipString);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get interfaceIp string failed, error=%d", ret);
    return SOFTBUS_OK;
}

std::string P2pAdapter::GetMacAddress()
{
    std::vector<uint8_t> macArray = WifiDirectUtils::GetInterfaceMacAddr("p2p0");
    std::string macString = WifiDirectUtils::MacArrayToString(macArray);
    if (macString.empty()) {
        macArray = WifiDirectUtils::GetInterfaceMacAddr("wlan0");
        macString = WifiDirectUtils::MacArrayToString(macArray);
        CONN_LOGI(CONN_WIFI_DIRECT, "wlan0");
        return macString;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "p2p0");
    return macString;
}

int32_t P2pAdapter::GetDynamicMacAddress(std::string &macString)
{
    WifiP2pGroupInfo groupInfo;
    int32_t ret = GetCurrentGroup(&groupInfo);
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current group failed, error=%{public}d", ret);
        return ret;
    }
    std::vector<uint8_t> macArray = WifiDirectUtils::GetInterfaceMacAddr(groupInfo.interface);
    macString = WifiDirectUtils::MacArrayToString(macArray);
    return SOFTBUS_OK;
}

int32_t P2pAdapter::RequestGcIp(const std::string &macString, std::string &ipString)
{
    std::vector<uint8_t> macArray = WifiDirectUtils::MacStringToArray(macString);

    uint32_t ipArray[IPV4_ADDR_ARRAY_LEN];
    int ret = Hid2dRequestGcIp(macArray.data(), ipArray);
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "request Gc Ip failed, error=%{public}d", ret);
        return ret;
    }

    std::stringstream ss;
    ss << ipArray[0] << ".";
    ss << ipArray[1] << ".";
    ss << ipArray[2] << "."; // 2 is ipArray index.
    ss << ipArray[3];        // 3 is ipArray index.

    ipString = ss.str();
    CONN_LOGI(CONN_WIFI_DIRECT, "gcIp=%{public}s", WifiDirectAnonymizeIp(ipString).c_str());
    return SOFTBUS_OK;
}

int32_t P2pAdapter::P2pConfigGcIp(const std::string &interface, const std::string &ip)
{
    IpAddrInfo addrInfo;

    int32_t ret = WifiDirectUtils::IpStringToIntArray(ip.c_str(), addrInfo.ip, IPV4_ARRAY_LEN);

    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "convert ip to int array failed");
    ret = WifiDirectUtils::IpStringToIntArray(ip.c_str(), addrInfo.gateway, IPV4_ARRAY_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "convert gateway to int array failed");
    ret = WifiDirectUtils::IpStringToIntArray(DEFAULT_NET_MASK, addrInfo.netmask, IPV4_ARRAY_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "convert gateway to int array failed");

    ret = Hid2dConfigIPAddr(interface.c_str(), &addrInfo);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "hid2d config ip failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "success");
    return SOFTBUS_OK;
}
} // namespace OHOS::SoftBus