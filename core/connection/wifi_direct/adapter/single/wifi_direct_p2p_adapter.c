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

#include "wifi_direct_p2p_adapter.h"
#include "securec.h"
#include "conn_log.h"
#include "wifi_device.h"
#include "wifi_p2p.h"
#include "wifi_hid2d.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_crypto.h"
#include "wifi_direct_defines.h"
#include "utils/wifi_direct_network_utils.h"
#include "data/resource_manager.h"

#define DEFAULT_NET_MASK "255.255.255.0"

static bool IsWifiP2pEnabled(void)
{
    enum P2pState state;
    int32_t ret = GetP2pEnableStatus(&state);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, false, CONN_WIFI_DIRECT, "get p2p enable status failed");

    return state == P2P_STATE_STARTED;
}

bool IsWifiConnected(void)
{
    return false;
}

bool IsWifiApEnabled(void)
{
    return false;
}

static bool IsWideBandSupported(void)
{
    return Hid2dIsWideBandwidthSupported();
}

static int32_t GetChannel5GListIntArray(int32_t *array, size_t *size)
{
    int32_t ret = Hid2dGetChannelListFor5G(array, (int32_t) *size);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT,
        "hid2d get channels failed ret=%{public}d", ret);

    int32_t count = 0;
    while (array[count]) {
        count++;
    }

    *size = count;
    return SOFTBUS_OK;
}

static int32_t GetStationFrequency(void)
{
    WifiLinkedInfo linkedInfo;
    int32_t ret = GetLinkedInfo(&linkedInfo);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, FREQUENCY_INVALID, CONN_WIFI_DIRECT,
        "get wifi linked info failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "frequency=%{public}d", linkedInfo.frequency);

    return linkedInfo.frequency;
}

static int32_t GetStationFrequencyWithFilter(void)
{
    int32_t ret;
    int32_t frequency = GetWifiDirectP2pAdapter()->getStationFrequency();
    CONN_CHECK_AND_RETURN_RET_LOGW(frequency > 0, FREQUENCY_INVALID, CONN_WIFI_DIRECT, "invalid frequency");

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    if (netWorkUtils->is5GBand(frequency)) {
        int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
        size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
        ret = GetChannel5GListIntArray(channelArray, &channelArraySize);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT,
            "get channel list failed. ret=%{public}d", ret);

        int32_t channel = netWorkUtils->frequencyToChannel(frequency);
        if (netWorkUtils->isInChannelList(channel, channelArray, channelArraySize)) {
            return frequency;
        }
        return FREQUENCY_INVALID;
    }
    if (netWorkUtils->is2GBand(frequency)) {
        return frequency;
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "get local frequency failed");
    return FREQUENCY_INVALID;
}

static int32_t GetRecommendChannel(void)
{
    RecommendChannelRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    RecommendChannelResponse response;
    (void)memset_s(&response, sizeof(response), 0, sizeof(response));

    int32_t ret = Hid2dGetRecommendChannel(&request, &response);
    if (ret != WIFI_SUCCESS) {
        return CHANNEL_INVALID;
    }

    if (response.centerFreq) {
        return GetWifiDirectNetWorkUtils()->frequencyToChannel(response.centerFreq);
    }

    if (response.centerFreq1) {
        return GetWifiDirectNetWorkUtils()->frequencyToChannel(response.centerFreq1);
    }

    return CHANNEL_INVALID;
}

static int32_t GetSelfWifiConfigInfo(uint8_t *config, size_t *configSize)
{
    uint8_t wifiConfig[CFG_DATA_MAX_BYTES] = {0};
    int32_t wifiConfigSize = 0;
    int32_t ret = Hid2dGetSelfWifiCfgInfo(TYPE_OF_GET_SELF_CONFIG, (char *)wifiConfig, &wifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT, "get self wifi config failed");

    CONN_LOGI(CONN_WIFI_DIRECT, "wifiConfigSize=%{public}d", wifiConfigSize);
    if (wifiConfigSize == 0) {
        *configSize = 0;
        CONN_LOGI(CONN_WIFI_DIRECT, "empty wifi cfg");
        return SOFTBUS_OK;
    }

    size_t cipherSize = 0;
    ret = SoftBusBase64Encode(config, *configSize, &cipherSize, wifiConfig, wifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "encode failed");

    *configSize = cipherSize;
    return SOFTBUS_OK;
}

static int32_t SetPeerWifiConfigInfo(const char *config)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(config, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "cfg is null");
    size_t configSize = strlen(config);
    size_t peerCfgLen = configSize + 1;
    uint8_t *peerCfg = (uint8_t *)SoftBusCalloc(peerCfgLen);
    size_t decLen;
    CONN_CHECK_AND_RETURN_RET_LOGW(peerCfg, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "malloc failed");

    int32_t ret = SoftBusBase64Decode(peerCfg, peerCfgLen, &decLen, (uint8_t *)config, configSize);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(peerCfg);
        CONN_LOGE(CONN_WIFI_DIRECT, "decode wifi cfg failed");
        return SOFTBUS_ERR;
    }

    ret = Hid2dSetPeerWifiCfgInfo(TYPE_OF_SET_PEER_CONFIG, (char *)peerCfg, (int32_t)decLen);
    SoftBusFree(peerCfg);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT, "set wifi cfg failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "set success");
    return SOFTBUS_OK;
}

static int32_t SetPeerWifiConfigInfoV2(const uint8_t *cfg, size_t size)
{
    (void)cfg;
    (void)size;
    return SOFTBUS_ERR;
}

static int32_t GetGroupConfig(char *groupConfigString, size_t *groupConfigStringSize)
{
    WifiP2pGroupInfo *groupInfo = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(*groupInfo));
    CONN_CHECK_AND_RETURN_RET_LOGW(groupInfo, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "alloc group info failed");

    int32_t ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current group failed");
        SoftBusFree(groupInfo);
        groupInfo = NULL;
        return SOFTBUS_ERR;
    }

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    uint8_t macAddrArray[MAC_ADDR_ARRAY_SIZE];
    size_t macAddrArraySize = MAC_ADDR_ARRAY_SIZE;
    ret = netWorkUtils->getInterfaceMacAddr(groupInfo->interface, macAddrArray, &macAddrArraySize);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get interface mac addr failed");
        SoftBusFree(groupInfo);
        return ret;
    }

    char macAddrString[MAC_ADDR_STR_LEN];
    ret = netWorkUtils->macArrayToString(macAddrArray, macAddrArraySize, macAddrString, sizeof(macAddrString));
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "convert mac addr to string failed");
        SoftBusFree(groupInfo);
        groupInfo = NULL;
        return ret;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "groupName=%{public}s, frequency=%{public}d", groupInfo->groupName,
        groupInfo->frequency);

    ret = sprintf_s(groupConfigString, *groupConfigStringSize, "%s\n%s\n%s\n%d",
                    groupInfo->groupName, macAddrString, groupInfo->passphrase, groupInfo->frequency);
    SoftBusFree(groupInfo);
    groupInfo = NULL;
    if (ret < 0) {
        CONN_LOGE(CONN_WIFI_DIRECT, "convert mac addr to string failed");
        return SOFTBUS_ERR;
    }

    *groupConfigStringSize = ret;
    return SOFTBUS_OK;
}

static int32_t GetGroupInfo(struct WifiDirectP2pGroupInfo **groupInfoOut)
{
    WifiP2pGroupInfo *info = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(*info));
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "alloc group info failed");

    int32_t ret = GetCurrentGroup(info);
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current group failed");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }

    struct WifiDirectP2pGroupInfo *groupInfo = NULL;
    groupInfo = (struct WifiDirectP2pGroupInfo *)SoftBusCalloc(sizeof(struct WifiDirectP2pGroupInfo));
    if (groupInfo == NULL) {
        CONN_LOGE(CONN_WIFI_DIRECT, "alloc group info failed");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }

    groupInfo->isGroupOwner = info->isP2pGroupOwner;
    groupInfo->frequency = info->frequency;
    groupInfo->clientDeviceSize = info->clientDevicesSize;
    ret = memcpy_s(groupInfo->interface, sizeof(groupInfo->interface), info->interface, sizeof(info->interface));
    if (ret != EOK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "copy interface failed");
        SoftBusFree(info);
        SoftBusFree(groupInfo);
        *groupInfoOut = NULL;
        return SOFTBUS_ERR;
    }

    ret = memcpy_s(groupInfo->groupOwner.address, MAC_ADDR_ARRAY_SIZE, info->owner.devAddr,
                   sizeof(info->owner.devAddr));
    if (ret != EOK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "copy mac failed");
        SoftBusFree(info);
        SoftBusFree(groupInfo);
        *groupInfoOut = NULL;
        return SOFTBUS_ERR;
    }

    for (int32_t i = 0; i < groupInfo->clientDeviceSize; i++) {
        (void)memcpy_s(groupInfo->clientDevices[i].address, MAC_ADDR_ARRAY_SIZE,
            info->clientDevices[i].devAddr, COMMON_MAC_LEN);
    }

    *groupInfoOut = groupInfo;
    SoftBusFree(info);
    return SOFTBUS_OK;
}

static int32_t GetIpAddress(char *ipString, int32_t ipStringSize)
{
    WifiP2pGroupInfo *groupInfo = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(*groupInfo));
    CONN_CHECK_AND_RETURN_RET_LOGE(groupInfo, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "alloc group info failed");

    int32_t ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current group failed");
        SoftBusFree(groupInfo);
        return SOFTBUS_ERR;
    }

    char interface[INTERFACE_LENGTH];
    (void)memset_s(interface, sizeof(interface), 0, sizeof(interface));
    if (memcpy_s(interface, sizeof(interface), groupInfo->interface, sizeof(groupInfo->interface)) != EOK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "memcpy_s failed");
        SoftBusFree(groupInfo);
        return SOFTBUS_ERR;
    }
    SoftBusFree(groupInfo);
    CONN_LOGI(CONN_WIFI_DIRECT, "interfaceName=%{public}s", interface);

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    ret = netWorkUtils->getInterfaceIpString(interface, ipString, ipStringSize);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get ip string failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "ipString=%{public}s", ipString);
    return SOFTBUS_OK;
}

static int32_t GetMacAddress(char *macString, size_t macStringSize)
{
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    uint8_t mac[MAC_ADDR_ARRAY_SIZE];
    size_t macSize = MAC_ADDR_ARRAY_SIZE;
    (void)memset_s(mac, macSize, 0, macSize);
    if (netWorkUtils->getInterfaceMacAddr(IF_NAME_P2P, mac, &macSize) == SOFTBUS_OK) {
        netWorkUtils->macArrayToString(mac, macSize, macString, macStringSize);
        CONN_LOGI(CONN_WIFI_DIRECT, "p2p0");
        return SOFTBUS_OK;
    }

    int32_t ret = netWorkUtils->getInterfaceMacAddr(IF_NAME_WLAN, mac, &macSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get p2p mac failed");

    netWorkUtils->macArrayToString(mac, macSize, macString, macStringSize);
    CONN_LOGI(CONN_WIFI_DIRECT, "wlan0");
    return SOFTBUS_OK;
}

static int32_t GetDynamicMacAddress(char *macString, size_t macStringSize)
{
    WifiP2pGroupInfo *groupInfo = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(*groupInfo));
    CONN_CHECK_AND_RETURN_RET_LOGW(groupInfo, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "alloc group info failed");

    int32_t ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current group failed");
        SoftBusFree(groupInfo);
        return SOFTBUS_ERR;
    }

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    uint8_t macAddrArray[MAC_ADDR_ARRAY_SIZE];
    size_t macAddrArraySize = MAC_ADDR_ARRAY_SIZE;
    ret = netWorkUtils->getInterfaceMacAddr(groupInfo->interface, macAddrArray, &macAddrArraySize);
    SoftBusFree(groupInfo);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get interface mac addr failed");
        return ret;
    }

    ret = netWorkUtils->macArrayToString(macAddrArray, macAddrArraySize, macString, macStringSize);
    if (ret != SOFTBUS_OK) {
        CONN_LOGW(CONN_WIFI_DIRECT, "convert mac addr to string failed");
        return ret;
    }

    return SOFTBUS_OK;
}

static int32_t RequestGcIp(const char *macString, char *ipString, size_t ipStringSize)
{
    uint8_t macArray[MAC_ADDR_ARRAY_SIZE];
    size_t macArraySize = MAC_ADDR_ARRAY_SIZE;
    (void)memset_s(macArray, macArraySize, 0, macArraySize);
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t ret = netWorkUtils->macStringToArray(macString, macArray, &macArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "mac to string failed");

    uint32_t ipArray[IPV4_ADDR_ARRAY_LEN];
    ret = Hid2dRequestGcIp(macArray, ipArray);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT, "request gc ip failed");

    ret = sprintf_s(ipString, ipStringSize, "%u.%u.%u.%u", ipArray[0], ipArray[1], ipArray[2], ipArray[3]);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret > 0, SOFTBUS_ERR, CONN_WIFI_DIRECT, "format ip string failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "gcIp=%{public}s", ipString);

    return SOFTBUS_OK;
}

static int32_t P2pConfigGcIp(const char *interface, const char *ip)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(interface, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "interface is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(ip, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "ip is null");

    IpAddrInfo addrInfo;
    (void)memset_s(&addrInfo, sizeof(addrInfo), 0, sizeof(addrInfo));
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t ret = netWorkUtils->ipStringToIntArray(ip, addrInfo.ip, IPV4_ARRAY_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "convert ip to int array failed");
    ret = netWorkUtils->ipStringToIntArray(ip, addrInfo.gateway, IPV4_ARRAY_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT,
        "convert gateway to int array failed");
    ret = netWorkUtils->ipStringToIntArray(DEFAULT_NET_MASK, addrInfo.netmask, IPV4_ARRAY_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT,
        "convert gateway to int array failed");

    ret = Hid2dConfigIPAddr(interface, &addrInfo);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT, "hid2d config ip failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "success");
    return SOFTBUS_OK;
}

static int32_t P2pCreateGroup(int32_t frequency, bool wideBandSupported)
{
    FreqType type = wideBandSupported ? FREQUENCY_160M : FREQUENCY_DEFAULT;
    int32_t ret = Hid2dCreateGroup(frequency, type);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT, "create group failed");

    CONN_LOGI(CONN_WIFI_DIRECT, "create group success");
    return SOFTBUS_OK;
}

static int32_t P2pConnectGroup(char *groupConfigString, bool isLegacyGo)
{
    char *configs[P2P_GROUP_CONFIG_INDEX_MAX];
    size_t configsSize = P2P_GROUP_CONFIG_INDEX_MAX;

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t ret = netWorkUtils->splitString(groupConfigString, (char *)"\n", configs, &configsSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "split group config failed");

    Hid2dConnectConfig connectConfig;
    (void)memset_s(&connectConfig, sizeof(connectConfig), 0, sizeof(connectConfig));

    ret = strcpy_s(connectConfig.ssid, sizeof(connectConfig.ssid), configs[P2P_GROUP_CONFIG_INDEX_SSID]);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy ssid failed");

    size_t macLen = MAC_LEN;
    ret = netWorkUtils->macStringToArray(configs[P2P_GROUP_CONFIG_INDEX_BSSID], connectConfig.bssid, &macLen);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "convert mac failed");

    ret = strcpy_s(connectConfig.preSharedKey, sizeof(connectConfig.preSharedKey),
                   configs[P2P_GROUP_CONFIG_INDEX_SHARE_KEY]);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy share key failed");

    char *end = NULL;
    connectConfig.frequency = (int32_t)strtol(configs[P2P_GROUP_CONFIG_INDEX_FREQ], &end, DECIMAL_BASE);

    if (isLegacyGo) {
        connectConfig.dhcpMode = CONNECT_AP_NODHCP;
    } else {
        connectConfig.dhcpMode = CONNECT_GO_NODHCP;
        if (configsSize == P2P_GROUP_CONFIG_INDEX_MAX && !strcmp(configs[P2P_GROUP_CONFIG_INDEX_MODE], "1")) {
            connectConfig.dhcpMode = CONNECT_AP_DHCP;
        }
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "dhcpMode=%{public}d", connectConfig.dhcpMode);
    ret = Hid2dConnect(&connectConfig);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT, "connect group failed");

    CONN_LOGI(CONN_WIFI_DIRECT, "connect group success");
    return SOFTBUS_OK;
}

static int32_t P2pShareLinkReuse(void)
{
    WifiErrorCode ret = Hid2dSharedlinkIncrease();
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT, "failed ret=%{public}d", ret);
    return SOFTBUS_OK;
}

static int32_t P2pShareLinkRemoveGroup(const char *interface)
{
    (void)interface;
    WifiErrorCode ret = Hid2dSharedlinkDecrease();
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT, "failed ret=%{public}d", ret);
    return SOFTBUS_OK;
}

static int32_t P2pRemoveGroup(const char *interface)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(interface != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface is null");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(interface);
    if (info == NULL) {
        CONN_LOGE(CONN_WIFI_DIRECT, "can't find interface. interface=%{public}s", interface);
        return SOFTBUS_ERR;
    }

    enum WifiDirectApiRole role = (enum WifiDirectApiRole)info->getInt(info, II_KEY_WIFI_DIRECT_ROLE,
        WIFI_DIRECT_API_ROLE_NONE);

    WifiErrorCode ret;
    if (role == WIFI_DIRECT_API_ROLE_GO) {
        ret = RemoveGroup();
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT,
            "remove group failed, ret=%{public}d", ret);
    } else if (role == WIFI_DIRECT_API_ROLE_GC) {
        ret = Hid2dRemoveGcGroup(interface);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_WIFI_DIRECT,
            "remove gc group of interface failed, interface=%{public}s, ret=%{public}d", interface, ret);
    } else {
        CONN_LOGW(CONN_WIFI_DIRECT, "unknonwn api role. role=%{public}d", role);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static void SetWifiLinkAttr(const char *interface, const char *attr)
{
    (void)interface;
    (void)attr;
}

static int32_t GetInterfaceCoexistCap(char **cap)
{
    *cap = NULL;
    return SOFTBUS_OK;
}

static int32_t GetRecommendChannelV2(const char *jsonString, char *result, size_t resultSize)
{
    (void)jsonString;
    (void)result;
    (void)resultSize;
    CONN_LOGE(CONN_WIFI_DIRECT, "not supported");
    return SOFTBUS_ERR;
}

static int SetConnectNotify(const char *notify)
{
    (void)notify;
    return SOFTBUS_OK;
}

static int32_t GetBaseMac(const char *interface, uint32_t cap, char baseMac[], size_t baseMacLen)
{
    (void)interface;
    (void)cap;
    (void)baseMac;
    (void)baseMacLen;
    CONN_LOGE(CONN_WIFI_DIRECT, "not supported");
    return SOFTBUS_ERR;
}

static bool IsThreeVapConflict(void)
{
    return false;
}

static struct WifiDirectP2pAdapter g_adapter = {
    .isWifiP2pEnabled = IsWifiP2pEnabled,
    .isWifiConnected = IsWifiConnected,
    .isWifiApEnabled = IsWifiApEnabled,
    .isWideBandSupported = IsWideBandSupported,

    .getChannel5GListIntArray = GetChannel5GListIntArray,
    .getStationFrequency = GetStationFrequency,
    .getStationFrequencyWithFilter = GetStationFrequencyWithFilter,
    .getRecommendChannel = GetRecommendChannel,
    .getSelfWifiConfigInfo = GetSelfWifiConfigInfo,
    .setPeerWifiConfigInfo = SetPeerWifiConfigInfo,
    .getGroupConfig = GetGroupConfig,
    .getGroupInfo = GetGroupInfo,
    .getIpAddress = GetIpAddress,
    .getMacAddress = GetMacAddress,
    .getDynamicMacAddress = GetDynamicMacAddress,
    .requestGcIp = RequestGcIp,
    .configGcIp = P2pConfigGcIp,

    .createGroup = P2pCreateGroup,
    .connectGroup = P2pConnectGroup,
    .shareLinkReuse = P2pShareLinkReuse,
    .shareLinkRemoveGroupAsync = P2pShareLinkRemoveGroup,
    .shareLinkRemoveGroupSync = P2pShareLinkRemoveGroup,
    .removeGroup = P2pRemoveGroup,
    .setWifiLinkAttr = SetWifiLinkAttr,

    .getInterfaceCoexistCap = GetInterfaceCoexistCap,
    .getSelfWifiConfigInfoV2 = GetSelfWifiConfigInfo,
    .setPeerWifiConfigInfoV2 = SetPeerWifiConfigInfoV2,
    .getRecommendChannelV2 = GetRecommendChannelV2,
    .setConnectNotify = SetConnectNotify,

    .getBaseMac = GetBaseMac,
    .isThreeVapConflict = IsThreeVapConflict,
};

struct WifiDirectP2pAdapter *GetWifiDirectP2pAdapter(void)
{
    return &g_adapter;
}