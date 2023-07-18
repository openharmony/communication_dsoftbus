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
#include "wifi_device.h"
#include "wifi_p2p.h"
#include "wifi_hid2d.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_crypto.h"
#include "wifi_direct_defines.h"
#include "utils/wifi_direct_network_utils.h"
#include "utils/wifi_direct_anonymous.h"
#include "data/resource_manager.h"

#define LOG_LABEL "[WifiDirect] WifiDirectP2pAdapter: "
#define DEFAULT_NET_MASK "255.255.255.0"

static bool IsWifiP2pEnabled(void)
{
    enum P2pState state;
    int32_t ret = GetP2pEnableStatus(&state);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, false, LOG_LABEL "get p2p enable status failed");

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
    return Hid2dIsWideBandwidthSupported() == WIFI_SUCCESS;
}

static int32_t GetChannel5GListIntArray(int32_t *array, size_t *size)
{
    int32_t ret = Hid2dGetChannelListFor5G(array, (int32_t )*size);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "hid2d get channels failed ret=%d", ret);

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
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "get wifi linked info failed");
    CLOGI(LOG_LABEL "frequency=%d", linkedInfo.frequency);

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    if (netWorkUtils->is2GBand(linkedInfo.frequency)) {
        return linkedInfo.frequency;
    }

    if (netWorkUtils->is5GBand(linkedInfo.frequency)) {
        int32_t channelArray[CHANNEL_ARRAY_NUM_MAX];
        size_t channelArraySize = CHANNEL_ARRAY_NUM_MAX;
        ret = GetChannel5GListIntArray(channelArray, &channelArraySize);
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get channel list failed", ret);

        int32_t channel = netWorkUtils->frequencyToChannel(linkedInfo.frequency);
        if (netWorkUtils->isInChannelList(channel, channelArray, channelArraySize)) {
            return linkedInfo.frequency;
        }
    }

    CLOGE(LOG_LABEL "get local frequency failed");
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
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "get self wifi config failed");

    CLOGI(LOG_LABEL "wifiConfigSize=%d", wifiConfigSize);
    if (wifiConfigSize == 0) {
        *configSize = 0;
        CLOGI(LOG_LABEL "empty wifi cfg");
        return SOFTBUS_OK;
    }

    size_t cipherSize = 0;
    ret = SoftBusBase64Encode(config, *configSize, &cipherSize, wifiConfig, wifiConfigSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "encode failed");

    *configSize = cipherSize;
    return SOFTBUS_OK;
}

static int32_t SetPeerWifiConfigInfo(char *config)
{
    CONN_CHECK_AND_RETURN_RET_LOG(config, SOFTBUS_INVALID_PARAM, LOG_LABEL "cfg is null");
    size_t configSize = strlen(config);
    size_t peerCfgLen = configSize + 1;
    uint8_t *peerCfg = SoftBusCalloc(peerCfgLen);
    size_t decLen;
    CONN_CHECK_AND_RETURN_RET_LOG(peerCfg, SOFTBUS_MALLOC_ERR, LOG_LABEL "malloc failed");

    int32_t ret = SoftBusBase64Decode(peerCfg, peerCfgLen, &decLen, (uint8_t *)config, configSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "decode wifi cfg failed");

    ret = Hid2dSetPeerWifiCfgInfo(TYPE_OF_SET_PEER_CONFIG, (char *)peerCfg, (int32_t)decLen);
    SoftBusFree(peerCfg);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "set wifi cfg failed");
    CLOGI(LOG_LABEL "set success");
    return SOFTBUS_OK;
}

static int32_t GetGroupConfig(char *groupConfigString, size_t *groupConfigStringSize)
{
    WifiP2pGroupInfo *groupInfo = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(*groupInfo));
    CONN_CHECK_AND_RETURN_RET_LOG(groupInfo, SOFTBUS_MALLOC_ERR, LOG_LABEL "alloc group info failed");

    int32_t ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        CLOGE(LOG_LABEL "get current group failed");
        SoftBusFree(groupInfo);
        return SOFTBUS_ERR;
    }

    char macAddrString[MAC_ADDR_STR_LEN];
    ret = GetWifiDirectNetWorkUtils()->macArrayToString(groupInfo->owner.devAddr, sizeof(groupInfo->owner.devAddr),
                                                        macAddrString, sizeof(macAddrString));
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "convert mac addr to string failed");
        SoftBusFree(groupInfo);
        return ret;
    }
    CLOGI(LOG_LABEL "groupName=%s, mac=%s, passphrase=%s, frequency=%d",
          groupInfo->groupName, WifiDirectAnonymizeMac(macAddrString), groupInfo->passphrase, groupInfo->frequency);

    ret = sprintf_s(groupConfigString, *groupConfigStringSize, "%s\n%s\n%s\n%d",
                    groupInfo->groupName, macAddrString, groupInfo->passphrase, groupInfo->frequency);
    SoftBusFree(groupInfo);
    if (ret < 0) {
        CLOGE(LOG_LABEL "convert mac addr to string failed");
        return SOFTBUS_ERR;
    }

    *groupConfigStringSize = ret;
    return SOFTBUS_OK;
}

static int32_t GetGroupInfo(struct WifiDirectP2pGroupInfo **groupInfoOut)
{
    WifiP2pGroupInfo *info = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(*info));
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_MALLOC_ERR, LOG_LABEL "alloc group info failed");

    int32_t ret = GetCurrentGroup(info);
    if (ret != WIFI_SUCCESS) {
        CLOGE(LOG_LABEL "get current group failed");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }

    struct WifiDirectP2pGroupInfo *groupInfo = NULL;
    groupInfo = (struct WifiDirectP2pGroupInfo *)SoftBusCalloc(sizeof(struct WifiDirectP2pGroupInfo));
    if (groupInfo == NULL) {
        CLOGE(LOG_LABEL "alloc group info failed");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }

    (void)memcpy_s(groupInfo->groupOwner.address, sizeof(groupInfo->groupOwner.address),
        info->owner.devAddr, sizeof(info->owner.devAddr));
    groupInfo->isGroupOwner = info->isP2pGroupOwner;
    groupInfo->frequency = info->frequency;
    groupInfo->clientDeviceSize = info->clientDevicesSize;
    ret = memcpy_s(groupInfo->interface, sizeof(groupInfo->interface), info->interface, sizeof(info->interface));
    if (ret != EOK) {
        CLOGE(LOG_LABEL "memcpy_s failed");
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
    CONN_CHECK_AND_RETURN_RET_LOG(groupInfo, SOFTBUS_MALLOC_ERR, LOG_LABEL "alloc group info failed");

    int32_t ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        CLOGE(LOG_LABEL "get current group failed");
        SoftBusFree(groupInfo);
        return SOFTBUS_ERR;
    }

    char interface[INTERFACE_LENGTH];
    int32_t res = memcpy_s(interface, sizeof(interface), groupInfo->interface, sizeof(groupInfo->interface));
    if (res != EOK) {
        CLOGE(LOG_LABEL "memcpy_s failed");
        SoftBusFree(groupInfo);
        return SOFTBUS_ERR;
    }
    SoftBusFree(groupInfo);
    CLOGI(LOG_LABEL "interfaceName=%s", interface);

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    ret = netWorkUtils->getInterfaceIpString(interface, ipString, ipStringSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get ip string failed");
    CLOGI(LOG_LABEL "ipString=%s", ipString);
    return SOFTBUS_OK;
}

static int32_t GetMacAddress(char *macString, size_t macStringSize)
{
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    uint8_t mac[MAC_ADDR_ARRAY_SIZE];
    size_t macSize = MAC_ADDR_ARRAY_SIZE;
    if (netWorkUtils->getInterfaceMacAddr(IF_NAME_P2P, mac, &macSize) == SOFTBUS_OK) {
        netWorkUtils->macArrayToString(mac, macSize, macString, macStringSize);
        CLOGI(LOG_LABEL "p2p0");
        return SOFTBUS_OK;
    }

    int32_t ret = netWorkUtils->getInterfaceMacAddr(IF_NAME_WLAN, mac, &macSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get p2p mac failed");

    netWorkUtils->macArrayToString(mac, macSize, macString, macStringSize);
    CLOGI(LOG_LABEL "wlan0");
    return SOFTBUS_OK;
}

static int32_t GetDynamicMacAddress(char *macString, size_t macStringSize)
{
    WifiP2pGroupInfo *groupInfo = (WifiP2pGroupInfo *)SoftBusCalloc(sizeof(*groupInfo));
    CONN_CHECK_AND_RETURN_RET_LOG(groupInfo, SOFTBUS_MALLOC_ERR, LOG_LABEL "alloc group info failed");

    int32_t ret = GetCurrentGroup(groupInfo);
    if (ret != WIFI_SUCCESS) {
        CLOGE(LOG_LABEL "get current group failed");
        SoftBusFree(groupInfo);
        return SOFTBUS_ERR;
    }

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    uint8_t macAddrArray[MAC_ADDR_ARRAY_SIZE];
    size_t macAddrArraySize = MAC_ADDR_ARRAY_SIZE;
    ret = netWorkUtils->getInterfaceMacAddr(groupInfo->interface, macAddrArray, &macAddrArraySize);
    SoftBusFree(groupInfo);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "get interface mac addr failed");
        return ret;
    }

    ret = netWorkUtils->macArrayToString(macAddrArray, macAddrArraySize, macString, macStringSize);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "convert mac addr to string failed");
        return ret;
    }

    return SOFTBUS_OK;
}

static int32_t RequestGcIp(const char *macString, char *ipString, size_t ipStringSize)
{
    uint8_t macArray[MAC_ADDR_ARRAY_SIZE];
    size_t macArraySize = MAC_ADDR_ARRAY_SIZE;
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t ret = netWorkUtils->macStringToArray(macString, macArray, &macArraySize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "mac to string failed");

    uint32_t ipArray[IPV4_ADDR_ARRAY_LEN];
    ret = Hid2dRequestGcIp(macArray, ipArray);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "request gc ip failed");

    ret = sprintf_s(ipString, ipStringSize, "%u.%u.%u.%u", ipArray[0], ipArray[1], ipArray[2], ipArray[3]);
    CONN_CHECK_AND_RETURN_RET_LOG(ret > 0, SOFTBUS_ERR, LOG_LABEL "format ip string failed");
    CLOGI(LOG_LABEL "gcIp=%s", ipString);

    return SOFTBUS_OK;
}

static int32_t P2pConfigGcIp(const char *interface, const char *ip)
{
    CONN_CHECK_AND_RETURN_RET_LOG(interface, SOFTBUS_INVALID_PARAM, LOG_LABEL "interface is null");
    CONN_CHECK_AND_RETURN_RET_LOG(ip, SOFTBUS_INVALID_PARAM, LOG_LABEL "ip is null");

    IpAddrInfo addrInfo;
    (void)memset_s(&addrInfo, sizeof(addrInfo), 0, sizeof(addrInfo));
    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t ret = netWorkUtils->ipStringToIntArray(ip, addrInfo.ip, IPV4_ARRAY_LEN);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "convert ip to int array failed");
    ret = netWorkUtils->ipStringToIntArray(ip, addrInfo.gateway, IPV4_ARRAY_LEN);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "convert gateway to int array failed");
    ret = netWorkUtils->ipStringToIntArray(DEFAULT_NET_MASK, addrInfo.netmask, IPV4_ARRAY_LEN);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "convert gateway to int array failed");

    ret = Hid2dConfigIPAddr(interface, &addrInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, "hid2d config ip failed");
    CLOGI(LOG_LABEL "success");
    return SOFTBUS_OK;
}

static int32_t P2pCreateGroup(int32_t frequency, bool wideBandSupported)
{
    FreqType type = wideBandSupported ? FREQUENCY_160M : FREQUENCY_DEFAULT;
    int32_t ret = Hid2dCreateGroup(frequency, type);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "create group failed");

    CLOGI(LOG_LABEL "create group success");
    return SOFTBUS_OK;
}

static int32_t P2pConnectGroup(const char *groupConfigString)
{
    char *configs[P2P_GROUP_CONFIG_INDEX_MAX];
    size_t configsSize = P2P_GROUP_CONFIG_INDEX_MAX;

    struct WifiDirectNetWorkUtils *netWorkUtils = GetWifiDirectNetWorkUtils();
    int32_t ret = netWorkUtils->splitString(groupConfigString, "\n", configs, &configsSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "split group config failed");

    Hid2dConnectConfig connectConfig;
    (void)memset_s(&connectConfig, sizeof(connectConfig), 0, sizeof(connectConfig));

    ret = strcpy_s(connectConfig.ssid, sizeof(connectConfig.ssid), configs[P2P_GROUP_CONFIG_INDEX_SSID]);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy ssid failed");

    size_t macLen = MAC_LEN;
    ret = netWorkUtils->macStringToArray(configs[P2P_GROUP_CONFIG_INDEX_BSSID], connectConfig.bssid, &macLen);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, "convert mac failed");

    ret = strcpy_s(connectConfig.preSharedKey, sizeof(connectConfig.preSharedKey),
                   configs[P2P_GROUP_CONFIG_INDEX_SHARE_KEY]);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy share key failed");

    char *end = NULL;
    connectConfig.frequency = (int32_t)strtol(configs[P2P_GROUP_CONFIG_INDEX_FREQ], &end, DECIMAL_BASE);

    connectConfig.dhcpMode = CONNECT_GO_NODHCP;
    if (configsSize == P2P_GROUP_CONFIG_INDEX_MAX && !strcmp(configs[P2P_GROUP_CONFIG_INDEX_MODE], "1")) {
        connectConfig.dhcpMode = CONNECT_AP_DHCP;
    }
    CLOGI(LOG_LABEL "ssid=%s", connectConfig.ssid);
    CLOGI(LOG_LABEL "bssid=%s", configs[P2P_GROUP_CONFIG_INDEX_BSSID]);
    CLOGI(LOG_LABEL "preSharedKey=%s", connectConfig.preSharedKey);
    CLOGI(LOG_LABEL "frequency=%d", connectConfig.frequency);

    ret = Hid2dConnect(&connectConfig);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "connect group failed");

    CLOGI(LOG_LABEL "connect group success");
    return SOFTBUS_OK;
}

static int32_t P2pShareLinkReuse(void)
{
    WifiErrorCode ret = Hid2dSharedlinkIncrease();
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "failed ret=%d", ret);
    return SOFTBUS_OK;
}

static int32_t P2pShareLinkRemoveGroup(const char *interface)
{
    (void)interface;
    WifiErrorCode ret = Hid2dSharedlinkDecrease();
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR, LOG_LABEL "failed ret=%d", ret);
    return SOFTBUS_OK;
}

static int32_t P2pRemoveGroup(const char *interface)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(interface);
    if (info == NULL) {
        CLOGE(LOG_LABEL "can't find interface %s", interface);
        return SOFTBUS_ERR;
    }

    enum WifiDirectApiRole role = info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);

    WifiErrorCode ret;
    if (role == WIFI_DIRECT_API_ROLE_GO) {
        ret = RemoveGroup();
        CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR,
            LOG_LABEL "remove group failed, ret=%d", ret);
    } else if (role == WIFI_DIRECT_API_ROLE_GC) {
        ret = Hid2dRemoveGcGroup(interface);
        CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, SOFTBUS_ERR,
            LOG_LABEL "remove gc group of %s failed, ret=%d", interface, ret);
    } else {
        CLOGE(LOG_LABEL "unknonwn api role %d", role);
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
    CLOGE(LOG_LABEL "not supported");
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
    CLOGE(LOG_LABEL "not supported");
    return SOFTBUS_ERR;
}

static bool AddInterfaceMultiIps(const char *interface, const char *localIp, uint8_t prefixLen)
{
    (void)interface;
    (void)localIp;
    (void)prefixLen;
    CLOGE(LOG_LABEL "not supported");
    return false;
}

static bool DeleteInterfaceMultiIps(const char *interface, const char *localIp, uint8_t prefixLen)
{
    (void)interface;
    (void)localIp;
    (void)prefixLen;
    CLOGE(LOG_LABEL "not supported");
    return false;
}

static bool AddInterfaceStaticArp(const char *interface, const char *remoteIp, const char *remoteMac)
{
    (void)interface;
    (void)remoteIp;
    (void)remoteMac;
    CLOGE(LOG_LABEL "not supported");
    return false;
}

static bool DeleteInterfaceStaticArp(const char *interface, const char *remoteIp, const char *remoteMac)
{
    (void)interface;
    (void)remoteIp;
    (void)remoteMac;
    CLOGE(LOG_LABEL "not supported");
    return false;
}

static int32_t GetInterfaceStaticArp(const char *interface, char *arpOutput[], int32_t *arpOutputLen)
{
    (void)interface;
    (void)arpOutput;
    (void)arpOutputLen;
    CLOGE(LOG_LABEL "not supported");
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
    .setPeerWifiConfigInfoV2 = SetPeerWifiConfigInfo,
    .getRecommendChannelV2 = GetRecommendChannelV2,
    .setConnectNotify = SetConnectNotify,

    .getBaseMac = GetBaseMac,
    .addInterfaceMultiIps = AddInterfaceMultiIps,
    .deleteInterfaceMultiIps = DeleteInterfaceMultiIps,
    .addInterfaceStaticArp = AddInterfaceStaticArp,
    .deleteInterfaceStaticArp = DeleteInterfaceStaticArp,
    .getInterfaceStaticArp = GetInterfaceStaticArp,

    .isThreeVapConflict = IsThreeVapConflict,
};

struct WifiDirectP2pAdapter* GetWifiDirectP2pAdapter(void)
{
    return &g_adapter;
}