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

#include "conn_log.h"
#include "softbus_error_code.h"

#define DEFAULT_NET_MASK "255.255.255.0"

static bool IsWifiP2pEnabled(void)
{
    return false;
}

static bool IsWifiConnected(void)
{
    return false;
}

static bool IsWifiApEnabled(void)
{
    return false;
}

static bool IsWideBandSupported(void)
{
    return false;
}

static int32_t GetChannel5GListIntArray(int32_t *array, size_t *size)
{
    (void)array;
    (void)size;
    return SOFTBUS_OK;
}

static int32_t GetStationFrequency(void)
{
    return SOFTBUS_OK;
}

static int32_t GetRecommendChannel(void)
{
    return SOFTBUS_OK;
}

static int32_t GetSelfWifiConfigInfo(uint8_t *config, size_t *configSize)
{
    (void)config;
    (void)configSize;
    return SOFTBUS_OK;
}

static int32_t SetPeerWifiConfigInfo(const char *config)
{
    (void)config;
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
    (void)groupConfigString;
    (void)groupConfigStringSize;
    return SOFTBUS_OK;
}

static int32_t GetGroupInfo(struct WifiDirectP2pGroupInfo **groupInfoOut)
{
    (void)groupInfoOut;
    return SOFTBUS_OK;
}

static int32_t GetIpAddress(char *ipString, int32_t ipStringSize)
{
    (void)ipStringSize;
    return SOFTBUS_OK;
}

static int32_t GetMacAddress(char *macString, size_t macStringSize)
{
    (void)macString;
    (void)macStringSize;
    return SOFTBUS_OK;
}

static int32_t GetDynamicMacAddress(char *macString, size_t macStringSize)
{
    (void)macString;
    (void)macStringSize;
    return SOFTBUS_OK;
}

static int32_t RequestGcIp(const char *macString, char *ipString, size_t ipStringSize)
{
    (void)macString;
    (void)ipString;
    (void)ipStringSize;
    return SOFTBUS_OK;
}

static int32_t P2pConfigGcIp(const char *interface, const char *ip)
{
    (void)interface;
    (void)ip;
    return SOFTBUS_OK;
}

static int32_t P2pCreateGroup(int32_t frequency, bool wideBandSupported)
{
    (void)frequency;
    (void)wideBandSupported;
    return SOFTBUS_OK;
}

static int32_t P2pConnectGroup(char *groupConfigString, bool isLegacyGo)
{
    (void)groupConfigString;
    (void)isLegacyGo;
    return SOFTBUS_OK;
}

static int32_t P2pShareLinkReuse(void)
{
    return SOFTBUS_OK;
}

static int32_t P2pShareLinkRemoveGroup(const char *interface)
{
    (void)interface;
    return SOFTBUS_OK;
}

static int32_t P2pRemoveGroup(const char *interface)
{
    (void)interface;
    return SOFTBUS_OK;
}

static void SetWifiLinkAttr(const char *interface, const char *attr)
{
    (void)interface;
    (void)attr;
}

static int32_t GetInterfaceCoexistCap(char **cap)
{
    (void)cap;
    return SOFTBUS_OK;
}

static int32_t GetRecommendChannelV2(const char *jsonString, char *result, size_t resultSize)
{
    (void)jsonString;
    (void)result;
    (void)resultSize;
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